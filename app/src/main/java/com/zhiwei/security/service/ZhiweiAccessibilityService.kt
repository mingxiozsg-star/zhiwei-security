package com.zhiwei.security.service

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.media.AudioManager
import android.os.Handler
import android.os.Looper
import android.view.KeyEvent
import android.view.accessibility.AccessibilityEvent
import android.widget.Toast
import com.zhiwei.security.core.AppScanner
import com.zhiwei.security.core.PanicKill
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.core.Privilege
import kotlin.concurrent.thread

/**
 * 知微无障碍守护服务
 * 运行在独立 :volguard 进程，由系统绑定托管——主进程被杀也会自动拉起
 *
 * 三大职责：
 * 1. 音量上键三连击（1.5秒内）→ 斩杀所有第三方应用（PanicKill）
 * 2. 软件音量攻击检测：前台第三方应用无按键操作却把音量拉满 → 斩杀该应用
 * 3. 无障碍霸占检测：危险应用通过无障碍霸屏导致用户无法操作 → 斩杀+吊销其无障碍
 */
class ZhiweiAccessibilityService : AccessibilityService() {

    private val handler = Handler(Looper.getMainLooper())
    private lateinit var audioManager: AudioManager

    // 音量键狂按计数（上/下键都算，2 秒内 ≥3 次触发）
    private var volKeyCount = 0
    private var lastVolKeyAt = 0L

    // 音量监控
    private var lastMusicVolume = -1
    private var lastKeyEventAt = 0L   // 最近一次音量键按下时间（区分用户/软件操作）
    private var volumeAbuseCount = 0

    // 无障碍霸占检测
    private var foregroundPkg = ""
    private var foregroundSince = 0L
    private var lastUserInteractionAt = 0L

    private val volumeWatcher = object : Runnable {
        override fun run() {
            checkVolumeAbuse()
            checkScreenHijack()
            handler.postDelayed(this, 1_000L)
        }
    }

    companion object {
        private const val RAPID_PRESS_WINDOW = 2_000L  // 狂按窗口：2 秒
        private const val RAPID_PRESS_COUNT = 3        // 按 3 次及以上触发
        private const val KEY_EVENT_GRACE = 2_000L      // 按键后 2 秒内的音量变化算用户操作
        private const val HIJACK_NO_INPUT_TIMEOUT = 15_000L // 15 秒无任何用户输入
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        Prefs.init(this)
        audioManager = getSystemService(Context.AUDIO_SERVICE) as AudioManager
        lastMusicVolume = audioManager.getStreamVolume(AudioManager.STREAM_MUSIC)
        lastUserInteractionAt = System.currentTimeMillis()
        handler.post(volumeWatcher)
    }

    override fun onDestroy() {
        handler.removeCallbacks(volumeWatcher)
        super.onDestroy()
    }

    // ========== 1. 音量键监听（狂按 3 次以上斩杀，上/下键都算） ==========

    override fun onKeyEvent(event: KeyEvent): Boolean {
        if (!Prefs.volumeGuardEnabled && !Prefs.a11yGuardEnabled) return super.onKeyEvent(event)

        // F1 悬浮窗霸屏检测：返回键连按 ≥3 次且前台纹丝不动 → 疑似被悬浮窗盖住
        if (event.keyCode == KeyEvent.KEYCODE_BACK && event.action == KeyEvent.ACTION_DOWN
            && event.repeatCount == 0 && Prefs.a11yGuardEnabled) {
            trackBackForOverlayHijack()
            return super.onKeyEvent(event)
        }

        if (!Prefs.volumeGuardEnabled) return super.onKeyEvent(event)

        if (event.keyCode == KeyEvent.KEYCODE_VOLUME_UP ||
            event.keyCode == KeyEvent.KEYCODE_VOLUME_DOWN) {
            // 长按自动连发（repeatCount>0）不计数——否则长按调音量就误触发斩杀
            if (event.action == KeyEvent.ACTION_DOWN && event.repeatCount == 0) {
                val now = System.currentTimeMillis()
                lastKeyEventAt = now
                lastUserInteractionAt = now

                // 超出狂按窗口重新计数
                if (now - lastVolKeyAt > RAPID_PRESS_WINDOW) volKeyCount = 0
                lastVolKeyAt = now
                volKeyCount++

                if (volKeyCount >= RAPID_PRESS_COUNT) {
                    volKeyCount = 0
                    triggerPanicKill()
                    return true // 吞掉这次按键，防止音量变化
                }
            }
        } else {
            // 其他键按下会打断狂按节奏
            if (event.action == KeyEvent.ACTION_DOWN) volKeyCount = 0
        }
        // 不拦截正常音量键功能
        return super.onKeyEvent(event)
    }

    private fun triggerPanicKill() {
        Toast.makeText(this, "🚨 知微安全：紧急斩杀已触发", Toast.LENGTH_LONG).show()
        // 触觉反馈：长按震感确认斩杀已触发
        try {
            val vib = getSystemService(VIBRATOR_SERVICE) as android.os.Vibrator
            vib.vibrate(android.os.VibrationEffect.createOneShot(400, android.os.VibrationEffect.DEFAULT_AMPLITUDE))
        } catch (e: Throwable) { }
        thread {
            val killed = PanicKill.killAllThirdParty(this)
            val msg = if (killed >= 0) "已斩杀 $killed 个第三方应用（前台+后台全部杀光）"
                else "已清理 ${-killed} 个第三方应用后台进程（前台应用需激活提权通道才能强杀）"
            com.zhiwei.security.core.NotifHelper.alert(this, "🚨 紧急斩杀完成", msg)
            handler.post {
                Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
            }
        }
    }

    // ========== 2. 软件音量攻击检测 ==========

    private fun checkVolumeAbuse() {
        if (!Prefs.volumeGuardEnabled) return
        val current = audioManager.getStreamVolume(AudioManager.STREAM_MUSIC)
        val max = audioManager.getStreamMaxVolume(AudioManager.STREAM_MUSIC)
        val now = System.currentTimeMillis()

        if (lastMusicVolume >= 0 && current > lastMusicVolume) {
            // 音量上升，且 2 秒内没有用户按音量键 → 软件行为
            val isSoftwareAction = now - lastKeyEventAt > KEY_EVENT_GRACE
            if (isSoftwareAction && current >= max) {
                volumeAbuseCount++
                // 连续 2 次秒级检测到被拉满 → 判定恶意
                if (volumeAbuseCount >= 2) {
                    volumeAbuseCount = 0
                    val suspect = foregroundPkg
                    if (suspect.isNotEmpty() && suspect != packageName &&
                        !PanicKill.isSystemApp(this, suspect) && suspect !in Prefs.whitelist) {
                        thread {
                            val ok = PanicKill.killOne(this, suspect)
                            val strong = ok && Privilege.isReady
                            handler.post {
                                Toast.makeText(this,
                                    if (strong) "⚠️ $suspect 恶意拉满音量，已斩杀"
                                    else if (ok) "⚠️ $suspect 恶意拉满音量，已清理其后台（强杀需提权）"
                                    else "⚠️ $suspect 恶意拉满音量（需提权才能处置）",
                                    Toast.LENGTH_LONG).show()
                            }
                        }
                        // 恢复音量
                        audioManager.setStreamVolume(AudioManager.STREAM_MUSIC, max / 2, 0)
                    }
                }
            }
        }
        lastMusicVolume = current
    }
// ========== 3. 无障碍霸占检测 ==========

    // F1 悬浮窗霸屏：返回键连按记录
    private var backPressTimes = LongArray(0)
    private var overlayHijackCooldownAt = 0L

    /**
     * 悬浮窗霸屏判定：返回键 3 秒内连按 ≥3 次，前台包却纹丝不动，
     * 且该应用持有悬浮窗权限（SYSTEM_ALERT_WINDOW）→ 悬浮窗盖住真界面，返回键被吞。
     * 处置：提权 appops 吊销其悬浮窗权限 + 斩杀。
     */
    private fun trackBackForOverlayHijack() {
        val now = System.currentTimeMillis()
        lastUserInteractionAt = now
        backPressTimes = (backPressTimes + now).filter { now - it <= 3_000L }.toLongArray()
        if (backPressTimes.size < 3) return
        if (now - overlayHijackCooldownAt < 30_000L) return

        val pkg = foregroundPkg
        if (pkg.isEmpty() || pkg == packageName) return
        if (pkg in Prefs.whitelist || PanicKill.isSystemApp(this, pkg)) return
        if (!hasOverlayPermission(pkg)) return

        overlayHijackCooldownAt = now
        backPressTimes = LongArray(0)
        thread {
            // 吊销悬浮窗权限（真正解除霸屏）+ 斩杀
            if (Privilege.isReady) {
                Privilege.exec("appops set $pkg SYSTEM_ALERT_WINDOW deny")
            }
            val ok = PanicKill.killOne(this, pkg)
            val msg = if (ok) "⚠️ $pkg 悬浮窗霸屏（返回键失效），已吊销悬浮窗并斩杀"
                else "⚠️ $pkg 疑似悬浮窗霸屏，已吊销其悬浮窗权限（强杀需提权）"
            handler.post { Toast.makeText(this, msg, Toast.LENGTH_LONG).show() }
            com.zhiwei.security.core.NotifHelper.alert(this, "🪟 悬浮窗霸屏拦截", msg)
        }
    }

    /** 检查应用当前是否实际持有悬浮窗权限（AppOps 判定，非仅声明） */
    private fun hasOverlayPermission(pkg: String): Boolean {
        return try {
            val appOps = getSystemService(Context.APP_OPS_SERVICE) as android.app.AppOpsManager
            val ai = packageManager.getApplicationInfo(pkg, 0)
            val mode = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                appOps.unsafeCheckOpNoThrow(
                    android.app.AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, ai.uid, pkg)
            } else {
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(
                    android.app.AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, ai.uid, pkg)
            }
            mode == android.app.AppOpsManager.MODE_ALLOWED
        } catch (e: Throwable) { false }
    }


    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return
        when (event.eventType) {
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                val pkg = event.packageName?.toString() ?: return
                if (pkg != foregroundPkg) {
                    foregroundPkg = pkg
                    foregroundSince = System.currentTimeMillis()
                    // 切换应用视为用户操作的证据
                    lastUserInteractionAt = System.currentTimeMillis()
                }
            }
            AccessibilityEvent.TYPE_VIEW_CLICKED,
            AccessibilityEvent.TYPE_VIEW_SCROLLED,
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED -> {
                lastUserInteractionAt = System.currentTimeMillis()
            }
        }
    }

    /**
     * 霸占判定：一个带锁机/无障碍高危特征的第三方应用占前台超过 15 秒，
     * 期间用户没有任何有效输入（点击/滚动/按键）→ 判定霸屏，斩杀
     */
    private fun checkScreenHijack() {
        if (!Prefs.a11yGuardEnabled) return
        val pkg = foregroundPkg
        if (pkg.isEmpty() || pkg == packageName) return
        if (pkg in Prefs.whitelist || PanicKill.isSystemApp(this, pkg)) return

        val now = System.currentTimeMillis()
        val noInput = now - lastUserInteractionAt > HIJACK_NO_INPUT_TIMEOUT
        val longForeground = now - foregroundSince > HIJACK_NO_INPUT_TIMEOUT

        if (noInput && longForeground) {
            // 检查该应用是否有锁机高危特征
            val risk = AppScanner(this).analyzePackageName(pkg) ?: return
            if (risk.level == com.zhiwei.security.core.VirusDb.ThreatLevel.HIGH ||
                risk.level == com.zhiwei.security.core.VirusDb.ThreatLevel.VIRUS) {
                thread {
                    // 吊销其无障碍权限
                    if (Privilege.isReady) {
                        revokeA11yFor(pkg)
                    }
                    val ok = PanicKill.killOne(this, pkg)
                    handler.post {
                        Toast.makeText(this,
                            if (ok) "⚠️ $pkg 疑似霸屏锁机，已斩杀并吊销无障碍"
                            else "⚠️ $pkg 疑似霸屏锁机（需 Shizuku 才能处置）",
                            Toast.LENGTH_LONG).show()
                    }
                }
                // 重置计时避免连杀
                foregroundSince = now
                lastUserInteractionAt = now
            }
        }
    }

    /** 从系统已启用的无障碍服务列表中移除指定应用的服务 */
    private fun revokeA11yFor(pkg: String) {
        val enabled = android.provider.Settings.Secure.getString(
            contentResolver, android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return
        val kept = enabled.split(":").filter { !it.startsWith("$pkg/") }
        val newValue = kept.joinToString(":")
        Privilege.exec(
            "settings put secure enabled_accessibility_services '$newValue'"
        )
    }

    override fun onInterrupt() { }
}