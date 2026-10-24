package com.zhiwei.security.service

import android.app.AppOpsManager
import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.Process
import androidx.core.app.NotificationCompat
import com.zhiwei.security.MainActivity
import com.zhiwei.security.R
import com.zhiwei.security.ZhiweiApp
import com.zhiwei.security.core.AppScanner
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.core.ShizukuManager
import com.zhiwei.security.core.VirusDb
import com.zhiwei.security.ui.ShieldWarnActivity

/**
 * 防锁机守护前台服务
 * 真实拦截逻辑：
 * 1. UsageStats 每 2 秒轮询前台应用，命中黑名单/恶意应用立即强杀（Shizuku）+ 全屏警告
 * 2. 监听新装应用，命中锁机权限组合立即警告 + 提供一键卸载
 * 3. 屏幕点亮时检查前台是否有黑名单应用
 * 4. 无 UsageStats 权限时降级为屏幕事件检测
 */
class ProtectService : Service() {

    private var wakeLock: PowerManager.WakeLock? = null
    private val handler = Handler(Looper.getMainLooper())
    private var screenReceiver: BroadcastReceiver? = null
    private var packageReceiver: BroadcastReceiver? = null
    private lateinit var scanner: AppScanner

    // 记录最近一次拦截的包名+时间，避免对同一应用 1 秒内重复弹窗
    private var lastBlockedPkg = ""
    private var lastBlockedAt = 0L

    private val foregroundWatcher = object : Runnable {
        override fun run() {
            checkForegroundApp()
            handler.postDelayed(this, WATCH_INTERVAL)
        }
    }

    companion object {
        private const val WATCH_INTERVAL = 2_000L // 2 秒轮询前台
        private const val BLOCK_COOLDOWN = 8_000L // 同一应用 8 秒内不重复警告
        private const val NOTIFICATION_ID = 1001
        var isRunning = false
            private set

        /** 检查是否有「使用情况访问」权限 */
        fun hasUsageAccess(context: Context): Boolean {
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                appOps.unsafeCheckOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(), context.packageName
                )
            } else {
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(), context.packageName
                )
            }
            return mode == AppOpsManager.MODE_ALLOWED
        }
    }

    override fun onCreate() {
        super.onCreate()
        isRunning = true
        Prefs.init(this)
        scanner = AppScanner(this)
        acquireWakeLock()
        registerScreenReceiver()
        registerPackageReceiver()
        handler.post(foregroundWatcher)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, buildNotification())
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        isRunning = false
        handler.removeCallbacks(foregroundWatcher)
        unregisterReceivers()
        releaseWakeLock()
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val shizukuState = if (ShizukuManager.isReady) "Shizuku 已连接" else "Shizuku 未连接"
        return NotificationCompat.Builder(this, ZhiweiApp.CHANNEL_PROTECT)
            .setContentTitle("知微安全守护中")
            .setContentText("前台监控运行中 · $shizukuState")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pi)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    private fun acquireWakeLock() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "zhiwei:protect").apply {
            acquire(10 * 60 * 1000L)
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
    }

    // ========== 核心：前台应用监控 ==========

    /** 通过 UsageStats 拿当前前台应用包名 */
    private fun getForegroundPackage(): String? {
        if (!hasUsageAccess(this)) return null
        val usm = getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        val now = System.currentTimeMillis()
        val events = usm.queryEvents(now - 15_000, now)
        val event = UsageEvents.Event()
        var foreground: String? = null
        while (events.hasNextEvent()) {
            events.getNextEvent(event)
            when (event.eventType) {
                UsageEvents.Event.MOVE_TO_FOREGROUND,
                UsageEvents.Event.ACTIVITY_RESUMED -> foreground = event.packageName
                UsageEvents.Event.MOVE_TO_BACKGROUND,
                UsageEvents.Event.ACTIVITY_PAUSED -> {
                    if (event.packageName == foreground) foreground = null
                }
            }
        }
        return foreground
    }

    private fun checkForegroundApp() {
        // 屏幕熄灭时不检查，省电
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (!pm.isInteractive) return

        val foreground = getForegroundPackage() ?: return
        if (foreground == packageName) return // 自己不管

        val shouldBlock = foreground !in Prefs.whitelist &&
                (foreground in Prefs.blacklist || foreground in VirusDb.maliciousPackages)
        if (!shouldBlock) return

        // 冷却时间内不重复处理
        val now = System.currentTimeMillis()
        if (foreground == lastBlockedPkg && now - lastBlockedAt < BLOCK_COOLDOWN) return
        lastBlockedPkg = foreground
        lastBlockedAt = now

        // 1. 立刻强杀（需要 Shizuku）
        val killed = if (ShizukuManager.isReady) {
            ShizukuManager.forceStop(foreground)
        } else false

        // 2. 弹出全屏警告（盖住恶意应用界面）
        showThreatWarning(
            foreground,
            if (killed) "黑名单应用已被强制停止" else "检测到黑名单应用进入前台（开启 Shizuku 可自动强杀）"
        )
    }

    // ========== 屏幕事件 ==========

    private fun registerScreenReceiver() {
        screenReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action == Intent.ACTION_SCREEN_ON) {
                    // 点亮屏幕立即查一次前台
                    handler.postDelayed({ checkForegroundApp() }, 300)
                }
            }
        }
        val filter = IntentFilter(Intent.ACTION_SCREEN_ON)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(screenReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(screenReceiver, filter)
        }
    }

    // ========== 新装应用拦截 ==========

    private fun registerPackageReceiver() {
        packageReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val pkg = intent.data?.schemeSpecificPart ?: return
                if (pkg == packageName) return
                when (intent.action) {
                    Intent.ACTION_PACKAGE_ADDED -> checkNewApp(pkg)
                    Intent.ACTION_PACKAGE_REMOVED -> {
                        Prefs.removeFromBlacklist(pkg)
                        Prefs.removeFromWhitelist(pkg)
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(packageReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(packageReceiver, filter)
        }
    }

    private fun checkNewApp(pkg: String) {
        if (pkg in Prefs.whitelist) return
        val result = scanner.analyzePackageName(pkg) ?: return
        if (result.level == VirusDb.ThreatLevel.HIGH || result.level == VirusDb.ThreatLevel.VIRUS) {
            showThreatWarning(
                pkg,
                "新安装应用存在风险：${result.reasons.firstOrNull() ?: "权限异常"}（评分 ${result.score}）"
            )
        }
    }

    private fun unregisterReceivers() {
        try { screenReceiver?.let { unregisterReceiver(it) } } catch (e: Exception) { }
        try { packageReceiver?.let { unregisterReceiver(it) } } catch (e: Exception) { }
    }

    // ========== 警告 ==========

    private fun showThreatWarning(pkg: String, reason: String) {
        if (pkg in Prefs.whitelist) return

        val appName = try {
            val pm = packageManager
            val appInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(pkg, 0)
            }
            appInfo.loadLabel(pm).toString()
        } catch (e: Exception) { pkg }

        val warnIntent = Intent(this, ShieldWarnActivity::class.java).apply {
            putExtra("pkg", pkg)
            putExtra("app_name", appName)
            putExtra("reason", reason)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }

        val pi = PendingIntent.getActivity(
            this, pkg.hashCode(), warnIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(this, ZhiweiApp.CHANNEL_WARN)
            .setContentTitle("⚠️ 安全警告")
            .setContentText("$appName: $reason")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .build()

        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as android.app.NotificationManager
        nm.notify(pkg.hashCode(), notification)

        startActivity(warnIntent)
    }
}