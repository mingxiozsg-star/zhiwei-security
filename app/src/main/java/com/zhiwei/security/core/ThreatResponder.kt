package com.zhiwei.security.core

import android.content.Context
import android.content.Intent
import com.zhiwei.security.ui.ShieldWarnActivity

/**
 * 威胁统一处置中心（唯一出口）
 *
 * 铁律（v1.8.0 起强制）：
 * 1. **任何扫描器都不得自行卸载应用**。卸载只在用户于弹窗点击「卸载」后，
 *    由 [ShieldWarnActivity] 执行或不执行。
 * 2. 自动处置上限 = **冻结隔离**：`am force-stop`，可选 `am suspend`（可逆、无损、不丢数据）。
 *    不再回收权限、不再卸载。
 * 3. 每个 VIRUS/HIGH 命中必须落到一个弹窗上，弹窗三按钮：
 *    「卸载」「本次忽略」「加入白名单」。
 * 4. 去重：同一包名 N 秒内只弹一次，避免批量扫描时弹窗风暴。
 */
object ThreatResponder {

    private const val ALERT_COOLDOWN_MS = 60_000L
    private val lastAlertAt = HashMap<String, Long>()

    /** 弹窗串行锁：同一时刻只允许一个确认窗在前台，避免批量扫描弹窗风暴 */
    @Volatile private var alerting = false
    @Volatile private var alertingAt = 0L
    /** 锁自动过期时间：弹窗被系统拦截/异常销毁时防止永久卡死 */
    private const val ALERT_LOCK_TTL = 120_000L

    /**
     * 处置一次威胁判定。
     *
     * @param allowIsolate 是否允许自动冻结（受 Prefs.autoKillOnVirus 控制）
     * @return true 表示本次真的弹了窗（调用方可据此计数）
     */
    fun handle(
        context: Context,
        result: VirusDb.ScanResult,
        source: String,
        allowIsolate: Boolean = true
    ): Boolean {
        val pkg = result.packageName
        if (pkg.isEmpty()) return false

        // 用户白名单免打扰
        if (pkg in Prefs.whitelist) return false
        // 内置可信库免打扰；但若明确命中恶意名单（真样本冒用正规包名），仍然要告警
        val explicitMalicious = pkg in VirusDb.maliciousPackages ||
            pkg in VirusDb.maliciousFileNames ||
            VirusDb.maliciousPackagePrefixes.any { pkg.startsWith(it) }
        if (!explicitMalicious && KnownSafeApps.isTrusted(pkg)) {
            SecurityJournal.log("处置", "$pkg 命中内置可信库，跳过告警（$source）")
            return false
        }

        val virus = result.level == VirusDb.ThreatLevel.VIRUS
        // 只对确认病毒做隔离（HIGH 仅提示，不动手）
        if (virus && allowIsolate && Prefs.autoKillOnVirus) {
            isolate(context, pkg, result.appName, source)
        }

        if (!shouldAlert(pkg)) return false

        val reason = buildReason(result)

        // 高风险（非确认病毒）只发通知、不弹窗打断：
        // 权限评分本身不足以定罪，弹窗会变成骚扰。用户点通知再看详情。
        if (!virus) {
            NotifHelper.notify(
                context,
                "⚠️ 高风险应用：${result.appName}",
                "$reason\n\n仅提示，未做任何处置。可在扫描页查看详情"
            )
            SecurityJournal.log("告警", "$source → $pkg（HIGH）已发通知，不弹窗")
            return false
        }

        // 串行弹窗：扫描一次命中多个病毒时，只弹最严重的一个，
        // 其余进通知栏排队，避免连续弹十几个窗把用户逼疯。
        val canPopup = synchronized(this) {
            val now = System.currentTimeMillis()
            if (alerting && now - alertingAt < ALERT_LOCK_TTL) {
                false
            } else {
                alerting = true; alertingAt = now; true
            }
        }
        val intent = warnIntent(context, pkg, result.appName, reason, true)
        if (canPopup) {
            // 强制拉起三按钮窗：全屏意图 + startActivity 双通道，
            // 避免"只看见一条通知、应用已经被处理"的体验
            NotifHelper.alertPopup(
                context,
                "☠️ 检测到病毒：${result.appName}",
                "$reason\n\n已冻结隔离（可恢复），未卸载。请选择：卸载 / 本次忽略 / 加入白名单",
                intent
            )
        } else {
            // 已有窗口在前台，其余进通知栏排队
            NotifHelper.alert(
                context,
                "☠️ 检测到病毒：${result.appName}",
                "$reason\n\n已冻结隔离（可恢复），未卸载。点击选择：卸载 / 本次忽略 / 加入白名单",
                intent
            )
        }
        SecurityJournal.log(
            "告警",
            "$source → $pkg（${result.level.label}）" + if (canPopup) "已弹窗，等待用户选择" else "弹窗排队中（通知栏）"
        )
        return true
    }

    /** 弹窗关闭后调用，释放串行锁 */
    fun onAlertClosed() {
        alerting = false
    }

    /** 拉起三按钮弹窗（新装拦截、前台拦截等场景共用） */
    fun warnIntent(
        context: Context,
        pkg: String,
        appName: String,
        reason: String,
        virus: Boolean = true
    ): Intent = Intent(context, ShieldWarnActivity::class.java).apply {
        putExtra("pkg", pkg)
        putExtra("app_name", appName)
        putExtra("reason", reason)
        putExtra("is_virus", virus)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
    }

    /**
     * 冻结隔离：强杀 + （可选）系统级 suspend。
     * 不碰数据、不碰权限、不卸载，用户点「卸载」前应用完好可恢复。
     */
    fun isolate(context: Context, pkg: String, appName: String, source: String) {
        kotlin.concurrent.thread(isDaemon = true) {
            try {
                if (Privilege.isReady) {
                    Privilege.forceStop(pkg)
                    if (Prefs.lockdownFreezeEnabled) {
                        Privilege.exec("am suspend --user 0 $pkg")
                    }
                    SecurityJournal.log("隔离", "$source 冻结 $pkg（$appName），未卸载")
                } else {
                    Privilege.exec("am force-stop $pkg")
                    SecurityJournal.log("隔离", "$source 无提权，仅 am force-stop $pkg")
                }
            } catch (e: Throwable) { }
        }
    }

    /** 解除隔离（用户选「本次忽略」或「加入白名单」时调用） */
    fun release(pkg: String) {
        kotlin.concurrent.thread(isDaemon = true) {
            try { Privilege.exec("am unsuspend --user 0 $pkg") } catch (e: Throwable) { }
        }
    }

    private fun shouldAlert(pkg: String): Boolean {
        val now = System.currentTimeMillis()
        synchronized(lastAlertAt) {
            val last = lastAlertAt[pkg] ?: 0L
            if (now - last < ALERT_COOLDOWN_MS) return false
            lastAlertAt[pkg] = now
            // 简单清理，防长期驻留
            if (lastAlertAt.size > 200) {
                lastAlertAt.entries.removeAll { now - it.value > ALERT_COOLDOWN_MS * 5 }
            }
            return true
        }
    }

    private fun buildReason(result: VirusDb.ScanResult): String {
        val head = result.reasons.firstOrNull() ?: "综合风险评分 ${result.score}"
        val more = result.reasons.drop(1).take(2)
        return if (more.isEmpty()) head else head + "；" + more.joinToString("；")
    }

    /** 用户确认卸载（唯一允许调用 pm uninstall 的入口） */
    fun confirmUninstall(context: Context, pkg: String, appName: String): Boolean {
        return try {
            Privilege.forceStop(pkg)
            val ok = Privilege.uninstall(pkg)
            Prefs.addToBlacklist(pkg)
            Prefs.userConfirmedUninstalled = Prefs.userConfirmedUninstalled + pkg
            SecurityJournal.log(
                "卸载",
                "用户确认卸载 $pkg（$appName）${if (ok) "成功" else "失败"}"
            )
            ok
        } catch (e: Throwable) { false }
    }
}