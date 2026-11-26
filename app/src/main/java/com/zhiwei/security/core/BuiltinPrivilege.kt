package com.zhiwei.security.core

import android.content.Context
import android.util.Log

/**
 * 内置特权服务（BuiltinPrivilege）—— 知微作为**特权宿主**的核心
 *
 * 架构与参考样本 Stellar 对齐，分三层：
 *
 *  1. **内核（真身）**：[BuiltinEngine] + [com.zhiwei.security.daemon.ZhiweiDaemon]
 *     用 `app_process` 把知微自己的代码拉成常驻进程，以 shell/root 身份长期存活。
 *     → 权限在知微自己手里，外部应用关授权、卸载都不影响它。
 *
 *  2. **服务端（对外分发）**：[com.zhiwei.security.service.ZhiweiApiService]
 *     + [com.zhiwei.security.provider.ZhiweiProvider]，
 *     第三方通过 `content://com.zhiwei.security.provider` 的 `getBinder` 拿到 Binder，
 *     再 `requestPermissionWithReason` 申请授权。
 *
 *  3. **授权（治理）**：[AuthDb] + `AuthGrantActivity`，按调用方 uid 精确判定，
 *     可随时撤销，全程审计。
 *
 * 诚实的边界：
 *  - **拉起 daemon 需要一次性提权**（无线调试配对 / Root）。这是 Android 的硬限制，
 *    任何非系统应用都无法凭空创建高权限进程；Stellar 同样如此。
 *  - daemon 拉起后就不再依赖外部通道；但**设备重启 / daemon 被杀**后需要再拉一次。
 *  - 对第三方开放的是 daemon 实际持有的身份（shell 或 root），不做夸大宣传。
 */
object BuiltinPrivilege {

    private const val TAG = "BuiltinPrivilege"

    /** 服务端状态 */
    enum class State(val label: String) {
        STOPPED("未激活"),
        STARTING("启动中"),
        RUNNING("运行中"),
        NO_PRIVILEGE("待通道"),
        NO_DAEMON("已开启·守护进程未运行")
    }

    /** 服务端内核版本（协议版本，第三方可据此兼容） */
    const val CORE_VERSION = "1.10.0"

    /** 协议版本（与 ZhiweiApiService.VERSION 保持一致） */
    const val PROTOCOL_VERSION = 2

    /** Provider authority（第三方接入用到的常量） */
    const val AUTHORITY = "com.zhiwei.security.provider"

    @Volatile
    private var started = false

    /** 常驻监控线程是否在跑 */
    @Volatile
    private var monitorRunning = false

    /** 最近一次启动结果（给 UI 展示） */
    @Volatile
    var lastMessage: String = ""
        private set

    /** 对外开关是否打开 */
    val isServiceRunning: Boolean get() = started

    /** 本次服务启动时间（UI 算运行时长） */
    val startedAt: Long get() = Prefs.builtinStartedAt

    /** daemon 是否在线（真连接探活，带 1.5 秒缓存） */
    fun isDaemonAlive(context: Context): Boolean = BuiltinEngine.isAlive(context)

    /**
     * 当前实际运行方式。
     *
     * 关键区别：以前这里读的是外部通道等级（ADB/Shizuku），
     * 现在优先读 **daemon 自己的 uid** —— 那才是知微实际握着的权限。
     */
    fun runModeOf(context: Context): String {
        if (!started) return "—"
        return BuiltinEngine.daemonIdentity(context)
    }

    /** 兼容旧调用（无 context 时退回读通道等级） */
    val runMode: String
        get() {
            val ctx = BuiltinEngineHolder.context
            if (ctx != null && started) {
                val id = BuiltinEngine.daemonIdentity(ctx)
                if (id != "未运行") return id
            }
            return when (Privilege.levelState.value) {
                Privilege.Level.BUILTIN -> "内置守护进程（常驻）"
                Privilege.Level.ROOT -> "Root（通道）"
                Privilege.Level.SYSTEM -> "System（通道）"
                Privilege.Level.ADB -> "ADB（通道就绪）"
                Privilege.Level.SHIZUKU -> "Shizuku（外部）"
                else -> if (started) "待通道" else "—"
            }
        }

    /** 聚合状态（UI 主卡用） */
    fun state(): State {
        if (!started) return State.STOPPED
        val ctx = BuiltinEngineHolder.context ?: return State.NO_PRIVILEGE
        return when {
            BuiltinEngine.isAlive(ctx) -> State.RUNNING
            !Privilege.isReady -> State.NO_PRIVILEGE
            else -> State.NO_DAEMON
        }
    }

    /** 已授权第三方应用数量 */
    fun grantedCount(): Int = try { AuthDb.grantedApps.size } catch (e: Throwable) { 0 }

    /** 运行时长文本 */
    fun uptimeText(): String {
        val t = startedAt
        if (t <= 0L || !started) return "—"
        val sec = (System.currentTimeMillis() - t) / 1000
        return when {
            sec < 60 -> "${sec} 秒"
            sec < 3600 -> "${sec / 60} 分钟"
            else -> "${sec / 3600} 小时 ${(sec % 3600) / 60} 分"
        }
    }

    /**
     * 激活内置特权 = 真正把 daemon 拉起来。
     *
     * 注意：这不是「打开一个开关」，而是要真起一个高权限进程。
     * 没有可用提权通道时会明确失败并提示用户先配对，绝不假装成功。
     *
     * @return Pair(是否成功, 说明)
     */
    fun activate(context: Context): Pair<Boolean, String> {
        Prefs.init(context)
        AuthDb.init(context)
        BuiltinEngineHolder.context = context.applicationContext
        com.zhiwei.security.service.ZhiweiApiServiceHolder.context = context.applicationContext
        lastMessage = "正在拉起守护进程…"

        val (ok, msg) = BuiltinEngine.ensureStarted(context)
        if (!ok) {
            // 拉起失败绝不能留下「已开启」的假状态
            started = false
            monitorRunning = false
            Prefs.builtinPrivilegeEnabled = false
            lastMessage = msg
            SecurityJournal.log("内置特权", "激活失败：$msg")
            return false to msg
        }
        started = true
        Prefs.daemonEverStarted = true
        Prefs.builtinPrivilegeEnabled = true
        if (Prefs.builtinStartedAt <= 0L) Prefs.builtinStartedAt = System.currentTimeMillis()
        startMonitor(context)
        lastMessage = msg
        SecurityJournal.log("内置特权", "已激活：$msg")
        Log.i(TAG, "builtin privilege activated: $msg")
        return true to msg
    }

    /** 兼容旧入口 */
    fun start(context: Context): Boolean = activate(context).first

    /**
     * 冷启动恢复。
     *
     * 分两种情况：
     *  - daemon 还活着（进程未被杀）→ 直接恢复状态，外部通道有没有都无所谓。
     *  - daemon 已不在（设备重启 / 被杀）→ 若开了「开机自动恢复」且当前有可用
     *    提权通道，就在后台重新拉起一次；失败则标记为待激活，等用户手动处理。
     */
    fun restoreIfEnabled(context: Context) {
        Prefs.init(context)
        AuthDb.init(context)
        BuiltinEngineHolder.context = context.applicationContext
        if (!Prefs.builtinPrivilegeEnabled) return
        if (started) return
        started = true

        if (BuiltinEngine.isAlive(context)) {
            lastMessage = "服务已恢复（守护进程在线）"
            startMonitor(context)
            return
        }
        if (!Prefs.builtinAutoStart) {
            lastMessage = "服务已恢复，但守护进程掉线（未开启自动恢复）"
            startMonitor(context)
            return
        }
        // 后台线程拉起，避免阻塞应用启动
        kotlin.concurrent.thread(isDaemon = true, name = "builtin-restore") {
            val (ok, msg) = runCatching { activate(context) }
                .getOrElse { false to "自动拉起异常：${it.message}" }
            if (!ok) {
                // 失败也要保留用户意图：标记为「已开启·等待通道」，
                // 下次进入应用时再按 autoStart 重试。
                Prefs.builtinPrivilegeEnabled = true
                started = true
                startMonitor(context)
            }
            lastMessage = if (ok) "服务已自动恢复：$msg" else "自动拉起失败：$msg"
            Log.i(TAG, "auto restore -> $ok: $msg")
        }
    }

    /** 停止：关闭对外开关 + 杀掉 daemon */
    fun stop(context: Context): Boolean {
        started = false
        monitorRunning = false
        try { BuiltinEngine.stop(context) } catch (e: Throwable) { }
        Prefs.builtinPrivilegeEnabled = false
        Prefs.builtinStartedAt = 0L
        lastMessage = "已停止，守护进程已结束"
        SecurityJournal.log("内置特权", "内置特权已关闭，守护进程已结束")
        return true
    }

    /** 兼容旧签名（无 context） */
    fun stop(): Boolean {
        val ctx = BuiltinEngineHolder.context
        return if (ctx != null) stop(ctx) else {
            started = false; monitorRunning = false
            Prefs.builtinPrivilegeEnabled = false
            lastMessage = "已停止"
            true
        }
    }

    /**
     * 常驻监控：每 30 秒探活一次 daemon。
     *
     * daemon 掉线时**不静默重连**（没有通道也重连不了），只更新状态，
     * 让 UI 明确显示「已开启·守护进程未运行」，避免误以为还有权限。
     */
    private fun startMonitor(context: Context) {
        if (monitorRunning) return
        monitorRunning = true
        kotlin.concurrent.thread(isDaemon = true, name = "builtin-privilege-monitor") {
            val ctx = context.applicationContext
            while (monitorRunning && started) {
                try {
                    Thread.sleep(30_000)
                    if (!started) break
                    val alive = BuiltinEngine.probe(ctx)
                    if (!alive) lastMessage = "守护进程已掉线，请重新激活"
                } catch (e: InterruptedException) {
                    break
                } catch (e: Throwable) {
                    Log.w(TAG, "monitor tick failed", e)
                }
            }
        }
    }

    /** 第三方应用调用前的能力自检说明 */
    fun capabilityReport(context: Context? = null): String = buildString {
        val ctx = context ?: BuiltinEngineHolder.context
        appendLine("内核版本：$CORE_VERSION（协议 v$PROTOCOL_VERSION）")
        appendLine("守护进程：" + if (ctx != null && BuiltinEngine.isAlive(ctx))
            "运行中 · ${BuiltinEngine.daemonIdentity(ctx)}" else "未运行")
        appendLine("服务状态：${state().label}")
        appendLine("运行时长：${uptimeText()}")
        appendLine("拉起通道：${Privilege.levelState.value.label}")
        append("已授权第三方应用：${grantedCount()} 个")
    }

    /** 对外接入说明 */
    fun sdkSnippet(): String = """
// 1) 探测知微是否可用
val st = contentResolver.call(
    Uri.parse("content://$AUTHORITY"), "getStatus", null, null)
if (st?.getBoolean("enabled") != true) return  // 未开启内置特权
// 2) 拿 Binder
val b = contentResolver.call(
    Uri.parse("content://$AUTHORITY"), "getBinder", null, null)
val svc = IZhiweiService.Stub.asInterface(
    (b?.getParcelable<BinderContainer>("binder"))?.binder)
// 3) 申请授权（reason 会显示在知微弹窗上）
svc.requestPermissionWithReason("需要 sh 执行能力", object : IZhiweiCallback.Stub() {
    override fun onResult(granted: Boolean) {
        if (!granted) return
        // 4) 执行。返回 "exitCode\noutput"
        val r = svc.execCommand("pm list packages -3").lines()
        val exitCode = r.firstOrNull()?.toIntOrNull() ?: -1
        val output = r.drop(1).joinToString("\n")
    }
})
""".trimIndent()

    /** 有线 ADB 模式：连接 USB 调试端口 */
    fun connectUsbDebugging(): Pair<Boolean, String> {
        AdbShell.connect("127.0.0.1", 5555).let { (ok, _) ->
            if (ok) return true to "✅ USB 调试端口 127.0.0.1:5555 已连接"
        }
        if (Prefs.adbHost.isNotEmpty() && Prefs.adbPort > 0) {
            val (ok, out) = AdbShell.connect(Prefs.adbHost, Prefs.adbPort)
            if (ok) return true to "✅ 已连接上次地址 ${Prefs.adbHost}:${Prefs.adbPort}"
            return false to "❌ 连接失败：$out"
        }
        return false to (
            "❌ 未发现可连接的 USB 调试端口。\n\n" +
                "说明：USB 调试模式需要 adbd 在 5555 端口监听，而开启该监听通常要在电脑上" +
                "执行一次 `adb tcpip 5555`。\n\n" +
                "纯手机场景请改用「无线调试」（Android 11+ 原生支持配对码，无需电脑）。"
            )
    }
}