package com.zhiwei.security.core

import android.content.Context
import android.util.Log

/**
 * 内置特权服务（BuiltinPrivilege）
 *
 * 定位：知微的「Stellar / Sui 等价层」——把提权通道做成一个可被其他应用发现、
 * 申请、授权的常驻服务，而不是只给本应用自己用。
 *
 * 三层结构（对应参考样本的 Stellar 内核 + Shizuku API + 授权面板）：
 *  1. **内核**：Root / 本机 ADB / uid.system 三条真实提权通道（见 [Privilege]）
 *  2. **服务端**：[com.zhiwei.security.service.ZhiweiApiService] + [com.zhiwei.security.provider.ZhiweiProvider]，
 *     通过 ContentProvider 暴露 Binder，第三方应用可 `requestPermissionWithReason` 申请授权
 *  3. **授权**：[AuthDb] + `AuthGrantActivity`，按调用方 uid 精确判定，可随时撤销，全程审计
 *
 * 固有限制（诚实声明）：
 *  - ADB 通道的 shell 权限来自本机 adbd（uid 2000），需要用户开「无线调试 / USB 调试」，
 *    这是 Android 的安全设计，任何应用都无法绕过。
 *  - Root 通道在无 Root 设备上不存在，属正常。
 *  - 本服务对第三方开放的是**shell 级**能力，不是 root 级；第三方拿到的是调用方 uid 校验后的通道。
 */
object BuiltinPrivilege {
    private const val TAG = "BuiltinPrivilege"

    /** 服务端状态 */
    enum class State(val label: String) {
        STOPPED("服务未运行"),
        STARTING("启动中"),
        RUNNING("服务运行中"),
        NO_PRIVILEGE("无提权通道")
    }

    /** 服务端内核版本（协议版本，第三方可据此兼容） */
    const val CORE_VERSION = "1.9.0"

    /** 协议版本（与 ZhiweiApiService.VERSION 保持一致） */
    const val PROTOCOL_VERSION = 2

    /** Provider authority（第三方接入用到的常量） */
    const val AUTHORITY = "com.zhiwei.security.provider"

    @Volatile
    private var started = false

    /** 守护线程是否在跑（常驻监听提权通道变化） */
    @Volatile
    private var daemonRunning = false

    /** 最近一次启动结果（给 UI 展示） */
    @Volatile
    var lastMessage: String = ""
        private set

    /** 服务是否已启动（对外开关打开 + Binder 可下发） */
    val isServiceRunning: Boolean get() = started

    /** 本次服务启动时间（UI 算运行时长） */
    val startedAt: Long get() = Prefs.builtinStartedAt

    /** 当前运行方式（用于 UI「运行方式」字段） */
    val runMode: String
        get() = when (Privilege.levelState.value) {
            Privilege.Level.ROOT -> "Root"
            Privilege.Level.SYSTEM -> "System"
            Privilege.Level.ADB -> "ADB"
            Privilege.Level.SHIZUKU -> "Shizuku"
            else -> if (started) "待通道" else "—"
        }

    /** 聚合状态（UI 主卡用） */
    fun state(): State = when {
        !isServiceRunning -> State.STOPPED
        !Privilege.isReady -> State.NO_PRIVILEGE
        else -> State.RUNNING
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
     * 启动内置特权服务。
     *
     * Provider 只要进程活着就能被 call 到，这里额外做三件 Provider 做不到的事：
     * 1. 预热授权库与提权检测（避免第三方第一次调用等到超时）
     * 2. 起守护线程，提权通道掉线时自动重连（ADB 断连是常态）
     * 3. 把「服务已启用」写进 Prefs，供开机自启逻辑判断
     *
     * @return true 表示服务已就绪（对外开关已打开）
     */
    fun start(context: Context): Boolean {
        if (started) {
            lastMessage = "服务已在运行"
            return true
        }
        return try {
            Prefs.init(context)
            AuthDb.init(context)
            com.zhiwei.security.service.ZhiweiApiServiceHolder.context = context.applicationContext
            started = true
            Prefs.builtinPrivilegeEnabled = true
            Prefs.builtinStartedAt = System.currentTimeMillis()
            // 预热提权检测（不阻塞调用方）
            Privilege.warmup()
            try { AdbShell.refreshStatus() } catch (e: Throwable) { }
            startDaemon()
            lastMessage = "服务已启动"
            SecurityJournal.log("内置特权", "特权服务已启动，运行方式：$runMode")
            Log.i(TAG, "builtin privilege service started")
            true
        } catch (e: Throwable) {
            started = false
            lastMessage = "启动失败：${e.message}"
            Log.w(TAG, "start failed", e)
            false
        }
    }

    /** 进程冷启动后同步持久化状态（开机自启 / 被系统复活时调用） */
    fun restoreIfEnabled(context: Context) {
        Prefs.init(context)
        AuthDb.init(context)
        if (!Prefs.builtinPrivilegeEnabled) return
        if (started) return
        com.zhiwei.security.service.ZhiweiApiServiceHolder.context = context.applicationContext
        started = true
        startDaemon()
        lastMessage = "服务已恢复"
        Log.i(TAG, "builtin privilege service restored")
    }

    /** 停止服务（撤销对外暴露，不影响已有授权记录） */
    fun stop(): Boolean {
        started = false
        daemonRunning = false
        Prefs.builtinPrivilegeEnabled = false
        lastMessage = "服务已停止"
        SecurityJournal.log("内置特权", "特权服务已停止")
        return true
    }

    /**
     * 常驻守护：每 45 秒检查一次提权通道，掉线则尝试自动恢复。
     *
     * 为什么需要：ADB 无线调试在息屏 / 网络切换后经常静默掉线，
     * 用户不会主动重连，服务就变成空壳。这里做无感自愈。
     */
    private fun startDaemon() {
        if (daemonRunning) return
        daemonRunning = true
        kotlin.concurrent.thread(isDaemon = true, name = "builtin-privilege-daemon") {
            while (daemonRunning && started) {
                try {
                    Thread.sleep(45_000)
                    if (!started) break
                    // 只在「以为连着但其实断了」时才重连，避免干扰用户手动操作
                    if (!Privilege.isReady) {
                        if (Prefs.adbHost.isNotEmpty() && Prefs.adbPort > 0) {
                            AdbShell.autoReconnect()
                            Privilege.refresh()
                        }
                    }
                } catch (e: InterruptedException) {
                    break
                } catch (e: Throwable) {
                    Log.w(TAG, "daemon tick failed", e)
                }
            }
        }
    }

    /** 第三方应用调用前的能力自检说明（写进 SDK 文档与 UI） */
    fun capabilityReport(): String = buildString {
        appendLine("内核版本：$CORE_VERSION（协议 v$PROTOCOL_VERSION）")
        appendLine("运行方式：$runMode")
        appendLine("提权等级：${Privilege.levelState.value.label}")
        appendLine("服务状态：${state().label}")
        appendLine("运行时长：${uptimeText()}")
        appendLine("ADB 通道：${if (AdbShell.isConnected) "已连接 ${AdbShell.connectedDevice ?: ""}" else "未连接"}")
        appendLine("Shizuku：${ShizukuManager.statusText}")
        append("已授权第三方应用：${grantedCount()} 个")
    }

    /** 对外接入说明（UI 里直接展示给用户看，也能复制给开发者） */
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

    /**
     * 有线 ADB 模式：连接 USB 调试端口。
     *
     * 与无线调试的区别只在端口来源：USB 调试默认监听本机 5555（部分机型需手动
     * `adb tcpip 5555`，但那一步本身就需要电脑，因此在纯手机场景下，
     * 这里主要尝试「本机 127.0.0.1:5555」与「上一次记住的地址」）。
     */
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
