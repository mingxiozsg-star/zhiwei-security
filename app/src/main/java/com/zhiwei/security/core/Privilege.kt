package com.zhiwei.security.core

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * 统一提权层
 * 优先级：root(su, uid 0) > Shizuku(shell, uid 2000)
 * 所有特权命令都走这里，自动选择最强可用通道
 */
object Privilege {

    private const val TAG = "Privilege"

    enum class Level(val label: String) {
        DETECTING("检测中"),
        NONE("无提权"),
        SHIZUKU("Shizuku (shell)"),
        ADB("本机 ADB (shell)"),
        SYSTEM("系统 uid (1000)"),
        ROOT("Root (uid 0)"),
        /** 内置守护进程已常驻：权限在知微自己手里，不再依赖任何外部应用 */
        BUILTIN("内置守护进程（常驻）")
    }

    /** 当前进程是否已是 android.uid.system（system 渠道包 + testkey 系统） */
    val isSystemUid: Boolean = android.os.Process.myUid() == 1000

    @Volatile private var rootChecked = false
    @Volatile private var rootAvailable = false

    /**
     * 可观察提权状态（Compose State，UI 订阅后自动刷新）。
     * 由后台检测一次性原子发布，杜绝"各通道缓存异步翻转导致状态跳变"。
     */
    val levelState = androidx.compose.runtime.mutableStateOf(Level.DETECTING)

    private var watcherStarted = false

    /** root 是否可用（读缓存，非阻塞；首次由 warmup 后台检测） */
    val hasRoot: Boolean
        get() {
            if (!rootChecked) startDetect()
            return rootAvailable
        }

    /** 后台预热提权检测（应用启动时调用一次） */
    fun warmup() {
        startDetect()
        startWatcher()
    }

    @Synchronized private fun startDetect() {
        if (rootChecked) return
        rootChecked = true
        kotlin.concurrent.thread(isDaemon = true) { detectAndPublish() }
    }

    /** 后台全量检测并原子发布（root 只在尚未可用时重试，避免反复弹 Magisk） */
    private fun detectAndPublish() {
        if (!rootAvailable) rootAvailable = checkRoot()
        try { AdbShell.refreshStatus() } catch (e: Throwable) { }
        // 内置 daemon 在线 = 优先级最高，此时外部通道存不存在都无所谓
        val builtinAlive = try {
            val ctx = BuiltinEngineHolder.context
            ctx != null && BuiltinEngine.isAlive(ctx)
        } catch (e: Throwable) { false }
        val lv = when {
            builtinAlive -> Level.BUILTIN
            rootAvailable -> Level.ROOT
            isSystemUid -> Level.SYSTEM
            AdbShell.isConnected -> Level.ADB
            ShizukuManager.isReady -> Level.SHIZUKU
            else -> Level.NONE
        }
        // Compose State 必须主线程写
        SecurityJournal.runOnMain { levelState.value = lv }
    }

    /** 每 30 秒后台重检一次（ADB 掉线/Shizuku 启停/授权变化可自动跟上） */
    @Synchronized private fun startWatcher() {
        if (watcherStarted) return
        watcherStarted = true
        kotlin.concurrent.thread(isDaemon = true) {
            while (true) {
                try { Thread.sleep(30_000); detectAndPublish() } catch (e: Throwable) { }
            }
        }
    }

    /** 手动触发重检（授权弹窗回调、ADB 连接成功后调用） */
    fun refresh() {
        kotlin.concurrent.thread(isDaemon = true) { detectAndPublish() }
    }

    private fun checkRoot(): Boolean {
        return try {
            val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val out = p.inputStream.bufferedReader().readText()
            p.waitFor() == 0 && out.contains("uid=0")
        } catch (e: Throwable) {
            false
        }
    }

    /** 当前最强可用提权等级（读 Compose 状态，UI 中读取会自动订阅刷新） */
    val level: Level get() = levelState.value

    val statusText: String
        get() = when (levelState.value) {
            Level.DETECTING -> "提权通道检测中…"
            Level.BUILTIN -> "内置守护进程已常驻（权限由知微自己持有）"
            Level.ROOT -> "Root 已就绪（uid 0，最高权限）"
            Level.SYSTEM -> "系统级提权已生效（android.uid.system）"
            Level.ADB -> "本机 ADB 已连接（shell 权限）"
            Level.SHIZUKU -> "Shizuku 已就绪（shell 权限）"
            Level.NONE -> "无提权通道"
        }

    /** 就绪判定（DETECTING 期按无提权处理，避免误放行） */
    val isReady: Boolean
        get() = levelState.value.let { it != Level.NONE && it != Level.DETECTING }

    /**
     * 执行特权命令。
     *
     * 通道优先级（关键改动）：
     *   1. **内置 daemon** —— 知微自己的常驻进程，权限在知微手里，不受任何第三方
     *      应用开关影响。只要它在，就绝不降级到外部通道。
     *   2. Root（su）
     *   3. uid.system
     *   4. 本机 ADB
     *   5. Shizuku（外部应用，随时可能被关掉，仅作兜底）
     */
    fun exec(command: String): Pair<Int, String> {
        // 1. 内置 daemon 优先（这是「权限在自己手里」的核心）
        val ctx = BuiltinEngineHolder.context
        if (ctx != null) {
            try {
                if (BuiltinEngine.isAlive(ctx)) {
                    // daemon 在线时结果即为准：命令失败就是真失败，
                    // 不再拿外部通道去「补救」，避免掩盖问题。
                    return BuiltinEngine.exec(ctx, command)
                }
            } catch (e: Throwable) {
                Log.w(TAG, "builtin daemon exec failed: $command", e)
            }
        }
        // 2. root 优先
        if (hasRoot) {
            try {
                val p = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
                val stdout = BufferedReader(InputStreamReader(p.inputStream)).readText()
                val stderr = BufferedReader(InputStreamReader(p.errorStream)).readText()
                val code = p.waitFor()
                return code to (stdout + stderr).trim()
            } catch (e: Throwable) {
                Log.w(TAG, "root exec failed: $command", e)
            }
        }
        // 3. 系统 uid：经 sh -c 执行（Runtime.exec(String) 不走 shell，分号/重定向/引号全失效）
        if (isSystemUid) {
            try {
                val p = Runtime.getRuntime().exec(arrayOf("sh", "-c", command))
                val stdout = BufferedReader(InputStreamReader(p.inputStream)).readText()
                val stderr = BufferedReader(InputStreamReader(p.errorStream)).readText()
                val code = p.waitFor()
                if (code == 0) return 0 to stdout.trim()
                if (stdout.isNotBlank() || stderr.isNotBlank()) return code to (stdout + stderr).trim()
            } catch (e: Throwable) {
                Log.w(TAG, "system exec failed: $command", e)
            }
        }
        // 4. 本机 ADB 通道
        if (AdbShell.isConnected) {
            val r = AdbShell.shell(command)
            if (r.first != -1) return r
        }
        // 5. Shizuku 兜底
        if (ShizukuManager.isReady) {
            return ShizukuManager.exec(command)
        }
        return -1 to "无可用提权通道"
    }

    /** 强制停止应用 */
    fun forceStop(pkg: String): Boolean = exec("am force-stop $pkg").first == 0

    /** 卸载应用 */
    fun uninstall(pkg: String): Boolean {
        var (code, out) = exec("pm uninstall --user 0 $pkg")
        if (code != 0 || !out.contains("Success", true)) {
            val r = exec("pm uninstall $pkg")
            code = r.first; out = r.second
        }
        return code == 0 && out.contains("Success", true)
    }

    /** 撤销设备管理员 */
    fun removeDeviceAdmin(componentFlat: String): Boolean =
        exec("dpm remove-active-admin $componentFlat").first == 0

    /** 吊销某应用的无障碍服务 */
    fun revokeAccessibility(context: android.content.Context, pkg: String) {
        val enabled = android.provider.Settings.Secure.getString(
            context.contentResolver,
            android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return
        val kept = enabled.split(":").filter { !it.startsWith("$pkg/") }
        exec("settings put secure enabled_accessibility_services '${kept.joinToString(":")}'")
    }
}