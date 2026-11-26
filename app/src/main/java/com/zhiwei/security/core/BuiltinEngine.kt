package com.zhiwei.security.core

import android.content.Context
import android.os.Process
import android.util.Log
import java.io.InputStream
import java.net.InetAddress
import java.net.Socket
import java.util.Base64
import java.util.UUID

/**
 * 内置守护进程客户端（BuiltinEngine）
 *
 * 职责：把知微自己的代码以提权身份拉成常驻进程，之后所有特权命令走它。
 *
 * 与参考样本 Stellar 的对应关系：
 *   Stellar:  CLASSPATH=<apk> app_process /system/bin --nice-name=stellar_daemon \
 *             roro.stellar.server.daemon.StellarDaemon <pid> '<cmd>'
 *   知微:     CLASSPATH=<apk> app_process /system/bin --nice-name=zhiwei_daemon \
 *             com.zhiwei.security.daemon.ZhiweiDaemon <port> <token>
 *
 * 关键点（这是与旧实现的本质区别）：
 *  - 拉起只发生在「安装后第一次激活」的那一下，需要一次已有提权通道（ADB/Root）。
 *  - 进程拉起后**权限就在知微自己手里**：外部 Shizuku/Dhizuku 之后关掉授权、
 *    甚至卸载，都不影响 daemon 继续以 shell/root 身份执行命令。
 *  - 设备重启 / daemon 被杀后需要重新拉起（同样需要一次通道），这是 Android
 *    的硬限制：非系统应用无法在无提权的情况下自建高权限进程。
 */
object BuiltinEngine {

    private const val TAG = "BuiltinEngine"
    private const val NICE_NAME = "zhiwei_daemon"
    private const val MAIN_CLASS = "com.zhiwei.security.daemon.ZhiweiDaemon"
    private const val LOG_PATH = "/data/local/tmp/zhiwei_daemon.log"
    /** 备用的 APK 副本路径：部分机型 shell 读不到 /data/app 下的 base.apk */
    private const val TMP_APK = "/data/local/tmp/zhiwei_daemon.apk"
    /** 固定端口（仅监听 127.0.0.1），daemon 端可能回退到 PORT..PORT+7 */
    private const val PORT = 38271
    private const val PORT_RANGE = 8

    /** 探活/执行超时 */
    private const val PING_TIMEOUT_MS = 2_500
    private const val EXEC_TIMEOUT_MS = 40_000

    private const val CMD_PING = "__ping__"
    private const val CMD_STOP = "__stop__"
    private const val CMD_LOG = "__log__"

    /** daemon 是否在线（带短缓存，避免每次命令都 ping） */
    @Volatile private var aliveCache = false
    @Volatile private var aliveCheckedAt = 0L

    /** 上次探测到在线的端口（避免每次全区间扫描） */
    @Volatile private var activePort = 0


    /**
     * 取 daemon 鉴权 token。
     *
     * 存 SharedPreferences 而不是写进命令行参数以外的文件：只有本应用（同 uid）
     * 能读到，配合 127.0.0.1 绑定，其他应用即使猜到端口也连不上。
     */
    private fun token(context: Context): String {
        Prefs.init(context)
        var t = Prefs.daemonToken
        if (t.length < 16) {
            t = UUID.randomUUID().toString() + UUID.randomUUID().toString().substring(0, 8)
            Prefs.daemonToken = t
        }
        return t
    }

    /** 本应用 APK 路径（daemon 的 CLASSPATH） */
    private fun apkPath(context: Context): String = context.applicationInfo.sourceDir

    /** 用 token 派生签名（与 ZhiweiDaemon.sign 保持一致），用于识别冒名进程 */
    private fun expectedSign(token: String, uid: Int): String {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val raw = md.digest("$token|ping|$uid".toByteArray(Charsets.UTF_8))
        return raw.joinToString("") { "%02x".format(it.toInt() and 0xff) }.substring(0, 16)
    }

    /** daemon 进程是否存活（真连一次，不走缓存） */
    fun probe(context: Context): Boolean {
        val r = try {
            pingOnce(context)
        } catch (e: Throwable) {
            null
        }
        val ok = r != null
        aliveCache = ok
        aliveCheckedAt = System.currentTimeMillis()
        return ok
    }

    /**
     * 扫端口 ping 一次，返回 "uid=<uid>" 携带的 uid（失败返回 null）。
     * 会校验 token 派生签名：同机应用即便抢占端口伪造 "OK"，签名也对不上。
     */
    private fun pingOnce(context: Context): Int? {
        val tk = token(context)
        val candidates = buildList {
            val last = activePort
            if (last in PORT until PORT + PORT_RANGE) add(last)
            for (p in PORT until PORT + PORT_RANGE) if (p != last) add(p)
        }
        for (p in candidates) {
            val r = try {
                socketExec(context, p, CMD_PING, PING_TIMEOUT_MS)
            } catch (e: Throwable) {
                null
            } ?: continue
            if (r.first != 0 || !r.second.contains("ZHIWEI_DAEMON_OK")) continue
            val uid = r.second.substringAfter("uid=", "?").substringBefore(" ").toIntOrNull() ?: continue
            val sign = r.second.substringAfter("sign=", "")
            if (sign != expectedSign(tk, uid)) {
                Log.w(TAG, "端口 $p 回包签名不符，疑似冒充进程")
                continue
            }
            activePort = p
            return uid
        }
        return null
    }

    /** daemon 是否在线（1.5 秒内复用缓存结果） */
    fun isAlive(context: Context): Boolean {
        val now = System.currentTimeMillis()
        if (now - aliveCheckedAt < 1_500) return aliveCache
        return probe(context)
    }

    /** daemon 运行身份（uid）文本，用于 UI 展示 */
    fun daemonIdentity(context: Context): String {
        val uid = pingOnce(context) ?: return "未运行"
        return when (uid) {
            0 -> "Root (uid 0)"
            2000 -> "Shell (uid 2000)"
            1000 -> "System (uid 1000)"
            else -> "uid $uid"
        }
    }

    /**
     * 确保 daemon 已启动。
     *
     * @param via 用于拉起的提权通道说明（仅日志用）
     * @return Pair(是否成功, 说明文本)
     */
    fun ensureStarted(context: Context): Pair<Boolean, String> {
        if (probe(context)) return true to "守护进程已在运行（${daemonIdentity(context)}）"

        val apk = apkPath(context)
        val tk = token(context)

        // 依次尝试各提权通道（谁可用谁拉）
        val channels = mutableListOf<Pair<String, (String) -> Pair<Int, String>>>()
        if (Privilege.hasRoot) {
            channels += "Root" to { cmd -> runShellAsRoot(apk, cmd) }
        }
        if (Privilege.isSystemUid) {
            channels += "System" to { cmd -> runShell(cmd) }
        }
        if (AdbShell.isConnected) {
            channels += "ADB" to { cmd -> AdbShell.shell(cmd) }
        }
        if (ShizukuManager.isReady) {
            channels += "Shizuku" to { cmd -> ShizukuManager.exec(cmd) }
        }
        if (channels.isEmpty()) {
            return false to "无可用提权通道：请先完成无线调试配对或 Root"
        }

        // 清掉可能残留的旧实例：token 轮换（清除数据）或旧版本残留会占着端口，
        // 导致新 daemon 绑不上。先杀干净再拉。
        channels.firstOrNull()?.let { (_, exec) ->
            try {
                exec("pkill -f $NICE_NAME")
                Thread.sleep(300)
            } catch (e: Throwable) { }
        }

        // 两轮：先用安装目录里的 APK；若失败（shell 常读不到 /data/app），
        // 再把 APK 复制到 /data/local/tmp 用副本加载，绕开读取权限问题。
        val classpaths = mutableListOf<String>()
        classpaths += apk
        classpaths += TMP_APK

        val tried = mutableListOf<String>()
        for (cp in classpaths) {
            if (cp == TMP_APK) {
                // 准备副本：/data/local/tmp 对 shell 可写
                val prepared = channels.any { (_, run) ->
                    try {
                        // 只信命令退出码：宿主 uid 无法 stat /data/local/tmp，不能靠 File.exists 判断
                        run("cp -f $apk $TMP_APK && chmod 644 $TMP_APK").first == 0
                    } catch (e: Throwable) { false }
                }
                if (!prepared) {
                    tried += "复制副本失败"
                    continue
                }
            }
            val launcher = buildLauncher(cp, tk)
            for ((name, run) in channels) {
                tried += name
                try {
                    run(launcher)
                } catch (e: Throwable) {
                    Log.w(TAG, "$name 拉起失败", e)
                    continue
                }
                // 最多等 4 秒让 daemon 起来（含 app_process 冷启动）
                var waited = 0
                while (waited < 4_000) {
                    Thread.sleep(300); waited += 300
                    if (probe(context)) {
                        val id = daemonIdentity(context)
                        SecurityJournal.log("内置特权", "守护进程已由 $name 渠道拉起（$id）")
                        return true to "✅ 守护进程已启动，运行身份：$id"
                    }
                }
            }
        }
        return false to "❌ 已尝试 ${tried.distinct().joinToString("/")} 渠道，但守护进程未就绪。\n" +
            "常见原因：SELinux 限制了对该路径执行 app_process，或该机型禁用了 app_process 加载外部 APK。"
    }

    /**
     * 构造拉起命令。
     *  - setsid：让 daemon 脱离拉起方的会话，su/adb shell 退出时不会被连带杀掉
     *  - exec app_process：以 daemon 进程替换 sh，少一层中间进程
     *  - CLASSPATH 指向 APK，由 app_process 加载 com.zhiwei.security.daemon.ZhiweiDaemon
     */
    private fun buildLauncher(classpath: String, token: String): String =
        "setsid sh -c 'CLASSPATH=$classpath exec app_process /system/bin " +
            "--nice-name=$NICE_NAME $MAIN_CLASS $PORT $token' >/dev/null 2>&1 </dev/null &"

    /** 停止 daemon */
    fun stop(context: Context): Boolean {
        // 先按已知端口停；未知就扫一遍
        var port = activePort
        if (port !in PORT until PORT + PORT_RANGE) {
            pingOnce(context)
            port = activePort
        }
        if (port in PORT until PORT + PORT_RANGE) {
            try { socketExec(context, port, CMD_STOP, 3_000) } catch (e: Throwable) { }
        }
        aliveCache = false
        aliveCheckedAt = 0
        activePort = 0
        // 兜底 pkill：只在确认 daemon 已失联时用。
        // 不能在 daemon 存活时执行 —— 那条命令会路由给 daemon 自己，
        // 等于让它中途自杀，回包必然断掉。
        val stillAlive = try { probe(context) } catch (e: Throwable) { false }
        if (!stillAlive) {
            try {
                if (Privilege.isReady) Privilege.exec("pkill -f $NICE_NAME")
            } catch (e: Throwable) { }
        }
        return true
    }

    /**
     * 执行特权命令。
     *
     * 优先走内置 daemon（权限在自己手里）；daemon 不在时**不会**静默降级到
     * 外部通道，而是明确返回失败并要求用户先激活——避免「以为有特权其实没有」。
     */
    fun exec(context: Context, command: String): Pair<Int, String> {
        val port = try {
            pingOnce(context)
            activePort
        } catch (e: Throwable) { 0 }
        if (port !in PORT until PORT + PORT_RANGE) {
            aliveCache = false
            return -1 to "内置守护进程未运行，请先在「内置特权」中启动"
        }
        return try {
            socketExec(context, port, command, EXEC_TIMEOUT_MS)
                ?: (-1 to "守护进程无响应")
        } catch (e: Throwable) {
            aliveCache = false
            (-1 to ("守护进程通信失败：${e.message}"))
        }
    }

    // ===== 底层通信 =====

    /**
     * 与 daemon 通信：发 token + Base64(命令)，收 exitCode + Base64(输出)。
     * @return null 表示连不上（daemon 未启动）
     */
    private fun socketExec(
        context: Context,
        port: Int,
        command: String,
        timeoutMs: Int
    ): Pair<Int, String>? {
        val tk = token(context)
        val socket = try {
            Socket()
        } catch (e: Throwable) {
            return null
        }
        return try {
            socket.connect(java.net.InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), timeoutMs)
            socket.soTimeout = timeoutMs
            val out = socket.getOutputStream()
            val payload = tk + "\n" + Base64.getEncoder()
                .encodeToString(command.toByteArray(Charsets.UTF_8)) + "\n"
            out.write(payload.toByteArray(Charsets.UTF_8))
            out.flush()

            val input = socket.getInputStream()
            val header = readLine(input) ?: return null
            val code = header.removePrefix("EXIT ").trim().toIntOrNull() ?: -1
            val body = readLine(input).orEmpty()
            val text = try {
                String(Base64.getDecoder().decode(body), Charsets.UTF_8)
            } catch (e: Throwable) {
                ""
            }
            code to text
        } catch (e: Throwable) {
            null
        } finally {
            try { socket.close() } catch (e: Throwable) { }
        }
    }

    private fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) return sb.toString()
            if (sb.length > 1 shl 20) return null
            sb.append(b.toChar())
        }
    }

    // ===== 拉起用的 shell 执行（只在启动瞬间用一次） =====

    private fun runShell(cmd: String): Pair<Int, String> = try {
        val p = ProcessBuilder("sh", "-c", cmd).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        p.waitFor()
        p.exitValue() to out.trim()
    } catch (e: Throwable) {
        -1 to (e.message ?: "")
    }

    /** root 通道拉起：su -c 执行 launcher，并顺手准备可写日志文件 */
    private fun runShellAsRoot(apk: String, launcher: String): Pair<Int, String> {
        val script = "touch $LOG_PATH 2>/dev/null; chmod 666 $LOG_PATH 2>/dev/null; " +
            "chmod 644 $apk 2>/dev/null; $launcher"
        return try {
            val p = ProcessBuilder("su", "-c", script).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText()
            p.waitFor()
            p.exitValue() to out.trim()
        } catch (e: Throwable) {
            -1 to (e.message ?: "")
        }
    }

    /** 给日志文件做准备（非 root 渠道也要能写日志） */
    fun prepareLogFile(context: Context) {
        try {
            if (Privilege.isReady) {
                Privilege.exec("touch $LOG_PATH 2>/dev/null; chmod 666 $LOG_PATH 2>/dev/null")
            }
        } catch (e: Throwable) { }
    }

    /**
     * 读取 daemon 日志（排障用，UI 可展示）。
     *
     * 注意：宿主 App 的 uid 读不了 /data/local/tmp（SELinux 限制），
     * 所以优先让 daemon 自己读并回传；daemon 不在时才退回直读。
     */
    fun tailLog(context: Context? = null, lines: Int = 40): String {
        if (context != null) {
            try {
                val port = pingOnce(context)
                if (port != null && activePort in PORT until PORT + PORT_RANGE) {
                    val r = socketExec(context, activePort, CMD_LOG, 5_000)
                    if (r != null && r.first == 0) return r.second.ifBlank { "（无日志）" }
                }
            } catch (e: Throwable) { }
        }
        val text = try {
            val f = java.io.File(LOG_PATH)
            if (!f.exists()) return "（无日志）"
            f.readText()
        } catch (e: Throwable) {
            return "（守护进程未运行，日志需 daemon 在线才能读取）"
        }
        val all = text.lines().filter { it.isNotBlank() }
        return if (all.size <= lines) all.joinToString("\n")
        else all.takeLast(lines).joinToString("\n")
    }

    /** 当前进程 uid 是否为 shell 身份（判断 daemon 权限等级时的参考） */
    fun selfUidText(): String = when (Process.myUid()) {
        0 -> "Root"
        1000 -> "System"
        2000 -> "Shell"
        else -> "App(${Process.myUid()})"
    }
}

/**
 * 进程内 Context 持有者（供 [com.zhiwei.security.core.Privilege] 无参调用时使用）。
 *
 * 单独放在文件末尾，避免 Privilege ↔ BuiltinEngine 循环初始化问题。
 */
object BuiltinEngineHolder {
    @Volatile
    var context: Context? = null
}