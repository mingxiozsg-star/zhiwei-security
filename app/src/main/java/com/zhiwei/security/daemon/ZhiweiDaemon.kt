package com.zhiwei.security.daemon

import java.io.FileOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Base64
import java.util.concurrent.Executors

/**
 * 知微内置守护进程（app_process 入口）
 *
 * 这是「内置特权」的真身，机制与参考样本 Stellar 完全一致：
 *
 *   CLASSPATH=<本应用 APK> app_process /system/bin --nice-name=zhiwei_daemon \
 *       com.zhiwei.security.daemon.ZhiweiDaemon <port> <token>
 *
 * 一旦被拉起，本进程就**以提权身份（shell uid 2000 / root uid 0）常驻**，
 * 后续所有特权命令都交给它执行。关键差异：
 *
 *  - 旧实现：命令靠外部 Shizuku / Dhizuku 应用执行 → 对方关授权，知微立刻失能。
 *  - 本实现：命令由知微自己的守护进程执行 → 权限在知微自己手里，不再受任何
 *    第三方应用开关影响。外部通道断了也不影响已拉起的 daemon。
 *
 * 协议（localhost TCP，单请求单连接）：
 *   客户端发送： `<token>\n` + `<Base64(命令)>\n`
 *   服务端回复： `EXIT <code>\n` + `<Base64(输出)>`
 *   token 用于拒绝同机其他应用的越权连接；绑定地址固定 127.0.0.1。
 *
 * 保留命令：`__ping__` 探活、`__stop__` 自杀。
 */
object ZhiweiDaemon {
    /** 日志文件（shell 可写，方便排障） */
    private const val LOG_PATH = "/data/local/tmp/zhiwei_daemon.log"

    /** 默认端口与回退区间长度 */
    private const val DEFAULT_PORT = 38271
    private const val PORT_RANGE = 8

    /** 单条命令默认超时（毫秒） */
    private const val EXEC_TIMEOUT_MS = 30_000L

    private const val CMD_PING = "__ping__"
    private const val CMD_STOP = "__stop__"
    private const val CMD_LOG = "__log__"

    /**
     * 用 token 派生签名，客户端据此确认「回包确实来自真 daemon」而
     * 不是同机上抢占了同一端口的冒名进程。
     */
    private fun sign(token: String, uid: Int): String {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val raw = md.digest("$token|ping|$uid".toByteArray(Charsets.UTF_8))
        return raw.joinToString("") { "%02x".format(it.toInt() and 0xff) }.substring(0, 16)
    }


    @JvmStatic
    fun main(args: Array<String>) {
        val wantPort = args.getOrNull(0)?.toIntOrNull() ?: DEFAULT_PORT
        val token = args.getOrNull(1)?.trim().orEmpty()
        if (token.length < 16) {
            log("拒绝启动：token 无效")
            return
        }

        // 端口回退：同机其他应用可能恶意占用 38271 来 DoS / 伪造回包。
        // 依次在 DEFAULT_PORT..DEFAULT_PORT+8 中找第一个能绑定的端口，
        // 客户端同样遍历该区间并用 token 派生签名校验，抢不到也伪造不了。
        var bound: ServerSocket? = null
        var port = wantPort
        for (p in wantPort until wantPort + PORT_RANGE) {
            try {
                bound = ServerSocket(p, 8, InetAddress.getByName("127.0.0.1"))
                port = p
                break
            } catch (e: Throwable) {
                log("端口 $p 无法绑定：${e.message}")
            }
        }
        val server = bound
        if (server == null) {
            log("全部端口均被占用，退出")
            return
        }
        log("启动 port=$port uid=${myUid()}")

        val pool = Executors.newCachedThreadPool { r ->
            Thread(r, "zhiwei-daemon-worker").apply { isDaemon = true }
        }
        while (true) {
            val socket = try {
                server.accept()
            } catch (e: Throwable) {
                continue
            }
            try {
                pool.execute { handle(socket, token) }
            } catch (e: Throwable) {
                try { socket.close() } catch (t: Throwable) { }
            }
        }
    }

    /** 处理一条连接：鉴权 → 执行 → 回包（Base64 保证二进制安全） */
    private fun handle(socket: Socket, token: String) {
        try {
            socket.soTimeout = (EXEC_TIMEOUT_MS + 15_000).toInt()
            val input = socket.getInputStream()
            val lineToken = readLine(input) ?: return
            if (lineToken != token) {
                reply(socket, -403, "invalid token")
                return
            }
            val lineCmd = readLine(input) ?: return
            val cmd = try {
                String(Base64.getDecoder().decode(lineCmd), Charsets.UTF_8)
            } catch (e: Throwable) {
                reply(socket, -400, "bad payload")
                return
            }

            when (cmd) {
                CMD_PING -> {
                    val uid = myUid()
                    // 带 token 派生签名：客户端可确认回包来自真 daemon，而非
                    // 抢占端口的第三方应用伪造的 OK。
                    reply(socket, 0, "ZHIWEI_DAEMON_OK uid=$uid sign=${sign(token, uid)}")
                    return
                }
                CMD_STOP -> {
                    reply(socket, 0, "BYE")
                    log("收到停止指令，退出")
                    kotlin.system.exitProcess(0)
                }
                CMD_LOG -> {
                    // 由 daemon（shell/root 身份）自己读日志：
                    // 宿主 App 的 uid 受 SELinux 限制读不了 /data/local/tmp。
                    reply(socket, 0, readLogTail())
                    return
                }
            }

            val (code, out) = runShell(cmd)
            reply(socket, code, out)
        } catch (e: Throwable) {
            try { reply(socket, -500, "daemon error: ${e.message}") } catch (t: Throwable) { }
        } finally {
            try { socket.close() } catch (e: Throwable) { }
        }
    }

    /** 以本进程身份（shell/root）执行 shell 命令 */
    private fun runShell(cmd: String): Pair<Int, String> {
        return try {
            val pb = ProcessBuilder("sh", "-c", cmd)
            pb.redirectErrorStream(true)
            val p = pb.start()
            val out = StringBuilder()
            val reader = Thread {
                try {
                    val inp = p.inputStream
                    val buf = ByteArray(8192)
                    while (true) {
                        val n = inp.read(buf)
                        if (n <= 0) break
                        out.append(String(buf, 0, n, Charsets.UTF_8))
                    }
                } catch (e: Throwable) { }
            }
            reader.isDaemon = true
            reader.start()
            val done = p.waitFor(EXEC_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
            if (!done) {
                p.destroyForcibly()
                return -2 to "超时（${EXEC_TIMEOUT_MS}ms）"
            }
            reader.join(2000)
            p.exitValue() to out.toString().trim()
        } catch (e: Throwable) {
            -1 to (e.message ?: "执行失败")
        }
    }

    private fun reply(socket: Socket, code: Int, output: String) {
        val payload = "EXIT $code\n" + Base64.getEncoder()
            .encodeToString(output.toByteArray(Charsets.UTF_8))
        socket.getOutputStream().apply {
            write(payload.toByteArray(Charsets.UTF_8))
            flush()
        }
    }

    private fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) return sb.toString()
            if (sb.length > 64 * 1024) return null
            sb.append(b.toChar())
        }
    }

    private fun myUid(): Int = android.os.Process.myUid()

    private fun log(msg: String) {
        try {
            FileOutputStream(LOG_PATH, true).use { fos ->
                val line = "[${System.currentTimeMillis()}] $msg\n"
                fos.write(line.toByteArray(Charsets.UTF_8))
            }
        } catch (e: Throwable) { }
    }

    /** 读日志尾部（供客户端排障，避免宿主 uid 直读 /data/local/tmp 被 SELinux 拒绝） */
    private fun readLogTail(lines: Int = 40): String = try {
        val f = java.io.File(LOG_PATH)
        if (!f.exists()) "（无日志）"
        else {
            val all = f.readLines().filter { it.isNotBlank() }
            if (all.size <= lines) all.joinToString("\n") else all.takeLast(lines).joinToString("\n")
        }
    } catch (e: Throwable) {
        "（日志不可读：${e.message}）"
    }
}
