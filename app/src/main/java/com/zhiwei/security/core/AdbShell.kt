package com.zhiwei.security.core

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * 本机 ADB 自提权（LADB 方案）
 *
 * 原理：完整 adb 客户端二进制打包成 libadb.so 放进 jniLibs，
 * 系统会把它解压到 nativeLibraryDir 并带可执行权限。
 * 用户开启「无线调试」后，App 自己执行：
 *   adb pair <ip>:<pairPort> <配对码>   （一次性配对）
 *   adb connect <ip>:<connectPort>      （连接本机 adbd）
 * 之后 adb shell 命令即以 shell(uid 2000) 身份运行，等效 Shizuku。
 */
object AdbShell {

    private const val TAG = "AdbShell"

    private lateinit var adbPath: String
    private lateinit var homeDir: String

    fun init(context: Context) {
        adbPath = context.applicationInfo.nativeLibraryDir + "/libadb.so"
        homeDir = context.filesDir.absolutePath
    }

    /** adb 二进制是否存在且可执行 */
    val isBinaryAvailable: Boolean
        get() = try { java.io.File(adbPath).let { it.exists() && it.canExecute() } } catch (e: Throwable) { false }

    // 连接状态缓存（主线程安全：getter 不阻塞，由 refreshStatus 后台刷新）
    @Volatile private var cachedConnected = false
    @Volatile private var cachedDevice: String? = null

    /** 是否已连接本机 adbd（读缓存，非阻塞） */
    val isConnected: Boolean get() = cachedConnected

    /** 已连接的设备地址（读缓存，非阻塞） */
    val connectedDevice: String? get() = cachedDevice

    /** 实际探测连接状态并刷新缓存（阻塞，必须在后台线程调用） */
    fun refreshStatus(): Boolean {
        val (code, out) = rawExec(arrayOf(adbPath, "devices"))
        val dev = if (code == 0) out.lines()
            .firstOrNull { it.contains("\tdevice") }?.substringBefore("\t") else null
        cachedDevice = dev
        cachedConnected = dev != null
        return cachedConnected
    }

    /** 配对（无线调试界面显示的 IP:配对端口 + 6位配对码） */
    fun pair(ip: String, port: Int, code: String): Pair<Boolean, String> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return false to "无线调试需要 Android 11+"
        }
        val (exit, out) = rawExec(arrayOf(adbPath, "pair", "$ip:$port", code), timeoutMs = 30_000)
        val ok = out.contains("Successfully paired", true)
        return ok to out
    }

    /** 连接（无线调试首页显示的 IP:端口，注意和配对端口不同） */
    fun connect(ip: String, port: Int): Pair<Boolean, String> {
        val (exit, out) = rawExec(arrayOf(adbPath, "connect", "$ip:$port"), timeoutMs = 15_000)
        val ok = out.contains("connected to", true) && !out.contains("failed", true)
        if (ok) {
            Prefs.adbHost = ip
            Prefs.adbPort = port
            cachedConnected = true
            cachedDevice = "$ip:$port"
        } else {
            refreshStatus() // 同步真实状态（可能连的是旧地址）
        }
        try { Privilege.refresh() } catch (e: Throwable) { }
        return ok to out
    }

    /** 尝试用上次保存的地址自动重连 */
    fun autoReconnect(): Boolean {
        val ip = Prefs.adbHost
        val port = Prefs.adbPort
        if (ip.isEmpty() || port == 0) return false
        return connect(ip, port).first
    }

    /** 以 shell 身份执行命令 */
    fun shell(command: String): Pair<Int, String> {
        val device = connectedDevice ?: return -1 to "未连接"
        val r = rawExec(arrayOf(adbPath, "-s", device, "shell", command), timeoutMs = 30_000)
        // 进程级失败（二进制异常/连接断开）：缓存状态可能已过期，后台重检纠正
        if (r.first == -1) {
            kotlin.concurrent.thread(isDaemon = true) {
                try { refreshStatus(); Privilege.refresh() } catch (e: Throwable) { }
            }
        }
        return r
    }

    private fun rawExec(args: Array<String>, timeoutMs: Long = 15_000): Pair<Int, String> {
        return try {
            val pb = ProcessBuilder(*args)
            val env = pb.environment()
            env["HOME"] = homeDir
            env["TMPDIR"] = homeDir
            env["ADB_SERVER_SOCKET"] = "tcp:5037"
            pb.redirectErrorStream(true)
            val p = pb.start()
            val reader = BufferedReader(InputStreamReader(p.inputStream))
            val out = StringBuilder()
            val t = Thread {
                try {
                    var line = reader.readLine()
                    while (line != null) {
                        out.appendLine(line)
                        line = reader.readLine()
                    }
                } catch (e: Exception) { }
            }
            t.start()
            val done = p.waitFor(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
            if (!done) {
                p.destroyForcibly()
                return -2 to "超时"
            }
            t.join(1000)
            p.exitValue() to out.toString().trim()
        } catch (e: Throwable) {
            Log.w(TAG, "exec failed: ${args.joinToString(" ")}", e)
            -1 to (e.message ?: "执行失败")
        }
    }
}