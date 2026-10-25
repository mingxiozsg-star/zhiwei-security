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
        NONE("无提权"),
        SHIZUKU("Shizuku (shell)"),
        ADB("本机 ADB (shell)"),
        SYSTEM("系统 uid (1000)"),
        ROOT("Root (uid 0)")
    }

    /** 当前进程是否已是 android.uid.system（system 渠道包 + testkey 系统） */
    val isSystemUid: Boolean = android.os.Process.myUid() == 1000

    @Volatile private var rootChecked = false
    @Volatile private var rootAvailable = false

    /** root 是否可用（读缓存，非阻塞；首次由 warmup 后台检测） */
    val hasRoot: Boolean
        get() {
            if (!rootChecked) {
                rootChecked = true
                // 后台检测，避免主线程执行 su 阻塞（Magisk 弹窗会长时间无返回）
                kotlin.concurrent.thread(isDaemon = true) {
                    rootAvailable = checkRoot()
                }
            }
            return rootAvailable
        }

    /** 后台预热提权检测（应用启动时调用一次） */
    fun warmup() {
        kotlin.concurrent.thread(isDaemon = true) {
            rootChecked = true
            rootAvailable = checkRoot()
            try { AdbShell.refreshStatus() } catch (e: Throwable) { }
        }
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

    /** 当前最强可用提权等级 */
    val level: Level
        get() = when {
            hasRoot -> Level.ROOT
            isSystemUid -> Level.SYSTEM
            AdbShell.isConnected -> Level.ADB
            ShizukuManager.isReady -> Level.SHIZUKU
            else -> Level.NONE
        }

    val statusText: String
        get() = when (level) {
            Level.ROOT -> "Root 已就绪（uid 0，最高权限）"
            Level.SYSTEM -> "系统级提权已生效（android.uid.system）"
            Level.ADB -> "本机 ADB 已连接（shell 权限）"
            Level.SHIZUKU -> "Shizuku 已就绪（shell 权限）"
            Level.NONE -> "无提权通道"
        }

    val isReady: Boolean get() = level != Level.NONE

    /** 执行特权命令，自动选择 root 或 Shizuku，返回 (exitCode, 输出) */
    fun exec(command: String): Pair<Int, String> {
        // root 优先
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
        // 系统 uid：直接执行（uid 1000 自带签名级权限，am/pm 特权命令直接可用）
        if (isSystemUid) {
            try {
                val p = Runtime.getRuntime().exec(command)
                val stdout = BufferedReader(InputStreamReader(p.inputStream)).readText()
                val stderr = BufferedReader(InputStreamReader(p.errorStream)).readText()
                val code = p.waitFor()
                if (code == 0) return 0 to stdout.trim()
                if (stdout.isNotBlank() || stderr.isNotBlank()) return code to (stdout + stderr).trim()
            } catch (e: Throwable) {
                Log.w(TAG, "system exec failed: $command", e)
            }
        }
        // 本机 ADB 通道（优先于 Shizuku）
        if (AdbShell.isConnected) {
            val r = AdbShell.shell(command)
            if (r.first != -1) return r
        }
        // Shizuku 兜底
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