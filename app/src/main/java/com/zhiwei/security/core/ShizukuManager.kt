package com.zhiwei.security.core

import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import rikka.shizuku.Shizuku
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Shizuku 管理器
 * 负责 binder 状态检测、权限申请、以 shell 身份执行命令（force-stop / uninstall）
 */
object ShizukuManager {

    private const val TAG = "ShizukuManager"

    /** binder 是否存活（Shizuku 服务在运行） */
    val isBinderAlive: Boolean
        get() = try { Shizuku.pingBinder() } catch (e: Throwable) { false }

    /** 是否已授权 */
    val isGranted: Boolean
        get() = try {
            isBinderAlive && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        } catch (e: Throwable) { false }

    /** 可用 = binder 存活 + 已授权 */
    val isReady: Boolean get() = isGranted

    /** 状态描述（UI 显示用） */
    val statusText: String
        get() = when {
            !isBinderAlive -> "Shizuku 未运行"
            !isGranted -> "未授权"
            else -> "已连接 (uid ${runCatching { Shizuku.getUid() }.getOrDefault(-1)})"
        }

    private var requestCallback: ((Boolean) -> Unit)? = null

    private val requestCode = 10086

    private val permissionListener = Shizuku.OnRequestPermissionResultListener { code, grantResult ->
        if (code == requestCode) {
            val granted = grantResult == PackageManager.PERMISSION_GRANTED
            Prefs.shizukuGranted = granted
            try { Privilege.refresh() } catch (e: Throwable) { }
            requestCallback?.invoke(granted)
            requestCallback = null
        }
    }

    fun init() {
        try {
            Shizuku.addRequestPermissionResultListener(permissionListener)
        } catch (e: Throwable) {
            Log.w(TAG, "addRequestPermissionResultListener failed", e)
        }
    }

    /** 请求 Shizuku 授权，结果通过回调返回 */
    fun requestPermission(onResult: (Boolean) -> Unit) {
        if (isGranted) { onResult(true); return }
        if (!isBinderAlive) { onResult(false); return }
        requestCallback = onResult
        try {
            Shizuku.requestPermission(requestCode)
        } catch (e: Throwable) {
            Log.w(TAG, "requestPermission failed", e)
            requestCallback = null
            onResult(false)
        }
    }

    /** 以 Shizuku 身份执行 shell 命令，返回 (exitCode, 输出) */
    fun exec(command: String): Pair<Int, String> {
        if (!isReady) return -1 to "Shizuku 不可用"
        return try {
            val method = Shizuku::class.java.getDeclaredMethod(
                "newProcess",
                Array<String>::class.java,
                Array<String>::class.java,
                String::class.java
            )
            method.isAccessible = true
            val process = method.invoke(null, arrayOf("sh", "-c", command), null, null) as Process
            val stdout = BufferedReader(InputStreamReader(process.inputStream)).readText()
            val stderr = BufferedReader(InputStreamReader(process.errorStream)).readText()
            val code = process.waitFor()
            code to (stdout + stderr).trim()
        } catch (e: Throwable) {
            Log.w(TAG, "exec failed: $command", e)
            -2 to (e.message ?: "执行失败")
        }
    }

    /** 强制停止应用（需要 Shizuku） */
    fun forceStop(pkg: String): Boolean {
        val (code, out) = exec("am force-stop $pkg")
        Log.i(TAG, "forceStop $pkg -> $code $out")
        return code == 0
    }

    /** 卸载应用（需要 Shizuku；保留数据失败时尝试完全卸载） */
    fun uninstall(pkg: String): Boolean {
        var (code, out) = exec("pm uninstall --user 0 $pkg")
        Log.i(TAG, "uninstall $pkg -> $code $out")
        if (code != 0 || !out.contains("Success", ignoreCase = true)) {
            val r = exec("pm uninstall $pkg")
            code = r.first; out = r.second
        }
        return code == 0 && out.contains("Success", ignoreCase = true)
    }

    /** 撤销设备管理员（对付锁机应用，需要 Shizuku/shell 权限） */
    fun removeDeviceAdmin(pkg: String, component: String): Boolean {
        val (code, out) = exec("dpm remove-active-admin $pkg/$component")
        Log.i(TAG, "removeDeviceAdmin $pkg -> $code $out")
        return code == 0
    }

    /** 查询应用激活的设备管理员组件列表 */
    fun listActiveAdmins(pkg: String): List<String> {
        val (code, out) = exec("dumpsys device_policy | grep -A 50 'Active admin'")
        if (code != 0) return emptyList()
        return out.lineSequence()
            .filter { it.contains(pkg) && it.contains("ComponentInfo") }
            .mapNotNull {
                Regex("ComponentInfo\\{([^}]+)\\}").find(it)?.groupValues?.get(1)
            }.toList()
    }
}
