package com.zhiwei.security.core

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log

/**
 * 系统权限自动收回
 *
 * 对非白名单第三方应用，通过提权通道收回其已授予的危险权限：
 *  - 运行时权限：pm revoke <pkg> <perm>
 *  - 特殊权限：appops deny（悬浮窗 / 修改系统设置 / 安装未知应用）
 *
 * 权限白名单（Prefs.permWhitelist）和系统应用不受影响。
 */
object PermissionRevoker {

    private const val TAG = "PermissionRevoker"

    /** 可通过 pm revoke 收回的运行时危险权限（白名单：只收真正高危的） */
    private val revocablePerms = listOf(
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.CALL_PHONE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    )

    /** 特殊权限 → appops 操作名 */
    private val specialAppOps = mapOf(
        "android.permission.SYSTEM_ALERT_WINDOW" to "SYSTEM_ALERT_WINDOW",
        "android.permission.WRITE_SETTINGS" to "WRITE_SETTINGS",
        "android.permission.REQUEST_INSTALL_PACKAGES" to "REQUEST_INSTALL_PACKAGES",
        "android.permission.PACKAGE_USAGE_STATS" to "GET_USAGE_STATS"
    )

    /**
     * 收回单个应用的危险权限，返回收回数量
     */
    fun revokeDangerousPerms(context: Context, pkg: String): Int {
        if (!Privilege.isReady) return 0
        if (PanicKill.isSystemApp(context, pkg)) return 0
        if (pkg in Prefs.whitelist || pkg in Prefs.permWhitelist) return 0
        if (pkg == context.packageName) return 0

        var count = 0
        val info = getPkgInfo(context, pkg) ?: return 0
        val granted = getGrantedPerms(info)

        // 收回运行时权限
        for (perm in revocablePerms) {
            if (perm in granted) {
                val (code, out) = Privilege.exec("pm revoke $pkg $perm")
                if (code == 0 || out.contains("revoked", true)) {
                    count++
                    Log.i(TAG, "收回 $pkg 的 $perm")
                }
            }
        }

        // 收回特殊权限（appops）
        for ((perm, op) in specialAppOps) {
            if (perm in (info.requestedPermissions?.toList() ?: emptyList())) {
                if (Privilege.exec("appops set $pkg $op deny").first == 0) count++
            }
        }
        return count
    }

    /** 新装应用的自动收回入口 */
    fun autoRevokeForNewApp(context: Context, pkg: String): Int {
        if (!Prefs.autoRevokeEnabled) return 0
        return revokeDangerousPerms(context, pkg)
    }

    /** 批量收回全部已装第三方应用（设置页手动触发） */
    fun revokeAll(context: Context, onProgress: (done: Int, total: Int, pkg: String) -> Unit): Int {
        if (!Privilege.isReady) return 0
        val pm = context.packageManager
        val pkgs = pm.getInstalledApplications(0)
            .filter {
                val sys = it.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0
                !sys && it.packageName != context.packageName &&
                        it.packageName !in Prefs.whitelist &&
                        it.packageName !in Prefs.permWhitelist
            }
        var total = 0
        pkgs.forEachIndexed { i, ai ->
            onProgress(i + 1, pkgs.size, ai.packageName)
            total += revokeDangerousPerms(context, ai.packageName)
        }
        return total
    }

    private fun getPkgInfo(context: Context, pkg: String): PackageInfo? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getPackageInfo(
                    pkg, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS)
            }
        } catch (e: Exception) { null }
    }

    private fun getGrantedPerms(info: PackageInfo): Set<String> {
        val perms = info.requestedPermissions ?: return emptySet()
        val flags = info.requestedPermissionsFlags ?: return emptySet()
        val granted = mutableSetOf<String>()
        for (i in perms.indices) {
            if (i < flags.size && flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0) {
                granted.add(perms[i])
            }
        }
        return granted
    }
}