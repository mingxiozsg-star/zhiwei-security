package com.zhiwei.security.core

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build

object RiskAnalyzer {

    data class PermissionInfo(
        val permission: String,
        val label: String,
        val risk: Int,
        val granted: Boolean
    )

    fun analyzeAppPermissions(context: Context, packageName: String): List<PermissionInfo> {
        val pm = context.packageManager
        return try {
            val pkg = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            }

            pkg.requestedPermissions?.map { perm ->
                val risk = VirusDb.dangerousPermissions[perm] ?: 0
                val granted = try {
                    pm.checkPermission(perm, packageName) == PackageManager.PERMISSION_GRANTED
                } catch (e: Exception) { false }

                PermissionInfo(
                    permission = perm,
                    label = perm.substringAfterLast("."),
                    risk = risk,
                    granted = granted
                )
            }?.sortedByDescending { it.risk } ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun getRiskDescription(permissions: List<PermissionInfo>): String {
        val highRisk = permissions.filter { it.risk >= 20 }
        return when {
            highRisk.isEmpty() -> "该应用权限风险较低"
            highRisk.size == 1 -> "该应用请求了 1 项高危权限"
            else -> "该应用请求了 ${highRisk.size} 项高危权限"
        }
    }
}