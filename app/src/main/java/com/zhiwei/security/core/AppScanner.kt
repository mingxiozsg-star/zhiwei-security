package com.zhiwei.security.core

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest

class AppScanner(private val context: Context) {

    private val pm: PackageManager = context.packageManager

    data class ScanProgress(
        val current: Int,
        val total: Int,
        val currentApp: String,
        val threats: List<VirusDb.ScanResult>
    )

    suspend fun scanAllApps(
        onProgress: (ScanProgress) -> Unit
    ): List<VirusDb.ScanResult> = withContext(Dispatchers.IO) {
        val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

        val threats = mutableListOf<VirusDb.ScanResult>()
        val total = packages.size

        packages.forEachIndexed { index, pkg ->
            val appName = try {
                pkg.applicationInfo?.loadLabel(pm)?.toString() ?: pkg.packageName
            } catch (e: Exception) {
                pkg.packageName
            }

            onProgress(ScanProgress(index + 1, total, appName, threats.toList()))

            // 跳过白名单
            if (pkg.packageName in Prefs.whitelist || pkg.packageName in VirusDb.systemWhitelist) {
                return@forEachIndexed
            }

            val result = analyzePackage(pkg)
            if (result.level != VirusDb.ThreatLevel.SAFE && result.level != VirusDb.ThreatLevel.LOW) {
                threats.add(result)
            }
        }

        Prefs.lastScanTime = System.currentTimeMillis()
        Prefs.lastScanThreatCount = threats.size
        Prefs.lastScanAppCount = total

        threats.sortedByDescending { it.score }
    }

    private fun analyzePackage(pkg: PackageInfo): VirusDb.ScanResult {
        val reasons = mutableListOf<String>()
        var score = 0

        val appName = try {
            pkg.applicationInfo?.loadLabel(pm)?.toString() ?: pkg.packageName
        } catch (e: Exception) {
            pkg.packageName
        }

        val isSystem = (pkg.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM != 0
        val permissions = pkg.requestedPermissions?.toList() ?: emptyList()

        // 1. 黑名单包名直接判病毒
        if (pkg.packageName in VirusDb.maliciousPackages) {
            score = 100
            reasons.add("已知恶意应用包名")
            return VirusDb.ScanResult(
                pkg.packageName, appName, VirusDb.ThreatLevel.VIRUS,
                score, reasons, permissions, isSystem,
                pkg.versionName, pkg.applicationInfo?.sourceDir
            )
        }

        // 2. 权限风险评分
        var permScore = 0
        val grantedDangerous = mutableListOf<String>()
        permissions.forEach { perm ->
            VirusDb.dangerousPermissions[perm]?.let { risk ->
                permScore += risk
                grantedDangerous.add(perm)
            }
        }

        // 3. 高危权限组合检测
        VirusDb.dangerousCombos.forEach { combo ->
            if (grantedDangerous.containsAll(combo)) {
                val comboScore = combo.sumOf { VirusDb.dangerousPermissions[it] ?: 0 } + 20
                permScore += comboScore
                reasons.add("高危权限组合: ${combo.joinToString("+") { it.substringAfterLast(".") }}")
            }
        }

        score = permScore.coerceAtMost(100)

        // 4. 单项高危权限原因
        if (grantedDangerous.contains("android.permission.BIND_DEVICE_ADMIN")) {
            reasons.add("请求设备管理器权限")
        }
        if (grantedDangerous.contains("android.permission.SYSTEM_ALERT_WINDOW")) {
            reasons.add("请求悬浮窗权限")
        }
        if (grantedDangerous.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")) {
            reasons.add("请求无障碍服务权限")
        }
        if (grantedDangerous.contains("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE")) {
            reasons.add("请求通知监听权限")
        }
        if (grantedDangerous.contains("android.permission.FACTORY_RESET") ||
            grantedDangerous.contains("android.permission.MASTER_CLEAR")) {
            reasons.add("请求恢复出厂设置权限")
        }

        // 5. 签名验证（可选）
        try {
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkg.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                pkg.signatures
            }
            signatures?.forEach { sig ->
                val md5 = md5Hex(sig.toByteArray())
                if (md5 in VirusDb.maliciousSignatures) {
                    score = 100
                    reasons.add("恶意签名特征")
                }
            }
        } catch (e: Exception) { /* ignore */ }

        // 6. 非系统应用且请求大量高危权限
        if (!isSystem && grantedDangerous.size >= 5) {
            score = (score + 15).coerceAtMost(100)
            reasons.add("请求大量高危权限(${grantedDangerous.size}项)")
        }

        val level = when {
            score >= 80 -> VirusDb.ThreatLevel.VIRUS
            score >= 60 -> VirusDb.ThreatLevel.HIGH
            score >= 35 -> VirusDb.ThreatLevel.MEDIUM
            score >= 15 -> VirusDb.ThreatLevel.LOW
            else -> VirusDb.ThreatLevel.SAFE
        }

        return VirusDb.ScanResult(
            pkg.packageName, appName, level, score,
            reasons, grantedDangerous, isSystem,
            pkg.versionName, pkg.applicationInfo?.sourceDir
        )
    }

    private fun md5Hex(data: ByteArray): String {
        val md = MessageDigest.getInstance("MD5")
        val digest = md.digest(data)
        return digest.joinToString("") { "%02x".format(it) }
    }
}