package com.zhiwei.security.core

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest

/**
 * 应用扫描引擎
 * 规则：
 * - 系统应用（FLAG_SYSTEM）默认安全，只核对恶意包名和恶意签名
 * - 第三方应用按权限评分，单项权限不构成威胁，组合才算
 * - 用户白名单直接跳过
 */
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

            // 用户白名单跳过
            if (pkg.packageName in Prefs.whitelist) return@forEachIndexed

            val result = ScanEngineHub.merge(
                analyzePackage(pkg),
                ScanEngineHub.scanWithExternalEngines(context, pkg)
            ) ?: return@forEachIndexed
            // 可疑样本触发云端哈希复核（后台异步，干净/已判病毒不触发）
            CloudHashVerifier.maybeRecheck(context, result)
            // 确认病毒 → 自动斩杀（冻结→回收无障碍/管理员→卸载+警报），开关默认开
            if (result.level == VirusDb.ThreatLevel.VIRUS && Prefs.autoKillOnVirus &&
                result.packageName !in Prefs.whitelist) {
                val pkgName = result.packageName
                val appLabel = result.appName
                kotlin.concurrent.thread(isDaemon = true) {
                    try {
                        if (Privilege.isReady) {
                            Privilege.forceStop(pkgName)
                            Privilege.revokeAccessibility(context, pkgName)
                            val ok = Privilege.uninstall(pkgName)
                            NotifHelper.alert(context, "☠️ 扫描命中病毒，已斩杀",
                                "$appLabel 判定为病毒，已自动处置（卸载${if (ok) "成功" else "失败"}）")
                            SecurityJournal.log("斩杀", "扫描联动斩杀 $pkgName 卸载${if (ok) "成功" else "失败"}")
                        } else {
                            Privilege.exec("am force-stop $pkgName")
                            NotifHelper.alert(context, "⚠️ 扫描命中病毒",
                                "$appLabel 判定为病毒；无提权通道，仅做后台清理，请连接本机 ADB/Root 后重扫以彻底卸载")
                            SecurityJournal.log("斩杀", "扫描命中 $pkgName 但无提权，未卸载")
                        }
                    } catch (e: Throwable) { }
                }
            }
            // 只有中风险及以上才进威胁列表
            if (result.level == VirusDb.ThreatLevel.MEDIUM ||
                result.level == VirusDb.ThreatLevel.HIGH ||
                result.level == VirusDb.ThreatLevel.VIRUS) {
                threats.add(result)
            }
        }

        Prefs.lastScanTime = System.currentTimeMillis()
        Prefs.lastScanThreatCount = threats.size
        Prefs.lastScanAppCount = total

        threats.sortedByDescending { it.score }
    }

    /** 分析单个应用；返回 null 表示完全安全不值得报告 */
    fun analyzePackage(pkg: PackageInfo): VirusDb.ScanResult? {
        val appName = try {
            pkg.applicationInfo?.loadLabel(pm)?.toString() ?: pkg.packageName
        } catch (e: Exception) {
            pkg.packageName
        }

        val flags = pkg.applicationInfo?.flags ?: 0
        val isSystem = flags and ApplicationInfo.FLAG_SYSTEM != 0 ||
                flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
        val permissions = pkg.requestedPermissions?.toList() ?: emptyList()
        val reasons = mutableListOf<String>()

        // 1. 恶意包名名单：无论系统与否都判病毒
        if (pkg.packageName in VirusDb.maliciousPackages) {
            return VirusDb.ScanResult(
                pkg.packageName, appName, VirusDb.ThreatLevel.VIRUS,
                100, listOf("命中恶意应用名单"), permissions, isSystem,
                pkg.versionName, pkg.applicationInfo?.sourceDir
            )
        }

        // 1.2 恶意包名前缀（锁机载体随机后缀变体）
        val hitPrefix = VirusDb.maliciousPackagePrefixes.firstOrNull { pkg.packageName.startsWith(it) }
        if (hitPrefix != null) {
            return VirusDb.ScanResult(
                pkg.packageName, appName, VirusDb.ThreatLevel.VIRUS,
                95, listOf("包名命中恶意前缀「$hitPrefix」（锁机载体变体）"), permissions, false,
                pkg.versionName, pkg.applicationInfo?.sourceDir
            )
        }

        // 1.3 恶意落地文件名（锁机主体释放在系统目录的 APK 名）
        val srcFile = pkg.applicationInfo?.sourceDir?.substringAfterLast('/') ?: ""
        if (srcFile in VirusDb.maliciousFileNames) {
            return VirusDb.ScanResult(
                pkg.packageName, appName, VirusDb.ThreatLevel.VIRUS,
                100, listOf("APK 文件名命中恶意名单「$srcFile」（锁机主体典型落地名）"), permissions, isSystem,
                pkg.versionName, pkg.applicationInfo?.sourceDir
            )
        }

        // 2. 恶意签名
        if (checkMaliciousSignature(pkg)) {
            return VirusDb.ScanResult(
                pkg.packageName, appName, VirusDb.ThreatLevel.VIRUS,
                100, listOf("命中恶意签名特征"), permissions, isSystem,
                pkg.versionName, pkg.applicationInfo?.sourceDir
            )
        }

        // 2.5 恶意应用名关键词（刷钻/锁机/外挂类名称，正常应用不会用）
        if (!isSystem) {
            val hitKw = VirusDb.maliciousNameKeywords.firstOrNull { appName.contains(it) }
            if (hitKw != null) {
                return VirusDb.ScanResult(
                    pkg.packageName, appName, VirusDb.ThreatLevel.VIRUS,
                    95, listOf("应用名命中恶意关键词「$hitKw」（锁机病毒典型传播名称）"),
                    permissions, false, pkg.versionName, pkg.applicationInfo?.sourceDir
                )
            }
        }

        // 3. 系统应用到此为止——不再按权限评分，避免误报
        if (isSystem) return null

        // 3.2 风险应用名单（广告/猎手木马家族，判 HIGH 不判 VIRUS）
        if (pkg.packageName in VirusDb.suspiciousPackages) {
            return VirusDb.ScanResult(
                pkg.packageName, appName, VirusDb.ThreatLevel.HIGH,
                60, listOf("命中风险应用名单（广告木马/猎手家族，捆绑恶意 SDK）"),
                permissions, false, pkg.versionName, pkg.applicationInfo?.sourceDir
            )
        }

        // 3.5 权限白名单：不参与权限评分
        if (pkg.packageName in Prefs.permWhitelist) return null

        // 4. 第三方应用：权限评分
        val grantedDangerous = permissions.filter { it in VirusDb.dangerousPermissions }
        var score = grantedDangerous.sumOf { VirusDb.dangerousPermissions[it] ?: 0 }

        // 5. 高危组合加成
        VirusDb.dangerousCombos.forEach { combo ->
            if (grantedDangerous.containsAll(combo.perms)) {
                score += combo.bonus
                reasons.add(combo.label)
            }
        }

        // 6. 单项显著风险说明
        if ("android.permission.BIND_DEVICE_ADMIN" in grantedDangerous) {
            reasons.add("请求设备管理器权限（可锁屏/改密码）")
        }
        if ("android.permission.BIND_ACCESSIBILITY_SERVICE" in grantedDangerous) {
            reasons.add("包含无障碍服务（可模拟操作）")
        }
        if ("android.permission.DISABLE_KEYGUARD" in grantedDangerous) {
            reasons.add("请求禁用锁屏权限")
        }
        if (grantedDangerous.size >= 8) {
            score += 10
            reasons.add("请求高危权限过多（${grantedDangerous.size} 项）")
        }

        score = score.coerceAtMost(100)

        val level = when {
            score >= 70 -> VirusDb.ThreatLevel.VIRUS
            score >= 50 -> VirusDb.ThreatLevel.HIGH
            score >= 30 -> VirusDb.ThreatLevel.MEDIUM
            score >= 15 -> VirusDb.ThreatLevel.LOW
            else -> VirusDb.ThreatLevel.SAFE
        }

        if (reasons.isEmpty() && level != VirusDb.ThreatLevel.SAFE) {
            reasons.add("综合权限风险评分 $score")
        }

        return VirusDb.ScanResult(
            pkg.packageName, appName, level, score,
            reasons, grantedDangerous, false,
            pkg.versionName, pkg.applicationInfo?.sourceDir
        )
    }

    /** 分析单个包名（ProtectService 检测新装应用用） */
    fun analyzePackageName(pkgName: String): VirusDb.ScanResult? {
        return try {
            val pkg = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(pkgName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkgName, PackageManager.GET_PERMISSIONS)
            }
            val local = analyzePackage(pkg)
            val external = ScanEngineHub.scanWithExternalEngines(context, pkg)
            val merged = ScanEngineHub.merge(local, external)
            merged?.let { CloudHashVerifier.maybeRecheck(context, it) }
            merged
        } catch (e: Exception) { null }
    }

    private fun checkMaliciousSignature(pkg: PackageInfo): Boolean {
        if (VirusDb.maliciousSignatures.isEmpty()) return false
        return try {
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkg.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                pkg.signatures
            }
            signatures?.any { md5Hex(it.toByteArray()) in VirusDb.maliciousSignatures } == true
        } catch (e: Exception) { false }
    }

    private fun md5Hex(data: ByteArray): String {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(data).joinToString("") { "%02x".format(it) }
    }
}