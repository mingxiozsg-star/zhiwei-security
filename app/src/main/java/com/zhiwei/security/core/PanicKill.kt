package com.zhiwei.security.core

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

/**
 * 紧急斩杀器
 * 音量上键三连击触发：斩杀所有第三方应用（前台+后台进程）
 * 系统应用一律豁免
 */
object PanicKill {

    /** 斩杀所有非系统应用，返回斩杀数量 */
    fun killAllThirdParty(context: Context): Int {
        Prefs.init(context)
        val pm = context.packageManager
        val thirdParty = getThirdPartyPackages(context).filter {
            it != context.packageName && it !in Prefs.whitelist
        }

        var killed = 0

        // 1. 优先走 Shizuku 批量强杀（一条命令搞定，最快）
        if (ShizukuManager.isReady) {
            val cmd = thirdParty.joinToString(";") { "am force-stop $it" }
            val (code, _) = ShizukuManager.exec(cmd)
            if (code == 0) killed = thirdParty.size
        }

        // 2. Shizuku 不可用时的降级方案：killBackgroundProcesses（只能杀后台）
        if (killed == 0) {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            thirdParty.forEach { pkg ->
                try {
                    am.killBackgroundProcesses(pkg)
                    killed++
                } catch (e: Exception) { }
            }
        }

        // 3. 回到桌面，把用户从可能的恶意界面里捞出来
        context.startActivity(Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_HOME)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        })

        return killed
    }

    /** 斩杀单个应用（前台音量异常等场景） */
    fun killOne(context: Context, pkg: String): Boolean {
        if (pkg == context.packageName) return false
        if (pkg in Prefs.whitelist) return false
        if (isSystemApp(context, pkg)) return false
        return if (ShizukuManager.isReady) {
            ShizukuManager.forceStop(pkg)
        } else {
            try {
                val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
                am.killBackgroundProcesses(pkg)
                true
            } catch (e: Exception) { false }
        }
    }

    fun getThirdPartyPackages(context: Context): List<String> {
        val pm = context.packageManager
        val apps = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(0)
        }
        return apps.filter {
            it.flags and ApplicationInfo.FLAG_SYSTEM == 0 &&
            it.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP == 0
        }.map { it.packageName }
    }

    fun isSystemApp(context: Context, pkg: String): Boolean {
        return try {
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getApplicationInfo(pkg, 0)
            }
            info.flags and ApplicationInfo.FLAG_SYSTEM != 0
        } catch (e: Exception) { true } // 拿不准的按系统应用处理，宁放过不错杀
    }
}