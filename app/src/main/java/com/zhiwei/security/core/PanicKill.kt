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

    /** 斩杀所有非系统应用，返回斩杀数量（自身双重豁免，绝不自毁） */
    fun killAllThirdParty(context: Context): Int {
        Prefs.init(context)
        val self = context.packageName
        val thirdParty = getThirdPartyPackages(context).filter {
            it != self && it !in Prefs.whitelist
        }

        var killed = 0
        var privileged = false

        // 1. 优先走提权逐包强杀（force-stop 会杀光该包全部进程，含前台）
        if (Privilege.isReady) {
            privileged = true
            for (pkg in thirdParty) {
                if (pkg == self) continue // 双保险
                val (code, _) = Privilege.exec("am force-stop $pkg")
                if (code == 0) killed++
            }
        }

        // 2. 降级/补充：killBackgroundProcesses（无提权时只能清后台缓存进程）
        if (!privileged) {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            thirdParty.forEach { pkg ->
                if (pkg == self) return@forEach // 双保险
                try {
                    am.killBackgroundProcesses(pkg)
                    killed++
                } catch (e: Exception) { }
            }
        }

        // 3. 回到桌面，把用户从可能的恶意界面里捞出来
        try {
            context.startActivity(Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_HOME)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            })
        } catch (e: Exception) { }

        return if (privileged) killed else -killed // 负数表示仅后台清理
    }

    /** 斩杀单个应用（前台音量异常等场景） */
    fun killOne(context: Context, pkg: String): Boolean {
        if (pkg == context.packageName) return false
        if (pkg in Prefs.whitelist) return false
        if (isSystemApp(context, pkg)) return false
        return if (Privilege.isReady) {
            Privilege.forceStop(pkg)
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