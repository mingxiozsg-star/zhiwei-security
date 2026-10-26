package com.zhiwei.security.core

import android.app.ActivityManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

/**
 * 紧急斩杀器
 * 狂按音量键 3 次触发：斩杀所有第三方应用（前台+后台进程）
 *
 * 铁律：
 * 1. 自身包名 + 自身 uid 双重豁免，绝不自毁
 * 2. 提权桥梁（Shizuku/Dhizuku 本体）豁免——杀了桥等于缴自己的枪
 * 3. 批量单会话执行，杀完验尸补刀
 * 4. 仅当用户被困在第三方界面时才回桌面；在知微或桌面里绝不动
 */
object PanicKill {

    /** 提权桥梁包名：斩杀时必须豁免，否则杀到一半通道断了 */
    private val BRIDGE_PKGS = setOf(
        "moe.shizuku.privileged.api",   // Shizuku
        "com.rosan.dhizuku",            // Dhizuku
        "com.rosan.dhizuku.aidl",
        "com.web1n.permissiondog",      // 权限狗（同类桥）
        "rikka.shizuku"
    )

    /**
     * 斩杀所有第三方应用
     * 返回值：正数=提权强杀数量；负数=仅后台清理数量
     */
    fun killAllThirdParty(context: Context): Int {
        Prefs.init(context)
        val self = context.packageName
        val selfUid = android.os.Process.myUid()
        val pm = context.packageManager

        val targets = getThirdPartyPackages(context).filter { pkg ->
            if (pkg == self) return@filter false                    // 自身豁免①
            if (pkg in Prefs.whitelist) return@filter false
            if (pkg in BRIDGE_PKGS) return@filter false             // 桥梁豁免
            try {                                                   // 自身 uid 豁免②（防双开/共享uid）
                val ai = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                    pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
                else @Suppress("DEPRECATION") pm.getApplicationInfo(pkg, 0)
                ai.uid != selfUid
            } catch (e: Exception) { true }
        }

        var killed: Int
        var privileged = false

        if (Privilege.isReady && targets.isNotEmpty()) {
            privileged = true
            // 单次会话批量强杀：一条 shell 脚本跑完，避免逐包往返慢且中途断桥
            val sb = StringBuilder()
            for (p in targets) {
                sb.append("am force-stop ").append(p).append(" 2>/dev/null;")
            }
            // 等 1 秒验尸：国产 ROM 有拉活机制，残留的用 am kill + kill -9 补刀
            sb.append("sleep 1;")
            for (p in targets) {
                sb.append("pidof ").append(p)
                    .append(" >/dev/null 2>&1 && { am kill ").append(p)
                    .append(" 2>/dev/null; kill -9 ${'$'}(pidof ").append(p)
                    .append(") 2>/dev/null; };")
            }
            sb.append("echo BATCH_DONE")
            Privilege.exec(sb.toString())

            // 逐个验尸统计真实斩杀数
            var alive = 0
            for (p in targets) {
                val r = Privilege.exec("pidof $p")
                if (r.first == 0 && r.second.isNotBlank()) alive++
            }
            killed = targets.size - alive
        } else {
            // 无提权：只能清后台缓存进程（系统限制）
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            var n = 0
            for (pkg in targets) {
                try { am.killBackgroundProcesses(pkg); n++ } catch (e: Exception) { }
            }
            killed = n
        }

        // 仅当用户被困在第三方界面（锁机/霸屏）时才拉回桌面；在知微或桌面里不动
        goHomeIfTrapped(context, self)

        return if (privileged) killed else -killed
    }

    /** 斩杀单个应用（前台音量异常/霸屏场景） */
    fun killOne(context: Context, pkg: String): Boolean {
        if (pkg == context.packageName) return false
        if (pkg in Prefs.whitelist) return false
        if (pkg in BRIDGE_PKGS) return false
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

    /** 被困才回桌面：前台是第三方应用才跳 HOME，否则原地不动 */
    private fun goHomeIfTrapped(context: Context, self: String) {
        try {
            val fg = foregroundPackage(context)
            // 前台是自己/桌面/系统界面 → 用户没被锁机困住，不动
            if (fg == null || fg == self || fg in BRIDGE_PKGS) return
            if (fg.contains("launcher") || fg == "android" || fg == "com.android.systemui") return
            if (isSystemApp(context, fg)) return
            context.startActivity(Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_HOME)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            })
        } catch (e: Exception) { }
    }

    /** 读最近任务事件判断当前前台包（无权限时返回 null，宁可不动） */
    private fun foregroundPackage(context: Context): String? {
        return try {
            val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
            val end = System.currentTimeMillis()
            val events = usm.queryEvents(end - 10_000L, end)
            val ev = UsageEvents.Event()
            var fg: String? = null
            while (events.hasNextEvent()) {
                events.getNextEvent(ev)
                if (ev.eventType == UsageEvents.Event.ACTIVITY_RESUMED) fg = ev.packageName
            }
            fg
        } catch (e: Exception) { null }
    }
}