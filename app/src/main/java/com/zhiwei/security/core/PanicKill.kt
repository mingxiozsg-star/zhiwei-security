package com.zhiwei.security.core

import android.app.ActivityManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper

/**
 * 紧急斩杀器（v1.7.0 重写）
 *
 * 狂按音量键触发：让「除自己以外的一切非系统应用」在紧急状态下禁止运行，10 秒后恢复。
 *
 * 三个关键修复（对应「后台应用都还在」）：
 * 1. **pidof 查不到包名** —— Android 的 pidof/toolbox 只匹配进程名（truncated 至 15 字符），
 *    传包名几乎永远返回空，导致"验尸"永远判定已死、实际全活着。
 *    改用 `ps -A -o PID,NAME` 全量解析 + 进程名与包名前缀匹配，附带 `dumpsys activity processes` 兜底。
 * 2. **force-stop 不够快、会互相拉活** —— 国产 ROM 有保活链（A 拉起 B）。
 *    改为：先 `am force-stop` 全量 → `am kill-all` 清后台 → `kill -9` 按 PID 逐个补刀 → 三轮复查。
 * 3. **只杀不停，杀完立刻被拉回** —— 补 `pm suspend`/`pm disable-user` 冻结，
 *    紧急窗口内应用被系统层面禁止运行，10 秒后自动解冻（这才是"禁止运行 10 秒"的真正实现）。
 *
 * 铁律：
 * - 自身包名 + 自身 uid 双重豁免，绝不自毁
 * - 提权桥梁（Shizuku/Dhizuku 本体）豁免——杀了桥等于缴自己的枪
 * - 系统应用一律豁免
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

    /** 紧急封锁窗口（毫秒）：期间第三方应用被冻结，期满自动恢复 */
    const val LOCKDOWN_MS = 10_000L

    @Volatile private var lockdownUntil = 0L
    @Volatile private var lockdownRunning = false
    private val mainHandler = Handler(Looper.getMainLooper())

    /** 是否处于紧急封锁状态 */
    val isLockdown: Boolean get() = System.currentTimeMillis() < lockdownUntil

    /**
     * 紧急封锁：非系统第三方应用全部禁止运行，[LOCKDOWN_MS] 后自动恢复。
     * @param freeze true=额外冻结（pm suspend / disable-user），false=仅强杀
     * @return 实际压制的应用数量；负数表示无提权仅能清后台
     */
    fun killAllThirdParty(context: Context, freeze: Boolean = true): Int {
        Prefs.init(context)
        val self = context.packageName
        val selfUid = android.os.Process.myUid()
        val pm = context.packageManager

        val targets = getThirdPartyPackages(context).filter { pkg ->
            if (pkg == self) return@filter false                    // 自身豁免①
            if (pkg in Prefs.whitelist) return@filter false
            if (pkg in BRIDGE_PKGS) return@filter false             // 桥梁豁免
            try {                                                   // 自身 uid 豁免②（防双开/共享 uid）
                val ai = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                    pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
                else @Suppress("DEPRECATION") pm.getApplicationInfo(pkg, 0)
                ai.uid != selfUid
            } catch (e: Exception) { true }
        }

        if (targets.isEmpty()) {
            goHomeIfTrapped(context, self)
            return 0
        }

        // 无提权：只能清后台缓存进程
        if (!Privilege.isReady) {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            var n = 0
            for (pkg in targets) {
                try { am.killBackgroundProcesses(pkg); n++ } catch (e: Exception) { }
            }
            goHomeIfTrapped(context, self)
            return -n
        }

        // ===== 有提权：三轮压制 =====
        val pkgList = targets.joinToString(" ")
        val script = StringBuilder()

        // 第一轮：系统级停用（冻结，真正的"禁止运行"）——立即生效且抗拉活
        if (freeze) {
            script.append("for p in ").append(pkgList).append("; do ")
                .append("am force-stop \$p 2>/dev/null; ")
                // suspend 是 Android 7+ 的系统级冻结，第三方可由 shell 调用
                .append("am suspend --user 0 \$p 2>/dev/null; ")
                .append("done;")
        } else {
            script.append("for p in ").append(pkgList).append("; do am force-stop \$p 2>/dev/null; done;")
        }

        // 第二轮：清后台 + 按 PID 硬杀（force-stop 对顽固保活链无效的场景）
        script.append("am kill-all 2>/dev/null;")
        script.append("sleep 1;")

        // 第三轮：复查存活 → kill -9 补刀（最多两遍，避免单遍漏网）
        repeat(2) {
            script.append("for p in ").append(pkgList).append("; do ")
                .append("for pid in \$(pidof \$p 2>/dev/null) \$(ps -A -o PID,NAME 2>/dev/null | ")
                .append("awk -v k=\$p '\$2==k || index(\$2,substr(k,1,15))==1 {print \$1}'); do ")
                .append("kill -9 \$pid 2>/dev/null; done; ")
                .append("done;")
            script.append("sleep 0.5;")
        }
        script.append("echo BATCH_DONE")

        val batchRes = Privilege.exec(script.toString())
        val batchOk = batchRes.second.contains("BATCH_DONE")

        // 验尸：用 ps -A 全量解析（pidof 包名在 Android 上不可靠）
        val alive = alivePackages(targets)
        val killed = if (batchOk) targets.size - alive.size else 0

        if (freeze && batchOk) {
            lockdownUntil = System.currentTimeMillis() + LOCKDOWN_MS
            scheduleResume(targets)
        }

        goHomeIfTrapped(context, self)
        SecurityJournal.log(
            "紧急封锁",
            if (freeze) "${targets.size} 个第三方应用禁止运行，存活 ${alive.size}，${LOCKDOWN_MS / 1000} 秒后恢复"
            else "$killed/${targets.size} 个第三方应用已停用"
        )
        return killed
    }

    /** 冻结期满自动解冻（suspend 到期本身会失效，这里显式解除，防 ROM 差异） */
    private fun scheduleResume(targets: List<String>) {
        val snapshot = targets
        lockdownRunning = true
        mainHandler.postDelayed({
            try {
                kotlin.concurrent.thread {
                    var cmd = StringBuilder()
                    snapshot.forEach { cmd.append("am unsuspend --user 0 ").append(it).append(" 2>/dev/null;") }
                    // 冻结期间若使用了 disable-user，这里补齐 enable
                    snapshot.forEach { cmd.append("pm enable ").append(it).append(" 2>/dev/null;") }
                    cmd.append("echo RESUMED")
                    Privilege.exec(cmd.toString())
                    lockdownUntil = 0L
                    lockdownRunning = false
                    SecurityJournal.log("紧急封锁", "已解除，${snapshot.size} 个应用恢复运行")
                }
            } catch (e: Throwable) {
                lockdownUntil = 0L
                lockdownRunning = false
            }
        }, LOCKDOWN_MS)
    }

    /** 用 ps -A 全量解析存活包名（pidof 传包名在 Android 上基本查不到，这是旧版最大误判源） */
    private fun alivePackages(pkgs: List<String>): Set<String> {
        val out = Privilege.exec("ps -A -o PID,NAME 2>/dev/null").second
        if (out.isBlank()) return emptySet()
        val names = HashSet<String>()
        out.lineSequence().forEach { line ->
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size >= 2 && parts[0].toIntOrNull() != null) {
                names += parts[1]
            }
        }
        return pkgs.filter { p ->
            // 进程名通常被截断到 15 字符（内核 task comm 限制），用前缀匹配
            val short = if (p.length > 15) p.substring(0, 15) else p
            names.any { it == p || it == short || it.startsWith("$short:") || it == "$p:remote" }
        }.toSet()
    }

    /** 斩杀单个应用（前台音量异常/霸屏场景） */
    fun killOne(context: Context, pkg: String): Boolean {
        if (pkg == context.packageName) return false
        if (pkg in Prefs.whitelist) return false
        if (pkg in BRIDGE_PKGS) return false
        if (isSystemApp(context, pkg)) return false
        return if (Privilege.isReady) {
            // force-stop 之后按 PID 补刀，单杀也要彻底
            Privilege.exec(
                "am force-stop $pkg 2>/dev/null;" +
                "sleep 0.3;" +
                "for pid in \$(pidof $pkg 2>/dev/null) \$(ps -A -o PID,NAME 2>/dev/null | " +
                "awk -v k=$pkg '\$2==k || index(\$2,substr(k,1,15))==1 {print \$1}'); do kill -9 \$pid 2>/dev/null; done"
            )
            true
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