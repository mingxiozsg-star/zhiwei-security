package com.zhiwei.security.core

import android.content.Context
import android.content.SharedPreferences

/**
 * 授权数据库：记录哪些第三方应用已获准使用知微特权服务，
 * 以及它们的命令白名单（加入白名单的危险命令不再弹窗）
 *
 * 内置特权（对外授权宿主）在此之上追加两类数据：
 *  - 授权档案：授权时间、申请理由、累计调用次数（供「已授权应用」列表展示）
 *  - 审计日志：最近 N 次第三方调用记录（谁、什么命令、被放行还是被拦），
 *    这是「对外授权」能被用户信任的前提——授权后必须可追溯。
 */
object AuthDb {
    private const val NAME = "zhiwei_auth"
    private const val KEY_AUDIT = "audit_log"
    private const val AUDIT_MAX = 120

    private lateinit var sp: SharedPreferences

    fun init(context: Context) {
        if (!::sp.isInitialized) {
            sp = context.getSharedPreferences(NAME, Context.MODE_PRIVATE)
        }
    }

    // ===== 已授权应用（存包名集合） =====
    var grantedApps: Set<String>
        get() = sp.getStringSet("granted_apps", emptySet()) ?: emptySet()
        private set(v) = sp.edit().putStringSet("granted_apps", v).apply()

    fun isGranted(pkg: String): Boolean = pkg in grantedApps

    fun grant(pkg: String) {
        grantedApps = grantedApps + pkg
        stampGrant(pkg)
        audit(pkg, "授予特权", true)
    }

    fun revoke(pkg: String) {
        grantedApps = grantedApps - pkg
        cmdWhitelist = cmdWhitelist.filter { !it.startsWith("$pkg|") }.toSet()
        clearProfile(pkg)
        audit(pkg, "撤销授权", false)
    }

    /** 撤销全部授权（保留审计日志） */
    fun revokeAll() {
        val all = grantedApps
        grantedApps = emptySet()
        cmdWhitelist = emptySet()
        all.forEach { clearProfile(it) }
        audit("-", "撤销全部授权（${all.size} 个应用）", false)
    }

    // ===== 授权档案（时间 / 理由 / 调用计数） =====

    private fun stampGrant(pkg: String) {
        sp.edit().putLong("grant_at_$pkg", System.currentTimeMillis()).apply()
    }

    /** 第三方 requestPermission 时自报的申请理由 */
    fun setRequestReason(pkg: String, reason: String) {
        sp.edit().putString("req_reason_$pkg", reason.take(200)).apply()
    }

    fun requestReason(pkg: String): String = sp.getString("req_reason_$pkg", "") ?: ""

    fun grantTime(pkg: String): Long = sp.getLong("grant_at_$pkg", 0L)

    fun callCount(pkg: String): Int = sp.getInt("calls_$pkg", 0)

    fun bumpCallCount(pkg: String) {
        sp.edit().putInt("calls_$pkg", callCount(pkg) + 1).apply()
    }

    fun lastCallTime(pkg: String): Long = sp.getLong("last_call_$pkg", 0L)

    private fun clearProfile(pkg: String) {
        sp.edit()
            .remove("grant_at_$pkg").remove("req_reason_$pkg")
            .remove("calls_$pkg").remove("last_call_$pkg")
            .apply()
    }

    // ===== 调用审计 =====

    /**
     * 追加一条审计记录。
     * 格式：时间戳|包名|动作|结果(1=放行 0=拦截)
     */
    fun audit(pkg: String, action: String, allowed: Boolean) {
        val line = "${System.currentTimeMillis()}|$pkg|${action.replace('|', '/').take(60)}|${if (allowed) 1 else 0}"
        val list = (sp.getStringSet(KEY_AUDIT, emptySet()) ?: emptySet()).toMutableList()
        list.add(line)
        val trimmed = if (list.size > AUDIT_MAX) {
            list.sortedBy { it.substringBefore('|').toLongOrNull() ?: 0L }.takeLast(AUDIT_MAX)
        } else list
        sp.edit().putStringSet(KEY_AUDIT, HashSet(trimmed)).apply()
        sp.edit().putLong("last_call_$pkg", System.currentTimeMillis()).apply()
    }

    data class AuditEntry(val time: Long, val pkg: String, val action: String, val allowed: Boolean)

    /** 审计日志，按时间倒序（最新在前） */
    fun auditLog(): List<AuditEntry> {
        return (sp.getStringSet(KEY_AUDIT, emptySet()) ?: emptySet())
            .mapNotNull { raw ->
                val p = raw.split('|')
                if (p.size < 4) return@mapNotNull null
                AuditEntry(p[0].toLongOrNull() ?: 0L, p[1], p[2], p[3] == "1")
            }
            .sortedByDescending { it.time }
    }

    fun clearAudit() {
        sp.edit().remove(KEY_AUDIT).apply()
    }

    // ===== 命令白名单（"包名|命令前缀"） =====
    var cmdWhitelist: Set<String>
        get() = sp.getStringSet("cmd_whitelist", emptySet()) ?: emptySet()
        private set(v) = sp.edit().putStringSet("cmd_whitelist", v).apply()

    fun addCmdWhitelist(pkg: String, cmdPrefix: String) {
        cmdWhitelist = cmdWhitelist + "$pkg|$cmdPrefix"
    }

    fun removeCmdWhitelist(entry: String) {
        cmdWhitelist = cmdWhitelist - entry
    }

    /** 该应用的某命令是否已在白名单（前缀匹配，白名单粒度=命令前两个词） */
    fun isCmdWhitelisted(pkg: String, cmd: String): Boolean {
        val normalized = cmd.trim().replace(Regex("\\s+"), " ")
        return cmdWhitelist.any { entry ->
            val sep = entry.indexOf('|')
            if (sep < 0) return@any false
            entry.substring(0, sep) == pkg &&
                normalized.startsWith(entry.substring(sep + 1))
        }
    }

    /** 生成白名单用的命令前缀（取前两个词，如 "pm uninstall"） */
    fun cmdPrefixOf(cmd: String): String {
        val parts = cmd.trim().split(Regex("\\s+"))
        return parts.take(2).joinToString(" ")
    }

    // ===== 命令拦截总开关 =====
    var cmdInterceptEnabled: Boolean
        get() = sp.getBoolean("cmd_intercept", true)
        set(v) = sp.edit().putBoolean("cmd_intercept", v).apply()
}
