package com.zhiwei.security.core

import android.content.Context
import android.content.SharedPreferences

/**
 * 授权数据库：记录哪些第三方应用已获准使用知微特权服务，
 * 以及它们的命令白名单（加入白名单的危险命令不再弹窗）
 */
object AuthDb {

    private const val NAME = "zhiwei_auth"
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
    fun grant(pkg: String) { grantedApps = grantedApps + pkg }
    fun revoke(pkg: String) {
        grantedApps = grantedApps - pkg
        // 撤销授权时清掉它的命令白名单
        cmdWhitelist = cmdWhitelist.filter { !it.startsWith("$pkg|") }.toSet()
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