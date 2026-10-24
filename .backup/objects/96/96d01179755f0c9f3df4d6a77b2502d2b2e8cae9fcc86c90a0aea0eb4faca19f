package com.zhiwei.security.core

import android.content.Context
import android.content.SharedPreferences

object Prefs {

    private const val NAME = "zhiwei_security"
    private lateinit var sp: SharedPreferences

    fun init(context: Context) {
        sp = context.getSharedPreferences(NAME, Context.MODE_PRIVATE)
    }

    // 防护开关
    var protectOn: Boolean
        get() = sp.getBoolean("protect_on", false)
        set(v) = sp.edit().putBoolean("protect_on", v).apply()

    // 黑名单
    var blacklist: Set<String>
        get() = sp.getStringSet("blacklist", emptySet()) ?: emptySet()
        set(v) = sp.edit().putStringSet("blacklist", v).apply()

    // 白名单
    var whitelist: Set<String>
        get() = sp.getStringSet("whitelist", emptySet()) ?: emptySet()
        set(v) = sp.edit().putStringSet("whitelist", v).apply()

    // 上次扫描时间
    var lastScanTime: Long
        get() = sp.getLong("last_scan_time", 0)
        set(v) = sp.edit().putLong("last_scan_time", v).apply()

    // 上次扫描结果数
    var lastScanThreatCount: Int
        get() = sp.getInt("last_scan_threats", 0)
        set(v) = sp.edit().putInt("last_scan_threats", v).apply()

    // 上次扫描应用总数
    var lastScanAppCount: Int
        get() = sp.getInt("last_scan_apps", 0)
        set(v) = sp.edit().putInt("last_scan_apps", v).apply()

    // Shizuku 授权状态
    var shizukuGranted: Boolean
        get() = sp.getBoolean("shizuku_granted", false)
        set(v) = sp.edit().putBoolean("shizuku_granted", v).apply()

    fun addToBlacklist(pkg: String) { blacklist = blacklist + pkg }
    fun removeFromBlacklist(pkg: String) { blacklist = blacklist - pkg }
    fun addToWhitelist(pkg: String) { whitelist = whitelist + pkg }
    fun removeFromWhitelist(pkg: String) { whitelist = whitelist - pkg }
}