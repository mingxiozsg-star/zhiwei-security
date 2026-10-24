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

    // 首次启动引导完成标记
    var onboardingDone: Boolean
        get() = sp.getBoolean("onboarding_done", false)
        set(v) = sp.edit().putBoolean("onboarding_done", v).apply()

    // ===== 功能开关 =====
    /** 前台黑名单拦截 */
    var interceptEnabled: Boolean
        get() = sp.getBoolean("sw_intercept", true)
        set(v) = sp.edit().putBoolean("sw_intercept", v).apply()

    /** 音量键管控（三连击斩杀 + 软拉满检测） */
    var volumeGuardEnabled: Boolean
        get() = sp.getBoolean("sw_volume_guard", true)
        set(v) = sp.edit().putBoolean("sw_volume_guard", v).apply()

    /** 无障碍霸占管控 */
    var a11yGuardEnabled: Boolean
        get() = sp.getBoolean("sw_a11y_guard", true)
        set(v) = sp.edit().putBoolean("sw_a11y_guard", v).apply()

    /** 安装后自动扫描 */
    var installScanEnabled: Boolean
        get() = sp.getBoolean("sw_install_scan", true)
        set(v) = sp.edit().putBoolean("sw_install_scan", v).apply()

    /** 后台网络拦截（VPN 黑洞） */
    var netGuardEnabled: Boolean
        get() = sp.getBoolean("sw_net_guard", false)
        set(v) = sp.edit().putBoolean("sw_net_guard", v).apply()

    /** 隐藏后台卡片 */
    var hideRecentsEnabled: Boolean
        get() = sp.getBoolean("sw_hide_recents", false)
        set(v) = sp.edit().putBoolean("sw_hide_recents", v).apply()

    /** 被网络拦截的应用 */
    var netBlocked: Set<String>
        get() = sp.getStringSet("net_blocked", emptySet()) ?: emptySet()
        set(v) = sp.edit().putStringSet("net_blocked", v).apply()

    fun addToNetBlocked(pkg: String) { netBlocked = netBlocked + pkg }
    fun removeFromNetBlocked(pkg: String) { netBlocked = netBlocked - pkg }

    fun addToBlacklist(pkg: String) { blacklist = blacklist + pkg }
    fun removeFromBlacklist(pkg: String) { blacklist = blacklist - pkg }
    fun addToWhitelist(pkg: String) { whitelist = whitelist + pkg }
    fun removeFromWhitelist(pkg: String) { whitelist = whitelist - pkg }
}