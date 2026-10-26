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

    // ADB 自提权连接信息
    var adbHost: String
        get() = sp.getString("adb_host", "") ?: ""
        set(v) = sp.edit().putString("adb_host", v).apply()
    var adbPort: Int
        get() = sp.getInt("adb_port", 0)
        set(v) = sp.edit().putInt("adb_port", v).apply()

    /** 越权行为检测（冻结系统应用/删除系统应用等） */
    var abuseDetectEnabled: Boolean
        get() = sp.getBoolean("sw_abuse_detect", true)
        set(v) = sp.edit().putBoolean("sw_abuse_detect", v).apply()

    /** 文件洪泛检测（恶意应用持续创建垃圾文件撑爆存储） */
    var fileFloodEnabled: Boolean
        get() = sp.getBoolean("sw_file_flood", true)
        set(v) = sp.edit().putBoolean("sw_file_flood", v).apply()

    /** C2 服务器封堵（VPN 黑洞路由失陷指标 IP） */
    var c2FilterEnabled: Boolean
        get() = sp.getBoolean("sw_c2_filter", true)
        set(v) = sp.edit().putBoolean("sw_c2_filter", v).apply()

    /** 系统权限自动收回（收回非白名单应用的危险权限） */
    var autoRevokeEnabled: Boolean
        get() = sp.getBoolean("sw_auto_revoke", false)
        set(v) = sp.edit().putBoolean("sw_auto_revoke", v).apply()

    /** 本地离线病毒扫描（LovelaceAV 二级校验）总开关 */
    var localAvEnabled: Boolean
        get() = sp.getBoolean("sw_local_av", true)
        set(v) = sp.edit().putBoolean("sw_local_av", v).apply()

    /** 云端哈希复核总开关（仅对可疑结果触发，不上传样本） */
    var cloudRecheckEnabled: Boolean
        get() = sp.getBoolean("sw_cloud_recheck", true)
        set(v) = sp.edit().putBoolean("sw_cloud_recheck", v).apply()

    /** VirusTotal v3 API Key（用户自备，空则跳过 VT 引擎） */
    var vtApiKey: String
        get() = sp.getString("vt_api_key", "") ?: ""
        set(v) = sp.edit().putString("vt_api_key", v).apply()

    /** 本地特征库下载地址（sha256.lst / rules.txt 打包的 zip 或单文件） */
    var avdbUrl: String
        get() = sp.getString("avdb_url", "") ?: ""
        set(v) = sp.edit().putString("avdb_url", v).apply()

    /** 特征库最近更新时间 */
    var avdbUpdatedAt: Long
        get() = sp.getLong("avdb_updated_at", 0)
        set(v) = sp.edit().putLong("avdb_updated_at", v).apply()

    /** VT 配额计数：当日已用 / 计数日期 / 最近一分钟窗口 */
    var vtDailyCount: Int
        get() = sp.getInt("vt_daily", 0)
        set(v) = sp.edit().putInt("vt_daily", v).apply()
    var vtDailyDate: String
        get() = sp.getString("vt_daily_date", "") ?: ""
        set(v) = sp.edit().putString("vt_daily_date", v).apply()

    /** 权限白名单（这些应用不参与权限风险评分，也不会被自动收回权限） */
    var permWhitelist: Set<String>
        get() = sp.getStringSet("perm_whitelist", emptySet()) ?: emptySet()
        set(v) = sp.edit().putStringSet("perm_whitelist", v).apply()

    fun addToPermWhitelist(pkg: String) { permWhitelist = permWhitelist + pkg }
    fun removeFromPermWhitelist(pkg: String) { permWhitelist = permWhitelist - pkg }

    fun addToNetBlocked(pkg: String) { netBlocked = netBlocked + pkg }
    fun removeFromNetBlocked(pkg: String) { netBlocked = netBlocked - pkg }

    fun addToBlacklist(pkg: String) { blacklist = blacklist + pkg }
    fun removeFromBlacklist(pkg: String) { blacklist = blacklist - pkg }
    fun addToWhitelist(pkg: String) { whitelist = whitelist + pkg }
    fun removeFromWhitelist(pkg: String) { whitelist = whitelist - pkg }
}