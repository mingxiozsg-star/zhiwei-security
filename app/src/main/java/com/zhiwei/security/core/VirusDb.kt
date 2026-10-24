package com.zhiwei.security.core

/**
 * 本地病毒特征库
 * 设计原则：不误报系统应用和普通应用，只抓真正的高危行为特征
 */
object VirusDb {

    // 已知恶意/锁机应用包名（真实样本持续补充）
    val maliciousPackages = setOf(
        "com.lock.virus",
        "com.screen.locker",
        "com.ransomware.lock",
        "com.fake.antivirus",
        "com.bank.trojan",
        "com.sms.spy",
        "com.keylogger.android"
    )

    /**
     * 危险权限评分（只统计非系统应用）
     * 原则：单项权限绝不构成病毒判定，只累计风险分
     */
    val dangerousPermissions = mapOf(
        "android.permission.SYSTEM_ALERT_WINDOW" to 8,       // 悬浮窗：很多正常应用都有，只算低分
        "android.permission.BIND_DEVICE_ADMIN" to 25,        // 设备管理器：锁机应用核心
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to 20, // 无障碍：可模拟点击
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" to 12,
        "android.permission.READ_SMS" to 10,
        "android.permission.SEND_SMS" to 12,
        "android.permission.RECEIVE_SMS" to 8,
        "android.permission.RECORD_AUDIO" to 5,
        "android.permission.CAMERA" to 3,
        "android.permission.ACCESS_FINE_LOCATION" to 3,
        "android.permission.READ_CONTACTS" to 5,
        "android.permission.READ_CALL_LOG" to 8,
        "android.permission.PROCESS_OUTGOING_CALLS" to 10,
        "android.permission.DISABLE_KEYGUARD" to 15,         // 禁用锁屏：锁机关键
        "android.permission.WRITE_SETTINGS" to 5,
        "android.permission.REQUEST_INSTALL_PACKAGES" to 5,
        "android.permission.CALL_PHONE" to 5,
        "android.permission.RECEIVE_BOOT_COMPLETED" to 2
    )

    // 高危权限组合（锁机/勒索/间谍的标志性特征，命中即高危）
    data class Combo(val perms: Set<String>, val bonus: Int, val label: String)

    val dangerousCombos = listOf(
        // 锁机组合：悬浮窗 + 设备管理器
        Combo(
            setOf("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_DEVICE_ADMIN"),
            45, "锁机权限组合（悬浮窗+设备管理器）"
        ),
        // 锁机组合：悬浮窗 + 禁用锁屏
        Combo(
            setOf("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.DISABLE_KEYGUARD"),
            35, "可疑锁屏组合（悬浮窗+禁用锁屏）"
        ),
        // 顽固锁机：设备管理器 + 开机自启 + 悬浮窗
        Combo(
            setOf("android.permission.BIND_DEVICE_ADMIN", "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.SYSTEM_ALERT_WINDOW"),
            50, "顽固锁机组合（设备管理器+自启+悬浮窗）"
        ),
        // 银行木马：短信读取 + 通知监听
        Combo(
            setOf("android.permission.READ_SMS", "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"),
            35, "验证码窃取组合（短信+通知监听）"
        ),
        // 间谍组合：定位 + 录音 + 通讯录 + 短信
        Combo(
            setOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS", "android.permission.READ_SMS"),
            40, "间谍行为组合（定位+录音+通讯录+短信）"
        )
    )

    // 已知恶意签名 MD5（真实样本持续补充）
    val maliciousSignatures = setOf<String>()

    enum class ThreatLevel(val label: String, val color: Long) {
        SAFE("安全", 0xFF4CAF50),
        LOW("低风险", 0xFF8BC34A),
        MEDIUM("中风险", 0xFFFF9800),
        HIGH("高风险", 0xFFF44336),
        VIRUS("病毒", 0xFF9C27B0)
    }

    data class ScanResult(
        val packageName: String,
        val appName: String,
        val level: ThreatLevel,
        val score: Int,
        val reasons: List<String>,
        val permissions: List<String>,
        val isSystem: Boolean,
        val versionName: String?,
        val apkPath: String?
    )
}