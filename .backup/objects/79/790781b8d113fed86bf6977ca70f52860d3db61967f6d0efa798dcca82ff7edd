package com.zhiwei.security.core

/**
 * 本地病毒特征库
 * 包含已知恶意应用包名、危险权限组合、签名特征
 */
object VirusDb {

    // 已知恶意/锁机应用包名
    val maliciousPackages = setOf(
        "com.lock.virus",
        "com.screen.locker",
        "com.fake.antivirus",
        "com.ransomware.lock",
        "com.android.system.lock",
        "com.system.security.fake",
        "com.phone.locker.pro",
        "com.device.locker",
        "com.lockscreen.hack",
        "com.privacy.locker.fake",
        "com.app.lock.virus",
        "com.security.locker.fake",
        "com.locker.master.fake",
        "com.screenlock.virus",
        "com.phishing.fake",
        "com.sms.fraud",
        "com.bank.trojan",
        "com.sms.spy",
        "com.call.recorder.spy",
        "com.location.tracker.spy",
        "com.keylogger.android",
        "com.rootkit.hidden",
        "com.adware.push",
        "com.click.fraud",
        "com.crypto.miner",
        "com.premium.sms.fraud",
        "com.fake.update",
        "com.system.update.fake",
        "com.google.update.fake",
        "com.browser.hijacker"
    )

    // 危险权限列表（单独出现时风险较低，组合出现时风险高）
    val dangerousPermissions = mapOf(
        "android.permission.SYSTEM_ALERT_WINDOW" to 30,
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to 35,
        "android.permission.BIND_DEVICE_ADMIN" to 40,
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" to 25,
        "android.permission.RECEIVE_BOOT_COMPLETED" to 5,
        "android.permission.READ_SMS" to 20,
        "android.permission.SEND_SMS" to 25,
        "android.permission.RECEIVE_SMS" to 20,
        "android.permission.RECORD_AUDIO" to 15,
        "android.permission.CAMERA" to 10,
        "android.permission.ACCESS_FINE_LOCATION" to 10,
        "android.permission.READ_CONTACTS" to 15,
        "android.permission.READ_CALL_LOG" to 15,
        "android.permission.PROCESS_OUTGOING_CALLS" to 20,
        "android.permission.WRITE_SETTINGS" to 20,
        "android.permission.WRITE_SECURE_SETTINGS" to 35,
        "android.permission.DEVICE_POWER" to 30,
        "android.permission.DISABLE_KEYGUARD" to 25,
        "android.permission.REORDER_TASKS" to 10,
        "android.permission.GET_TASKS" to 5,
        "android.permission.KILL_BACKGROUND_PROCESSES" to 10,
        "android.permission.REQUEST_INSTALL_PACKAGES" to 15,
        "android.permission.REQUEST_DELETE_PACKAGES" to 15,
        "android.permission.FACTORY_RESET" to 40,
        "android.permission.MASTER_CLEAR" to 40,
        "android.permission.MOUNT_UNMOUNT_FILESYSTEMS" to 25,
        "android.permission.READ_LOGS" to 20,
        "android.permission.SET_TIME" to 15,
        "android.permission.SET_TIME_ZONE" to 10,
        "android.permission.CHANGE_CONFIGURATION" to 10,
        "android.permission.MODIFY_PHONE_STATE" to 30,
        "android.permission.CALL_PHONE" to 15,
        "android.permission.USE_SIP" to 10,
        "android.permission.VIBRATE" to 1,
        "android.permission.WAKE_LOCK" to 2,
        "android.permission.FOREGROUND_SERVICE" to 2
    )

    // 高危权限组合（同时出现多个即为高风险）
    val dangerousCombos = listOf(
        // 锁机组合：悬浮窗 + 设备管理器 + 禁用锁屏
        setOf("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_DEVICE_ADMIN", "android.permission.DISABLE_KEYGUARD"),
        // 锁机组合：悬浮窗 + 无障碍 + 设备管理器
        setOf("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.BIND_DEVICE_ADMIN"),
        // 间谍组合：短信 + 通讯录 + 定位 + 录音
        setOf("android.permission.READ_SMS", "android.permission.READ_CONTACTS", "android.permission.ACCESS_FINE_LOCATION", "android.permission.RECORD_AUDIO"),
        // 勒索组合：悬浮窗 + 设备管理器 + 开机自启 + 写设置
        setOf("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_DEVICE_ADMIN", "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.WRITE_SETTINGS"),
        // 银行木马：短信 + 通知监听 + 悬浮窗
        setOf("android.permission.READ_SMS", "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW")
    )

    // 已知恶意签名 MD5
    val maliciousSignatures = setOf(
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3"
    )

    // 白名单包名（系统应用、常见安全应用）
    val systemWhitelist = setOf(
        "com.android.systemui",
        "com.android.settings",
        "com.android.phone",
        "com.android.providers.contacts",
        "com.android.providers.media",
        "com.android.providers.downloads",
        "com.android.packageinstaller",
        "com.android.shell",
        "com.android.permissioncontroller",
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.google.android.webview",
        "com.google.android.packageinstaller"
    )

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