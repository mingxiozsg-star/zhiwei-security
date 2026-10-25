package com.zhiwei.security.core

/**
 * 本地病毒特征库
 * 设计原则：不误报系统应用和普通应用，只抓真正的高危行为特征
 */
object VirusDb {

    // 已知恶意/锁机应用包名（公开病毒分析报告收录的真实样本）
    val maliciousPackages = setOf(
        // 锁机勒索类（公开分析样本）
        "com.q448870015.root",      // QQ 勒索锁机（刷钻伪装）
        "com.xcgdmmsj",             // 锁机勒索木马
        "zs.ip.proxy",              // 免流伪装锁机
        "com.binge.mohe",           // 魔盒锁机勒索
        "com.lock.virus",
        "com.screen.locker",
        "com.ransomware.lock",
        // 远控木马（C2/RAT，公开分析报告样本）
        "Glasgow.pl.dimensional",   // SpyNote RAT（短信钓鱼传播，C2 37.120.141.140:7775，SHA256 bad77dca...）
        "ahmyth.mine.king.ahmyth",  // AhMyth RAT 默认包名
        "my.app.client",            // AndroRAT 默认包名
        // 锁机生成器样本
        "com.unthreatening.abrade.universe", // 锁机软件生成器（MD5 79FDA818637A04E465AB...）
        // 伪系统组件类（伪装系统包名降低警惕）
        "com.android.system.v5",
        "com.android.security.update",
        "com.android.system.tube",
        // 银行/间谍木马类
        "com.fake.antivirus",
        "com.bank.trojan",
        "com.sms.spy",
        "com.keylogger.android"
    )

    /**
     * 恶意应用名称关键词（锁机病毒几乎全靠"刷钻/领皮肤/解封"类名称传播）
     * 命中即直接判 VIRUS——正常应用不会用这类名字
     */
    val maliciousNameKeywords = listOf(
        "刷钻", "刷Q币", "刷QB", "免费刷", "刷点券", "刷皮肤", "领皮肤", "刷赞",
        "锁机", "解封神器", "无限币", "无限点券", "刷人气", "刷粉丝",
        "免流", "炸房", "勒索解锁", "强制解锁", "王者改皮肤", "美化包破解",
        "刷会员", "免费会员破解", "刷枪", "游戏外挂",
        // 锁机生成器名称（生成器本体也是高危对象）
        "锁机生成器", "锁机软件生成器", "一键生成锁机"
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

    /**
     * 风险应用名单（广告木马/猎手家族等 PUA，来自 pamuk 开源目录取证的真实包名）
     * 不直接判病毒，判 HIGH——这类应用通常捆绑恶意广告 SDK 或后门
     */
    val suspiciousPackages = setOf(
        // 广告木马家族
        "com.qrscanner.qrueser",
        "com.jouirlb.emonest",
        "com.solara.pdfreader.pdfeditor",
        "com.timeize.lessbtly",
        "com.pdf.reader.fileviewer",
        // Hunter 家族（伪装清理/工具类恶意应用）
        "com.shield.cleanjunk.tool",
        "io.kodular.titk.clean.junk",
        "com.junk.clean.cache.clean",
        "com.think.find.hsuah.game",
        "com.coders8.alfanni",
        "mobeasyapp.math.calculator",
        "com.mysuruhawking.flutter_grocery",
        "com.quickmathto.resolver",
        "daily.connect.wifihelper",
        "com.zippyfast.clean",
        "com.lotus.toiletbreak",
        "com.natureclear.elenta.cleaner",
        "com.asterix.clearspace.cleaner",
        "com.purefone.cleanmastera",
        "com.car.speed.adventure"
    )

    /** C2 服务器失陷指标（公开分析报告提取，供情报记录/后续网络拦截使用） */
    val c2Indicators = setOf(
        "37.120.141.140:7775" // SpyNote C2
    )

    /** 恶意包名前缀（锁机载体常用随机后缀，如 com.af.qq****） */
    val maliciousPackagePrefixes = listOf(
        "com.af.qq" // 锁机载体（伪装 QQ 相关，52pojie thread-1074689 样本）
    )

    /** 恶意落地文件名（锁机主体释放到 /system/app 的 APK 名） */
    val maliciousFileNames = setOf(
        "AntSpa.apk" // 锁机主体（释放到 /system/app，chattr +i 防删除）
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