package com.zhiwei.security.core

import android.content.Context
import java.io.File

/**
 * 域名拦截规则库（广告 / 追踪 / 恶意域名）
 *
 * 采用 hosts 风格的「域名后缀匹配」，另加少量通配。设计要点：
 *
 * - **后缀匹配**：规则 `doubleclick.net` 同时命中 `ad.doubleclick.net`、
 *   `x.y.doubleclick.net`，这是广告拦截的行业标准语义（同 ABP / AdGuard）。
 * - **白名单优先**：命中白名单的子域不会被拦（避免把 CDN 误杀导致应用白屏）。
 * - **热路径零分配**：match() 只遍历字符串后缀，返回 Boolean，不建集合不建对象，
 *   因为它在 VPN 读包线程里每秒可能被调用几百次。
 * - **规则可热更新**：内置一份基础表 + 外部文件覆盖（dataDir/blockads/rules.txt），
 *   与本地病毒库同一套更新范式。
 */
object BlockAdsRules {

    private const val TAG = "BlockAdsRules"

    /** 内置基础规则（首批覆盖主流广告/统计/追踪域名） */
    private val BUILTIN = arrayOf(
        // ===== Google 广告与统计 =====
        "doubleclick.net", "googleadservices.com", "googlesyndication.com",
        "googletagmanager.com", "googletagservices.com", "google-analytics.com",
        "google-analytics.cn", "adservice.google.com", "pagead2.googlesyndication.com",
        "2mdn.net", "admob.com", "app-measurement.com", "firebase-settings.com",
        "googleads.g.doubleclick.net", "partner.googleadservices.com",
        // ===== 国内主流广告联盟 =====
        "umeng.com", "umeng.co", "umengcloud.com", "umsns.com", "uyunad.com",
        "cnzz.com", "cpro.baidu.com", "pos.baidu.com", "union.baidu.com",
        "tanx.com", "alimama.com", "mmstat.com", "simba.taobao.com",
        "gdt.qq.com", "advertising.apple.com", "applovin.com", "vungle.com",
        "pangolin-sdk-toutiao.com", "pglstatp-toutiao.com", "ad.toutiao.com",
        "gromore.com", "csjplatform.com",
        "mobads.baidu.com", "miuiad.com", "ad.xiaomi.com", "mistat.xiaomi.com",
        "tracking.miui.com", "adata.hicloud.com", "ads.hicloud.com",
        "opendata.hicloud.com", "metrics.oppomobile.com", "adx.oppo.com",
        "honor-ads.com", "ads.vivo.com.cn",
        "metrics.vivo.com.cn", "adnet.oppomobile.com",
        // ===== 国际广告与追踪 =====
        "graph.facebook.com", "connect.facebook.net",
        "appsflyer.com", "adjust.com", "branch.io", "kochava.com",
        "amplitude.com", "mixpanel.com", "segment.io", "segment.com",
        "heapanalytics.com", "fullstory.com", "hotjar.com", "mouseflow.com",
        "crazyegg.com", "newrelic.com", "bugsnag.com", "sentry.io",
        "scorecardresearch.com", "quantserve.com", "comscore.com",
        "chartbeat.com", "outbrain.com", "taboola.com", "criteo.com",
        "adnxs.com", "adsrvr.org", "rubiconproject.com", "pubmatic.com",
        "openx.net", "casalemedia.com", "smartadserver.com", "yieldmo.com",
        "amazon-adsystem.com", "media.net", "mgid.com", "revcontent.com",
        "zedo.com", "tribalfusion.com", "turn.com", "tapad.com",
        "moatads.com", "doubleverify.com", "adsafeprotected.com",
        "imasdk.googleapis.com", "googlevideo.com",
        // ===== 已知恶意/诈骗/钓鱼家族域名特征 =====
        "dnslog.cn", "ceye.io", "burpcollaborator.net",   // 反连测试被滥用
        "ngrok.io", "ngrok-free.app",                      // 隧道外连高发
        "trycloudflare.com", "serveo.net", "localhost.run",

        // ===== v1.8.1 扩充：国内广告 SDK 与追踪（真实公开域名） =====
        // 友盟 / 极光 / TalkingData / GrowingIO / 神策
        "umeng.com", "umeng.co", "umengcloud.com", "ufp.umeng.com", "uyunad.com",
        "jpush.cn", "jiguang.cn", "talkingdata.com", "talkingdata.net",
        "growingio.com", "sensorsdata.cn", "sensorsdata.com", "analysys.cn",
        // 腾讯系广告与统计
        "gdt.qq.com", "e.qq.com", "pingjs.qq.com", "ta.qq.com", "pingfore.qq.com",
        "btrace.qq.com", "ad.qq.com", "ads.qq.com", "mkt.qq.com",
        // 字节系（穿山甲 / 巨量 / Pangle）
        "pangolin-sdk-toutiao.com", "pglstatp-toutiao.com", "ad.toutiao.com",
        "gromore.com", "csjplatform.com", "snssdk.com",
        "pangle.io", "pangle-sdk.com",
        // 阿里系
        "tanx.com", "alimama.com", "atanx.alicdn.com", "log.mmstat.com",
        "wgo.mmstat.com", "mmstat.com", "simba.taobao.com", "adash.m.taobao.com",
        // 百度系
        "pos.baidu.com", "cpro.baidu.com", "cbjs.baidu.com", "eclick.baidu.com",
        "mobads.baidu.com", "union.baidu.com", "afd.baidu.com", "usp1.baidu.com",
        // 其他国内
        "miuiad.com", "ad.xiaomi.com", "mistat.xiaomi.com", "tracking.miui.com",
        "adata.hicloud.com", "ads.hicloud.com", "opendata.hicloud.com",
        "metrics.oppomobile.com", "adx.oppo.com", "adnet.oppomobile.com",
        "honor-ads.com", "ads.vivo.com.cn", "metrics.vivo.com.cn",
        "iad.g.163.com", "analytics.163.com", "beacon.sina.com.cn",
        "mvm.360.cn", "s.360.cn", "kuaishouzt.com", "ad.kuaishou.com",
        "wifi.sina.com.cn", "log.sina.com.cn", "sax.sina.com.cn",

        // ===== v1.8.1 扩充：海外广告网络 / 聚合平台（AppLovin MAX 生态等） =====
        "applovin.com", "applvn.com", "adcolony.com", "vungle.com",
        "chartboost.com", "tapjoy.com", "ironsrc.com", "ironsrc.mobi",
        "supersonicads.com", "inmobi.com", "inmobicdn.net", "mintegral.com",
        "fyber.com", "smaato.net", "ogury.com", "adform.net", "teads.tv",
        "unityads.unity3d.com", "auction.unityads.unity3d.com",
        "criteo.com", "criteo.net", "adnxs.com", "adsrvr.org",
        "rubiconproject.com", "pubmatic.com", "openx.net", "casalemedia.com",
        "smartadserver.com", "yieldmo.com", "indexww.com", "triplelift.com",
        "sharethrough.com", "conversantmedia.com", "ads.yandex.ru",
        "an.yandex.ru", "mc.yandex.ru", "top-fwz1.mail.ru",
        "amazon-adsystem.com", "media.net", "mgid.com", "revcontent.com",
        "zedo.com", "tribalfusion.com", "turn.com", "tapad.com",
        "moatads.com", "doubleverify.com", "adsafeprotected.com",
        "imasdk.googleapis.com", "2mdn.net",
        "scorecardresearch.com", "quantserve.com", "comscore.com",
        "chartbeat.com", "outbrain.com", "taboola.com",
        "appsflyer.com", "adjust.com", "branch.io", "kochava.com",
        "amplitude.com", "mixpanel.com", "segment.io", "segment.com",
        "heapanalytics.com", "fullstory.com", "hotjar.com", "mouseflow.com",
        "crazyegg.com", "newrelic.com", "bugsnag.com", "sentry.io",
        "graph.facebook.com", "connect.facebook.net",
        "analytics.tiktok.com", "business-api.tiktok.com",
        "ads.tiktok.com", "log.tiktokv.com", "mon.tiktokv.com",

        // ===== v1.8.1 扩充：反连 / 隧道 / 临时回连平台（钓鱼与后门高发） =====
        "interact.sh", "oast.fun", "oast.me", "oast.pro", "oast.live",
        "requestbin.net", "requestbin.io", "webhook.site", "pipedream.net",
        "beeceptor.com", "hookbin.com", "requestcatcher.com",
        "localtunnel.me", "pagekite.me", "telebit.io", "tunnelto.dev",
        "burpcollaborator.net", "canarytokens.com", "dnslog.cn", "ceye.io",
        "tu4.org", "xip.io", "nip.io", "sslip.io"
    )

    /** 明确放行（即使父域被拦也不拦），防止把正常服务打挂 */
    private val BUILTIN_WHITELIST = arrayOf(
        "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
        "qq.com", "gtimg.com", "tencent.com", "weixin.qq.com", "wechat.com",
        "aliyun.com", "aliyuncs.com", "taobao.com", "tmall.com", "alicdn.com",
        "bdstatic.com", "bdimg.com", "baidu.com", "zhihu.com", "zhimg.com",
        "xiaomi.com", "mi.com", "miui.com", "huawei.com", "hicloud.com",
        "oppo.com", "vivo.com", "honor.com", "samsung.com",
        "apple.com", "icloud.com", "mzstatic.com",
        "github.com", "githubusercontent.com", "ghfast.top",
        "wecom.work", "dingtalk.com", "feishu.cn", "bytedance.com"
    )

    // 运行期索引（避免每次热更新后重复解析）
    // v1.8.1：改为 HashSet，规则表从 150 条扩到 200+ 后线性扫描成为热路径瓶颈，
    // 精确匹配退化 O(1)，后缀判断只对当前域名的父域链做常数次。
    @Volatile private var ruleSet: Set<String> = BUILTIN.toHashSet()
    @Volatile private var whiteSet: Set<String> = BUILTIN_WHITELIST.toHashSet()

    /** 命中计数（UI 展示"已拦截 N 次"，非精确统计） */
    @Volatile var blockedCount: Long = 0L
        private set

    @Volatile var lastBlockedDomain: String = ""
        private set

    /**
     * 解析一行规则文本，支持三种主流格式（实测可直接吃下 AdGuard / ABP / hosts 规则包）：
     * - hosts：`0.0.0.0 ads.example.com` / `127.0.0.1 ads.example.com`
     * - ABP/AdGuard 拦截：`||ads.example.com^`、`|https://ads.example.com/`、纯域名
     * - ABP/AdGuard 例外：`@@||safe.example.com^`、`@@safe.example.com`
     *
     * @return Pair(域名, 是否为白名单) 或 null 表示该行不是可用规则
     */
    private fun parseRuleLine(raw: String): Pair<String, Boolean>? {
        var line = raw.trim()
        if (line.isEmpty()) return null
        if (line.startsWith("#") || line.startsWith("!")) return null   // 注释
        if (line.startsWith("[")) return null                            // [Adblock Plus 2.0]

        var isException = false
        // ABP 例外语法 @@||domain^
        if (line.startsWith("@@")) {
            isException = true
            line = line.substring(2).trim()
        }
        // hosts 格式：IP 开头
        if (line.startsWith("0.0.0.0") || line.startsWith("127.0.0.1") ||
            line.startsWith("::1") || line.startsWith("::")) {
            line = line.substringAfter(' ', "").trim()
            if (line.isEmpty()) return null
        }
        // 剥离 ABP 修饰符
        line = line.removePrefix("||").removePrefix("|")
        line = line.removeSuffix("^").removeSuffix("|")
        // AdGuard 的 $third-party 等选项：DNS 层做不到，直接丢弃整条
        if (line.contains('$')) return null
        // 显式正则规则（/regex/）不支持
        if (line.startsWith("/") && line.endsWith("/") && line.length > 2) return null
        // 通配符规则（*.example.com）转成后缀域名
        line = line.removePrefix("*.").removePrefix(".")
        // 取主机名部分（去掉路径、协议、端口）
        line = line.substringAfter("://")
        line = line.substringBefore('/')
        line = line.substringBefore(':')
        line = line.trim().lowercase()
        if (line.isEmpty() || !line.contains('.')) return null
        if (line.any { it == ' ' || it == '*' || it == '#' }) return null
        return line to isException
    }

    /** 加载外部规则文件（与内置合并；文件不存在则保持内置） */
    fun load(context: Context) {
        try {
            val f = File(context.filesDir, "blockads/rules.txt")
            if (!f.exists() || f.length() == 0L) {
                ruleSet = BUILTIN.toHashSet()
                whiteSet = BUILTIN_WHITELIST.toHashSet()
                return
            }
            applyRuleText(f.readText())
        } catch (e: Throwable) {
            ruleSet = BUILTIN.toHashSet()
            whiteSet = BUILTIN_WHITELIST.toHashSet()
        }
    }

    /**
     * 直接把整段规则文本并入规则库（供 UI 的「导入规则包」使用）。
     * 支持 AdGuard / ABP / hosts 三种格式，自动识别。
     *
     * @return Pair(新增拦截规则数, 新增白名单数)
     */
    fun applyRuleText(text: String): Pair<Int, Int> {
        val r = LinkedHashSet<String>(BUILTIN.toList())
        val wl = LinkedHashSet<String>(BUILTIN_WHITELIST.toList())
        var addedR = 0
        var addedW = 0
        text.lineSequence().forEach { raw ->
            val parsed = parseRuleLine(raw) ?: return@forEach
            val (host, isException) = parsed
            if (isException) {
                if (wl.add(host)) addedW++
            } else {
                if (r.add(host)) addedR++
            }
        }
        ruleSet = r
        whiteSet = wl
        return addedR to addedW
    }

    /** 规则条数（UI 展示） */
    val ruleCount: Int get() = ruleSet.size

    /** 白名单条数（UI 展示） */
    val whiteCount: Int get() = whiteSet.size

    /**
     * 是否应拦截该域名。
     *
     * 匹配逻辑：域名及其所有父域逐个比对规则表；
     * 任一父域命中规则即拦；但只要该域名命中白名单则直接放行。
     *
     * 说明：白名单只比对「当前完整域名」与父域，不做前缀匹配，
     * 因此白名单 `qq.com` 不会放行 `evil.ad.qq.com.attacker.net`。
     */
    fun shouldBlock(domain: String): Boolean {
        if (domain.isEmpty()) return false
        // 白名单优先：当前域名或任一父域在白名单里 → 放行
        if (matchesAny(domain, whiteSet)) return false
        // 规则匹配：当前域名或任一父域命中 → 拦截
        if (matchesAny(domain, ruleSet)) {
            blockedCount++
            lastBlockedDomain = domain
            return true
        }
        return false
    }

    /** 语义：上层域名后缀匹配（abp `||domain^` 的等价实现） */
    private fun matchesAny(domain: String, table: Set<String>): Boolean {
        var sub = domain
        while (true) {
            if (sub in table) return true
            val dot = sub.indexOf('.')
            if (dot < 0 || dot >= sub.length - 1) return false
            sub = sub.substring(dot + 1)
            // 只剩 TLD 时停止（不会把 "com" 当规则命中）
            if (!sub.contains('.')) return false
        }
    }

    /** 重置计数（UI「清空」按钮） */
    fun resetCounter() {
        blockedCount = 0L
        lastBlockedDomain = ""
    }
}