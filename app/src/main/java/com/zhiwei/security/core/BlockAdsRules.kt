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
        "bytedance.com/ad", "gromore.com", "csjplatform.com",
        "mobads.baidu.com", "miuiad.com", "ad.xiaomi.com", "mistat.xiaomi.com",
        "tracking.miui.com", "adata.hicloud.com", "ads.hicloud.com",
        "opendata.hicloud.com", "metrics.oppomobile.com", "adx.oppo.com",
        "grs.hicloud.com/ad", "honor-ads.com", "ads.vivo.com.cn",
        "metrics.vivo.com.cn", "adnet.oppomobile.com",
        // ===== 国际广告与追踪 =====
        "facebook.com/tr", "graph.facebook.com", "connect.facebook.net",
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
        "imasdk.googleapis.com", "googlevideo.com/ad",
        // ===== 已知恶意/诈骗/钓鱼家族域名特征 =====
        "dnslog.cn", "ceye.io", "burpcollaborator.net",   // 反连测试被滥用
        "ngrok.io", "ngrok-free.app",                      // 隧道外连高发
        "trycloudflare.com", "serveo.net", "localhost.run"
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
    @Volatile private var rules: Array<String> = BUILTIN
    @Volatile private var whitelist: Array<String> = BUILTIN_WHITELIST

    /** 命中计数（UI 展示"已拦截 N 次"，非精确统计） */
    @Volatile var blockedCount: Long = 0L
        private set

    @Volatile var lastBlockedDomain: String = ""
        private set

    /** 加载外部规则文件（覆盖内置；文件不存在则保持内置） */
    fun load(context: Context) {
        try {
            val f = File(context.filesDir, "blockads/rules.txt")
            if (!f.exists() || f.length() == 0L) {
                rules = BUILTIN
                whitelist = BUILTIN_WHITELIST
                return
            }
            val r = ArrayList<String>()
            val w = ArrayList<String>()
            val wl = ArrayList<String>(BUILTIN_WHITELIST.toList())
            f.forEachLine { raw ->
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#")) return@forEachLine
                when {
                    line.startsWith("@@") -> wl.add(line.substring(2).trim().lowercase())
                    line.startsWith("-") -> wl.add(line.substring(1).trim().lowercase())
                    else -> r.add(line.lowercase())
                }
            }
            // 外部文件里的规则 + 内置（合并而非覆盖，避免用户只加一条就丢全部基础库）
            val merged = LinkedHashSet<String>()
            merged.addAll(BUILTIN.toList())
            merged.addAll(r)
            rules = merged.toTypedArray()
            whitelist = wl.distinct().toTypedArray()
        } catch (e: Throwable) {
            rules = BUILTIN
            whitelist = BUILTIN_WHITELIST
        }
    }

    /** 规则条数（UI 展示） */
    val ruleCount: Int get() = rules.size

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
        if (matchesAny(domain, whitelist)) return false
        // 规则匹配：当前域名或任一父域命中 → 拦截
        if (matchesAny(domain, rules)) {
            blockedCount++
            lastBlockedDomain = domain
            return true
        }
        return false
    }

    /** 语义：上层域名后缀匹配（abp `||domain^` 的等价实现） */
    private fun matchesAny(domain: String, table: Array<String>): Boolean {
        var idx = 0
        while (true) {
            val sub = if (idx == 0) domain else domain.substring(idx)
            for (rule in table) {
                if (sub == rule) return true
                // 规则带路径的情况（如 "facebook.com/tr"）用前缀判断，
                // 因为 DNS 层拿不到路径，这类规则实际永远不命中，保留仅为将来 HTTP 层扩展
                if (rule.indexOf('/') > 0) continue
                if (sub.length > rule.length) {
                    val off = sub.length - rule.length
                    if (sub[off - 1] == '.' && sub.regionMatches(off, rule, 0, rule.length)) return true
                }
            }
            val dot = domain.indexOf('.', idx + 1)
            if (dot < 0) return false
            idx = dot + 1
            // 只剩 TLD 时没必要再查
            if (domain.indexOf('.', idx) < 0 && idx >= domain.length - 1) return false
        }
    }

    /** 重置计数（UI「清空」按钮） */
    fun resetCounter() {
        blockedCount = 0L
        lastBlockedDomain = ""
    }
}