package com.zhiwei.security.core

import android.content.Context
import androidx.compose.runtime.mutableStateMapOf
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/**
 * 云端哈希复核模块 —— 二级校验层，不替代本地扫描
 *
 * 铁律：
 * - 只提交 APK 的 SHA256，禁止上传样本本体
 * - 仅对本地判定【可疑】（MEDIUM/HIGH）的样本触发；干净应用零云端调用
 * - 本地哈希缓存池 1 小时；VT 严格 4 次/分 + 500 次/日
 * - 429/超时/无网/服务不可用 → 静默降级，保留本地判定，不弹窗不阻塞
 * - 不做全应用批量云端轮询
 */
object CloudHashVerifier {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    data class EngineVerdict(
        val engine: String,        // 来源平台
        val malicious: Boolean,
        val superHigh: Boolean,    // 锁机/远控/窃密/无障碍木马
        val family: String,
        val tags: List<String>,
        val detail: String,
        val time: Long
    ) {
        val timeText: String
            get() = SimpleDateFormat("MM-dd HH:mm:ss", Locale.getDefault()).format(Date(time))
    }

    data class Verdict(
        val packageName: String,
        val sha256: String,
        val results: List<EngineVerdict>,
        val triggeredKill: Boolean
    )

    /** 各包名最近一次云端核验结果（病毒详情面板订阅） */
    val verdicts = mutableStateMapOf<String, Verdict>()

    // 哈希缓存池：sha256 -> (完成时间, 判定结果)
    private val cache = ConcurrentHashMap<String, Pair<Long, List<EngineVerdict>>>()
    private const val CACHE_TTL = 60 * 60 * 1000L

    // VT 限流
    private val vtMinuteWindow = ArrayList<Long>()
    private const val VT_PER_MIN = 4
    private const val VT_PER_DAY = 500

    // 超级高危标签（锁机/远控/窃密/无障碍木马）
    private val superHighTags = setOf(
        "locker", "ransom", "ransomware", "rat", "spyware", "stealer",
        "banker", "banking", "keylogger", "backdoor", "accessibility"
    )

    /**
     * 对可疑样本发起云端复核（后台异步，不阻塞扫描）。
     * 仅 MEDIUM/HIGH 进入；干净/VIRUS（本地已处置）不触发。
     */
    fun maybeRecheck(context: Context, r: VirusDb.ScanResult) {
        if (!Prefs.cloudRecheckEnabled) return
        if (r.level != VirusDb.ThreatLevel.MEDIUM && r.level != VirusDb.ThreatLevel.HIGH) return
        val path = r.apkPath ?: return
        scope.launch { recheck(context, r.packageName, r.appName, path) }
    }

    private fun recheck(context: Context, pkg: String, appName: String, apkPath: String) {
        try {
            val sha = sha256(File(apkPath)) ?: return

            // 1 小时缓存命中直接复用
            cache[sha]?.let { (t, cached) ->
                if (System.currentTimeMillis() - t < CACHE_TTL) {
                    SecurityJournal.log("云端复核", "缓存命中 $pkg sha256=${sha.take(12)}… 复用上次结论")
                    publish(context, pkg, appName, sha, cached)
                    return
                }
            }

            val results = ArrayList<EngineVerdict>()
            // 优先级 ① MalwareBazaar
            queryMalwareBazaar(sha)?.let { results.add(it) }
            // 优先级 ② 国家计算机病毒协同分析平台（无公开 API，端点可达时启用）
            queryCverc(sha)?.let { results.add(it) }
            // 优先级 ③ VirusTotal 兜底（配额受限）
            queryVirusTotal(sha)?.let { results.add(it) }

            if (results.isEmpty()) {
                SecurityJournal.log("云端复核", "$pkg 全部云端引擎不可用，静默降级保留本地判定")
                return
            }
            cache[sha] = System.currentTimeMillis() to results
            publish(context, pkg, appName, sha, results)
        } catch (e: Throwable) {
            // 静默降级
        }
    }

    private fun publish(context: Context, pkg: String, appName: String,
                        sha: String, results: List<EngineVerdict>) {
        val superHigh = results.any { it.malicious && it.superHigh }
        var killed = false
        if (superHigh) {
            killed = executeKill(context, pkg)
            NotifHelper.alert(context, "☠️ 云端复核确认超级高危",
                "$appName 被云端标记为锁机/远控类威胁，已触发斩杀")
        }
        SecurityJournal.runOnMain { verdicts[pkg] = Verdict(pkg, sha, results, killed) }
        SecurityJournal.log(
            "云端复核",
            "包名=$pkg 哈希=${sha.take(16)}… " +
                results.joinToString("；") { "${it.engine}:${if (it.malicious) "恶意(${it.family})" else "未检出"}" } +
                " 触发斩杀=$killed"
        )
    }

    /** 超级高危联动斩杀：冻结 → 回收权限 → 卸载（复用 Privilege 通道） */
    private fun executeKill(context: Context, pkg: String): Boolean {
        if (!Privilege.isReady) return false
        return try {
            Privilege.forceStop(pkg)
            Privilege.revokeAccessibility(context, pkg)
            val ok = Privilege.uninstall(pkg)
            SecurityJournal.log("斩杀", "云端复核联动斩杀 $pkg 卸载${if (ok) "成功" else "失败"}")
            ok
        } catch (e: Throwable) { false }
    }

    // ===== 引擎实现 =====

    /** ① MalwareBazaar (abuse.ch)：POST query=get_info&hash=sha256，无需 key */
    private fun queryMalwareBazaar(sha: String): EngineVerdict? {
        return try {
            val conn = URI("https://mb-api.abuse.ch/api/v1/").toURL()
                .openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.connectTimeout = 8_000; conn.readTimeout = 8_000
            conn.doOutput = true
            conn.outputStream.use { it.write("query=get_info&hash=$sha".toByteArray()) }
            if (conn.responseCode != 200) return null
            val body = conn.inputStream.bufferedReader().readText()
            if (body.contains("hash_not_found")) {
                return EngineVerdict("MalwareBazaar", false, false, "", emptyList(), "未收录该样本", System.currentTimeMillis())
            }
            val sig = extractJsonString(body, "signature")
            val tags = extractJsonArray(body, "tags")
            val family = sig.ifEmpty { extractJsonString(body, "family") }
            val malicious = family.isNotEmpty() || tags.isNotEmpty()
            EngineVerdict(
                "MalwareBazaar", malicious,
                tags.any { it.lowercase() in superHighTags } || family.lowercase().let { f -> superHighTags.any { f.contains(it) } },
                family.ifEmpty { "未知家族" }, tags,
                "sha256 查询命中", System.currentTimeMillis()
            )
        } catch (e: Throwable) { null }
    }

    /** ② 国家计算机病毒协同分析平台：无公开 API，预留哈希查询端点，静默降级 */
    private fun queryCverc(sha: String): EngineVerdict? {
        // 国内平台无公开 REST 接口；如获得合作接入，在此实现哈希查询。
        // 保持返回 null = 静默跳过，不影响调度链。
        return null
    }

    /** ③ VirusTotal v3：严格 4/分 + 500/日，无 key 直接跳过 */
    private fun queryVirusTotal(sha: String): EngineVerdict? {
        val key = Prefs.vtApiKey
        if (key.isEmpty()) return null
        if (!vtQuotaOk()) return null
        return try {
            val conn = URI("https://www.virustotal.com/api/v3/files/$sha").toURL()
                .openConnection() as HttpURLConnection
            conn.setRequestProperty("x-apikey", key)
            conn.connectTimeout = 8_000; conn.readTimeout = 8_000
            val code = conn.responseCode
            if (code == 404) return EngineVerdict("VirusTotal", false, false, "", emptyList(), "未收录该样本", System.currentTimeMillis())
            if (code == 429 || code != 200) return null // 限流/故障静默降级
            val body = conn.inputStream.bufferedReader().readText()
            val stats = body.substringAfter("\"last_analysis_stats\"", "")
            val mal = Regex("\"malicious\"\\s*:\\s*(\\d+)").find(stats)?.groupValues?.get(1)?.toIntOrNull() ?: 0
            val label = extractJsonString(body, "suggested_threat_label")
            val tags = extractJsonArray(body, "tags")
            EngineVerdict(
                "VirusTotal", mal > 0,
                mal >= 5 || tags.any { it.lowercase() in superHighTags } ||
                    label.lowercase().let { l -> superHighTags.any { l.contains(it) } },
                label.ifEmpty { "未知家族" }, tags,
                "$mal 家引擎报毒", System.currentTimeMillis()
            )
        } catch (e: Throwable) { null }
    }

    @Synchronized
    private fun vtQuotaOk(): Boolean {
        val today = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date())
        if (Prefs.vtDailyDate != today) { Prefs.vtDailyDate = today; Prefs.vtDailyCount = 0 }
        if (Prefs.vtDailyCount >= VT_PER_DAY) return false
        val now = System.currentTimeMillis()
        vtMinuteWindow.removeAll { now - it > 60_000 }
        if (vtMinuteWindow.size >= VT_PER_MIN) return false
        vtMinuteWindow.add(now)
        Prefs.vtDailyCount += 1
        return true
    }

    // ===== 工具 =====

    private fun sha256(f: File): String? = try {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { inp ->
            val buf = ByteArray(64 * 1024)
            var n = inp.read(buf)
            while (n > 0) { md.update(buf, 0, n); n = inp.read(buf) }
        }
        md.digest().joinToString("") { "%02x".format(it) }
    } catch (e: Throwable) { null }

    private fun extractJsonString(json: String, key: String): String =
        Regex("\"$key\"\\s*:\\s*\"([^\"]*)\"").find(json)?.groupValues?.get(1) ?: ""

    private fun extractJsonArray(json: String, key: String): List<String> =
        Regex("\"$key\"\\s*:\\s*\\[([^]]*)]").find(json)?.groupValues?.get(1)
            ?.split(",")?.map { it.trim().removeSurrounding("\"") }
            ?.filter { it.isNotEmpty() } ?: emptyList()
}