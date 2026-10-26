package com.zhiwei.security.core

import android.content.Context
import android.content.pm.PackageInfo
import androidx.compose.runtime.mutableStateMapOf
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * LovelaceAV（Hypatia 分叉风格）本地离线病毒扫描引擎 —— 二级本地校验模块
 *
 * 设计约束：
 * - 主包不内置特征库；库文件外置在 filesDir/avdb/，后台下载/增量更新/可清空
 * - 初始化失败、特征库缺失 → 自动降级（isAvailable=false），只保留黑名单，不崩溃
 * - 全部扫描在调用方协程（IO）执行；本模块不碰主线程
 * - 不做内存扫描（内存行为由 /proc 枚举 + 行为监控模块互补承担）
 *
 * 特征库格式（纯文本，易做增量差分）：
 * - sha256.lst：每行 `sha256|家族名|威胁等级(SUPER/HIGH/RISK)`
 * - rules.txt：自定义 YARA 风格规则，每行
 *   `规则名|威胁等级|any/all|特征串1;特征串2;...`
 *   特征串为 APK 内 DEX/资源中的可见字符串（锁机/C2/恶意无障碍标记），
 *   自定义规则优先级高于哈希特征（先判规则）。
 */
object LocalAvScannerManager : ScanEngine {

    override val id = "local_av"
    override val displayName = "LovelaceAV 本地引擎"

    private const val DIR_NAME = "avdb"
    private const val HASH_FILE = "sha256.lst"
    private const val RULE_FILE = "rules.txt"

    /** 引擎状态（UI 展示） */
    enum class State(val label: String) {
        READY("就绪"), NO_DB("特征库缺失"), DISABLED("已关闭"), ERROR("初始化失败")
    }

    @Volatile var state: State = State.NO_DB
        private set

    data class HashSig(val family: String, val severity: String)
    data class Rule(val name: String, val severity: String, val matchAll: Boolean, val patterns: List<String>)
    data class Match(val kind: String, val name: String, val severity: String, val detail: String)

    private val hashDb = HashMap<String, HashSig>()
    private val rules = ArrayList<Rule>()

    /** 最近一次各包名的引擎命中（病毒详情面板展示用） */
    val lastMatches = mutableStateMapOf<String, List<Match>>()

    private var dbDir: File? = null

    /** 应用启动时调用：加载外置特征库；失败静默降级 */
    fun init(context: Context) {
        dbDir = File(context.filesDir, DIR_NAME)
        reload()
    }

    override fun isAvailable(context: Context): Boolean =
        Prefs.localAvEnabled && state == State.READY

    /** 重新加载特征库（下载/清空后调用） */
    @Synchronized
    fun reload() {
        if (!Prefs.localAvEnabled) { state = State.DISABLED; return }
        val dir = dbDir ?: run { state = State.ERROR; return }
        val hf = File(dir, HASH_FILE)
        val rf = File(dir, RULE_FILE)
        if (!hf.exists() && !rf.exists()) {
            hashDb.clear(); rules.clear()
            state = State.NO_DB
            return
        }
        try {
            hashDb.clear()
            hf.takeIf { it.exists() }?.forEachLine { line ->
                val p = line.trim()
                if (p.isEmpty() || p.startsWith("#")) return@forEachLine
                val parts = p.split("|")
                if (parts.size >= 3 && parts[0].length == 64) {
                    hashDb[parts[0].lowercase()] = HashSig(parts[1], parts[2].uppercase())
                }
            }
            rules.clear()
            rf.takeIf { it.exists() }?.forEachLine { line ->
                val p = line.trim()
                if (p.isEmpty() || p.startsWith("#")) return@forEachLine
                val parts = p.split("|")
                if (parts.size >= 4) {
                    rules.add(Rule(
                        parts[0], parts[1].uppercase(),
                        parts[2].equals("all", true),
                        parts[3].split(";").map { it.trim() }.filter { it.isNotEmpty() }
                    ))
                }
            }
            state = State.READY
            SecurityJournal.log("本地AV", "特征库加载完成：哈希 ${hashDb.size} 条，规则 ${rules.size} 条")
        } catch (e: Throwable) {
            state = State.ERROR
            SecurityJournal.log("本地AV", "特征库加载失败：${e.message}")
        }
    }

    /** 清空特征库（设置页） */
    fun clearDb() {
        try { dbDir?.deleteRecursively(); dbDir?.mkdirs() } catch (e: Throwable) { }
        hashDb.clear(); rules.clear()
        reload()
        SecurityJournal.log("本地AV", "特征库已清空")
    }

    /** 下载/更新特征库（后台；url 为空返回 false）。支持 zip 包或单文件 */
    suspend fun updateDb(context: Context): Boolean = withContext(Dispatchers.IO) {
        val url = Prefs.avdbUrl
        if (url.isEmpty()) return@withContext false
        val dir = (dbDir ?: File(context.filesDir, DIR_NAME).also { dbDir = it }).apply { mkdirs() }
        try {
            val conn = java.net.URI(url).toURL().openConnection() as java.net.HttpURLConnection
            conn.connectTimeout = 10_000; conn.readTimeout = 30_000
            conn.connect()
            if (conn.responseCode != 200) return@withContext false
            val tmp = File(dir, "dl.tmp")
            conn.inputStream.use { inp -> tmp.outputStream().use { inp.copyTo(it) } }
            if (url.endsWith(".zip")) {
                java.util.zip.ZipInputStream(tmp.inputStream()).use { z ->
                    var e = z.nextEntry
                    while (e != null) {
                        if (!e.isDirectory && (e.name.endsWith(HASH_FILE) || e.name.endsWith(RULE_FILE))) {
                            File(dir, e.name.substringAfterLast('/')).outputStream().use { z.copyTo(it) }
                        }
                        z.closeEntry(); e = z.nextEntry
                    }
                }
                tmp.delete()
            } else {
                // 单文件按内容首行格式判定落名
                val first = tmp.bufferedReader().readLine() ?: ""
                val target = if (first.count { it == '|' } >= 3) RULE_FILE else HASH_FILE
                tmp.renameTo(File(dir, target))
            }
            Prefs.avdbUpdatedAt = System.currentTimeMillis()
            reload()
            true
        } catch (e: Throwable) {
            SecurityJournal.log("本地AV", "特征库更新失败：${e.message}")
            false
        }
    }

    // ===== 扫描实现 =====

    override fun scanPackage(context: Context, pkg: PackageInfo): VirusDb.ScanResult? {
        val path = pkg.applicationInfo?.sourceDir ?: return null
        val appName = try {
            pkg.applicationInfo?.loadLabel(context.packageManager)?.toString() ?: pkg.packageName
        } catch (e: Throwable) { pkg.packageName }
        val matches = scanApk(path) ?: return null
        if (matches.isEmpty()) {
            SecurityJournal.runOnMain { lastMatches.remove(pkg.packageName) }
            return null
        }

        SecurityJournal.runOnMain { lastMatches[pkg.packageName] = matches }
        val worst = matches.maxBy { severityRank(it.severity) }
        val level = when (worst.severity) {
            "SUPER" -> VirusDb.ThreatLevel.VIRUS
            "HIGH" -> VirusDb.ThreatLevel.HIGH
            else -> VirusDb.ThreatLevel.MEDIUM
        }
        val reasons = matches.map { "[${displayName}] ${it.name}：${it.detail}" }

        // 超级高危 → 直接联动斩杀状态机：冻结 → 回收无障碍/管理员 → 卸载 + 警报
        var killed = false
        if (worst.severity == "SUPER" && Privilege.isReady) {
            kotlin.concurrent.thread(isDaemon = true) {
                try {
                    Privilege.forceStop(pkg.packageName)
                    Privilege.revokeAccessibility(context, pkg.packageName)
                    killed = Privilege.uninstall(pkg.packageName)
                    NotifHelper.alert(context, "☠️ 本地AV确认超级高危",
                        "$appName 命中「${worst.name}」，已执行斩杀")
                    SecurityJournal.log("斩杀", "本地AV联动斩杀 ${pkg.packageName} 卸载${if (killed) "成功" else "失败"}")
                } catch (e: Throwable) { }
            }
        }
        SecurityJournal.log(
            "本地AV",
            "命中 ${pkg.packageName} 规则=${matches.joinToString(",") { it.name }} 判定=${level.label} 斩杀=${worst.severity == "SUPER"}"
        )
        return VirusDb.ScanResult(
            pkg.packageName, appName, level,
            if (level == VirusDb.ThreatLevel.VIRUS) 98 else 55,
            reasons, pkg.requestedPermissions?.toList() ?: emptyList(),
            false, pkg.versionName, path
        )
    }

    /** 单独扫描一个 APK 文件；null=引擎不可用，empty=干净 */
    fun scanApk(apkPath: String): List<Match>? {
        if (!Prefs.localAvEnabled || state != State.READY) return null
        return try {
            val file = File(apkPath)
            if (!file.exists()) return null
            val matches = ArrayList<Match>()

            // 1. 哈希特征（sha256 整包）
            val sha = sha256(file)
            hashDb[sha]?.let { sig ->
                matches.add(Match("hash", sig.family, sig.severity, "SHA256 命中特征库"))
            }

            // 2. 自定义规则：扫描 DEX/资源可见字符串（优先级高于哈希）
            if (rules.isNotEmpty()) {
                val hay = extractStrings(file, 4 * 1024 * 1024)
                for (rule in rules) {
                    if (rule.patterns.isEmpty()) continue
                    val hit = if (rule.matchAll) rule.patterns.all { hay.contains(it) }
                              else rule.patterns.any { hay.contains(it) }
                    if (hit) {
                        matches.add(Match("rule", rule.name, rule.severity,
                            "自定义规则命中（${if (rule.matchAll) "全部" else "任一"}特征）"))
                    }
                }
            }
            matches
        } catch (e: Throwable) { null }
    }

    private fun sha256(f: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { inp ->
            val buf = ByteArray(64 * 1024)
            var n = inp.read(buf)
            while (n > 0) { md.update(buf, 0, n); n = inp.read(buf) }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    /** 从 APK 的 classes*.dex / resources.arsc 提取可见字符流（总量限 8MB，防大包拖死/OOM） */
    private fun extractStrings(apk: File, maxBytes: Long): String {
        val sb = StringBuilder(512 * 1024)
        var budget = 8 * 1024 * 1024L // 全包总量上限
        ZipFile(apk).use { z ->
            val entries = z.entries()
            while (entries.hasMoreElements() && budget > 0) {
                val e = entries.nextElement()
                val n = e.name
                if (!(n.endsWith(".dex") || n == "resources.arsc" || n.endsWith(".xml"))) continue
                if (e.size > maxBytes) continue
                z.getInputStream(e).use { inp ->
                    val buf = ByteArray(32 * 1024)
                    var r = inp.read(buf)
                    while (r > 0 && budget > 0) {
                        val take = minOf(r.toLong(), budget).toInt()
                        sb.append(String(buf, 0, take, Charsets.ISO_8859_1))
                        budget -= take
                        r = inp.read(buf)
                    }
                }
            }
        }
        return sb.toString()
    }

    private fun severityRank(s: String) = when (s) { "SUPER" -> 3; "HIGH" -> 2; "RISK" -> 1; else -> 0 }
}