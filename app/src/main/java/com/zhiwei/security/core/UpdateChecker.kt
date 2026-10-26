package com.zhiwei.security.core

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * 软件更新检查（GitHub Releases）+ 应用内下载 + 调起安装
 */
object UpdateChecker {

    private const val API =
        "https://api.github.com/repos/mingxiozsg-star/zhiwei-security/releases/latest"

    data class ReleaseInfo(
        val tag: String,
        val name: String,
        val changelog: String,
        val apkUrl: String?,
        val apkSize: Long
    )

    /** 检查更新：返回最新 Release；无网络/解析失败返回 null */
    fun check(): ReleaseInfo? {
        return try {
            val conn = URL(API).openConnection() as HttpURLConnection
            conn.connectTimeout = 10_000
            conn.readTimeout = 10_000
            conn.setRequestProperty("Accept", "application/vnd.github+json")
            conn.setRequestProperty("User-Agent", "zhiwei-security")
            if (conn.responseCode != 200) return null
            val body = conn.inputStream.bufferedReader().readText()
            val json = JSONObject(body)
            val assets = json.getJSONArray("assets")
            var apkUrl: String? = null
            var apkSize = 0L
            for (i in 0 until assets.length()) {
                val a = assets.getJSONObject(i)
                if (a.getString("name") == "app-normal-release.apk") {
                    apkUrl = a.getString("browser_download_url")
                    apkSize = a.getLong("size")
                    break
                }
            }
            ReleaseInfo(
                tag = json.getString("tag_name"),
                name = json.optString("name", json.getString("tag_name")),
                changelog = json.optString("body", ""),
                apkUrl = apkUrl,
                apkSize = apkSize
            )
        } catch (e: Throwable) { null }
    }

    /** 版本比较：latest 是否比 current 新（支持 v1.3.0 / 1.3.0 格式） */
    fun isNewer(latest: String, current: String): Boolean {
        fun parts(v: String) = v.trimStart('v', 'V').split(".")
            .map { it.filter { c -> c.isDigit() }.toIntOrNull() ?: 0 }
        val l = parts(latest); val c = parts(current)
        for (i in 0 until maxOf(l.size, c.size)) {
            val lv = l.getOrElse(i) { 0 }; val cv = c.getOrElse(i) { 0 }
            if (lv != cv) return lv > cv
        }
        return false
    }

    /** 最近一次下载失败原因（UI 展示用） */
    @Volatile var lastError: String? = null
        private set

    /** GitHub 直连不稳定时的加速镜像（逐个回退） */
    private fun mirrorUrls(url: String): List<String> = listOf(
        url,
        "https://ghfast.top/$url",
        "https://gh-proxy.com/$url",
        "https://mirror.ghproxy.com/$url"
    )

    /**
     * 应用内下载 APK：多镜像回退 + 每镜像 2 次重试 + Range 断点续传
     * 返回下载完成的文件，失败返回 null（失败原因写入 lastError）
     */
    fun download(context: Context, url: String, onProgress: (Int) -> Unit): File? {
        lastError = null
        val dir = File(context.cacheDir, "updates").apply { mkdirs() }
        val file = File(dir, "zhiwei-update.apk")
        val errors = mutableListOf<String>()

        for (mirror in mirrorUrls(url)) {
            for (attempt in 1..2) {
                try {
                    val existing = if (attempt > 1 && file.exists()) file.length() else 0L
                    val conn = URL(mirror).openConnection() as HttpURLConnection
                    conn.connectTimeout = 20_000
                    conn.readTimeout = 60_000
                    conn.setRequestProperty("User-Agent", "zhiwei-security")
                    conn.instanceFollowRedirects = true
                    if (existing > 0) conn.setRequestProperty("Range", "bytes=$existing-")

                    val code = conn.responseCode
                    if (code == 416) { file.delete(); continue }          // 范围失效，从头来
                    if (code != 200 && code != 206) {
                        errors.add("HTTP $code")
                        break                                             // 此镜像不可用，换下一个
                    }
                    val append = code == 206 && existing > 0
                    val total = conn.contentLengthLong + (if (append) existing else 0L)

                    conn.inputStream.use { input ->
                        (if (append) FileOutputStream(file, true) else FileOutputStream(file)).use { output ->
                            val buf = ByteArray(64 * 1024)
                            var downloaded = if (append) existing else 0L
                            while (true) {
                                val n = input.read(buf)
                                if (n < 0) break
                                output.write(buf, 0, n)
                                downloaded += n
                                if (total > 0) onProgress(((downloaded * 100) / total).toInt().coerceAtMost(100))
                            }
                            // 完整性校验：连接中途断开 read 会返回 -1，没下完的 APK 不能算成功
                            if (total > 0 && downloaded < total) {
                                throw java.io.IOException("下载不完整 $downloaded/$total")
                            }
                        }
                    }
                    onProgress(100)
                    return file
                } catch (e: Throwable) {
                    errors.add("${mirror.substringAfter("://").substringBefore("/")}: ${e.javaClass.simpleName}")
                }
            }
        }
        lastError = errors.lastOrNull() ?: "未知网络错误"
        return null
    }

    /** 调起系统安装器（Android 8+ 先检查「安装未知应用」权限并引导授权） */
    fun install(context: Context, apk: File) {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O &&
            !context.packageManager.canRequestPackageInstalls()) {
            context.startActivity(
                Intent(
                    android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:${context.packageName}")
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
            return
        }
        val uri: Uri = FileProvider.getUriForFile(
            context, "com.zhiwei.security.fileprovider", apk
        )
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(intent)
    }
}