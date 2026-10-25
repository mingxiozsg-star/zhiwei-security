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

    /**
     * 应用内下载 APK（流式写盘），onProgress(0..100)
     * 返回下载完成的文件，失败返回 null
     */
    fun download(context: Context, url: String, onProgress: (Int) -> Unit): File? {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 15_000
            conn.readTimeout = 30_000
            conn.setRequestProperty("User-Agent", "zhiwei-security")
            conn.instanceFollowRedirects = true
            if (conn.responseCode != 200) return null
            val total = conn.contentLengthLong
            val dir = File(context.cacheDir, "updates").apply { mkdirs() }
            val file = File(dir, "zhiwei-update.apk")
            conn.inputStream.use { input ->
                FileOutputStream(file).use { output ->
                    val buf = ByteArray(64 * 1024)
                    var downloaded = 0L
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        output.write(buf, 0, n)
                        downloaded += n
                        if (total > 0) onProgress(((downloaded * 100) / total).toInt())
                    }
                }
            }
            file
        } catch (e: Throwable) { null }
    }

    /** 调起系统安装器 */
    fun install(context: Context, apk: File) {
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