package com.zhiwei.security.core

import android.content.Context
import androidx.compose.runtime.mutableStateListOf
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 琐记日志（安全事件流水）
 *
 * 内存环形缓冲（Compose 可观察，UI 直接订阅）+ 追加写文件持久化。
 * 记录：哈希复核、本地 AV 命中、斩杀联动等关键安全事件。
 */
object SecurityJournal {

    data class Entry(
        val time: Long,
        val category: String,   // 云端复核 / 本地AV / 斩杀 / ...
        val message: String
    ) {
        val timeText: String
            get() = SimpleDateFormat("MM-dd HH:mm:ss", Locale.getDefault()).format(Date(time))
    }

    private const val MAX_ENTRIES = 500
    private const val FILE_NAME = "security_journal.log"

    val entries = mutableStateListOf<Entry>()

    @Volatile private var logFile: File? = null

    fun init(context: Context) {
        logFile = File(context.filesDir, FILE_NAME)
    }

    @Synchronized
    fun log(category: String, message: String) {
        val e = Entry(System.currentTimeMillis(), category, message)
        // Compose SnapshotState 非线程安全：必须在主线程写
        runOnMain {
            entries.add(0, e)
            while (entries.size > MAX_ENTRIES) entries.removeAt(entries.size - 1)
        }
        try {
            logFile?.appendText("${e.timeText} [$category] $message\n")
        } catch (t: Throwable) { }
    }

    private val mainHandler by lazy { android.os.Handler(android.os.Looper.getMainLooper()) }
    internal fun runOnMain(block: () -> Unit) {
        if (android.os.Looper.myLooper() == android.os.Looper.getMainLooper()) block()
        else mainHandler.post(block)
    }

    fun clear() {
        runOnMain { entries.clear() }
        try { logFile?.delete() } catch (t: Throwable) { }
    }
}