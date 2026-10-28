package com.zhiwei.security.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.zhiwei.security.core.SecurityJournal
import java.util.concurrent.Executors

/**
 * 服务日志：提权/斩杀/扫描/云端复核等安全事件流水（与游龙"服务日志"对齐）
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun JournalScreen(navController: NavController) {
    val context = LocalContext.current
    var clearTick by remember { mutableStateOf(0) }
    LaunchedEffect(Unit) { SecurityJournal.init(context) }
    LaunchedEffect(clearTick) { }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("服务日志", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                actions = {
                    TextButton(onClick = {
                        SecurityJournal.clear(); clearTick++
                    }) { Text("清空", color = Color(0xFFFF6B9D)) }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF0F0F1A), titleContentColor = Color.White
                )
            )
        },
        containerColor = Color(0xFF0F0F1A)
    ) { padding ->
        if (SecurityJournal.entries.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = androidx.compose.ui.Alignment.Center
            ) {
                Text("暂无日志", color = Color(0xFF606070), fontSize = 14.sp)
            }
        } else {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .padding(12.dp)
            ) {
                SecurityJournal.entries.forEach { e ->
                    Card(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
                    ) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            Text(
                                "${e.timeText}  [${e.category}]",
                                fontSize = 11.sp, color = Color(0xFF7EC8E3)
                            )
                            Spacer(Modifier.height(2.dp))
                            Text(e.message, fontSize = 13.sp, color = Color(0xFFE8E8F0))
                        }
                    }
                }
            }
        }
    }
}

/** 日志导出到文件（服务日志页长按/设置页用，避免主线程 IO） */
fun exportJournal(context: android.content.Context): String {
    return try {
        val src = java.io.File(context.filesDir, "security_journal.log")
        if (!src.exists()) "无日志文件"
        val dst = java.io.File(context.getExternalFilesDir(null), "security_journal_export.txt")
        Executors.newSingleThreadExecutor().execute {
            try { src.copyTo(dst, overwrite = true) } catch (e: Throwable) { }
        }
        "已导出到 ${dst.absolutePath}"
    } catch (e: Throwable) { "导出失败：${e.message}" }
}