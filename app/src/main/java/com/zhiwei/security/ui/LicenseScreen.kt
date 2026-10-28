package com.zhiwei.security.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController

/**
 * 开源许可：内置组件声明 + Apache-2.0 全文 + 已修改文件清单
 * （与游龙护盾「项目声明/开源许可」对齐，Shizuku 为 Apache-2.0 合规随包分发）
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LicenseScreen(navController: NavController) {
    val context = LocalContext.current

    val notice = remember { loadAsset(context, "licenses/notice.txt") ?: "（声明文件缺失）" }
    val apache = remember { loadAsset(context, "licenses/apache-2.0.txt") ?: "（许可全文缺失）" }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("开源许可", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF0F0F1A), titleContentColor = Color.White
                )
            )
        },
        containerColor = Color(0xFF0F0F1A)
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
        ) {
            // 项目声明
            Text("项目声明", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color.White)
            Spacer(Modifier.height(8.dp))
            Text(notice, fontSize = 13.sp, color = Color(0xFFC8C8D8), lineHeight = 20.sp)

            Spacer(Modifier.height(20.dp))

            // 许可全文
            Text("Apache License 2.0 全文", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color.White)
            Text("Shizuku（RikkaApps）—— 应用内嵌服务端依赖", fontSize = 12.sp, color = Color(0xFF9090A0))
            Spacer(Modifier.height(8.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        apache,
                        fontSize = 11.sp, color = Color(0xFFB8B8C8), lineHeight = 15.sp
                    )
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

private fun loadAsset(context: android.content.Context, path: String): String? = try {
    context.assets.open(path).bufferedReader().use { it.readText() }
} catch (e: Throwable) { null }