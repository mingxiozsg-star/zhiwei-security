package com.zhiwei.security.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.zhiwei.security.core.Prefs

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(navController: NavController) {
    val context = LocalContext.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("设置", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "返回")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 20.dp)
        ) {
            Spacer(modifier = Modifier.height(16.dp))

            // 统计信息
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text("统计", fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    Spacer(modifier = Modifier.height(12.dp))
                    StatRow("黑名单应用", "${Prefs.blacklist.size} 个")
                    StatRow("白名单应用", "${Prefs.whitelist.size} 个")
                    StatRow("上次扫描", if (Prefs.lastScanTime > 0) "已完成" else "未扫描")
                    StatRow("发现威胁", "${Prefs.lastScanThreatCount} 个")
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // 病毒库信息
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text("病毒库", fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    Spacer(modifier = Modifier.height(12.dp))
                    StatRow("已知恶意包名", "${com.zhiwei.security.core.VirusDb.maliciousPackages.size} 条")
                    StatRow("危险权限特征", "${com.zhiwei.security.core.VirusDb.dangerousPermissions.size} 条")
                    StatRow("高危权限组合", "${com.zhiwei.security.core.VirusDb.dangerousCombos.size} 组")
                    StatRow("恶意签名特征", "${com.zhiwei.security.core.VirusDb.maliciousSignatures.size} 条")
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // 关于
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text("关于", fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    Spacer(modifier = Modifier.height(12.dp))
                    StatRow("应用名称", "知微安全")
                    StatRow("版本", "1.0.0")
                    StatRow("包名", "com.zhiwei.security")
                }
            }
        }
    }
}

@Composable
fun StatRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, fontSize = 14.sp)
        Text(value, fontSize = 14.sp, fontWeight = FontWeight.Medium)
    }
}