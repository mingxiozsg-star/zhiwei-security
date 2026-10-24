package com.zhiwei.security.ui

import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
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
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.service.GuardService
import com.zhiwei.security.service.KeepAliveReceiver
import com.zhiwei.security.service.ProtectService

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProtectScreen(navController: NavController) {
    val context = LocalContext.current
    var protectOn by remember { mutableStateOf(Prefs.protectOn) }
    var guardOn by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("防护设置", fontWeight = FontWeight.Bold) },
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

            // 主开关卡片
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (protectOn)
                        Color(0xFF4CAF50).copy(alpha = 0.1f)
                    else
                        MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("防锁机守护", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                            Text("实时监控并拦截恶意锁机行为", fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Switch(
                            checked = protectOn,
                            onCheckedChange = { checked ->
                                protectOn = checked
                                Prefs.protectOn = checked
                                if (checked) {
                                    context.startForegroundService(Intent(context, ProtectService::class.java))
                                    context.startForegroundService(Intent(context, GuardService::class.java))
                                    KeepAliveReceiver.setupNextAlarm(context)
                                } else {
                                    context.stopService(Intent(context, ProtectService::class.java))
                                    context.stopService(Intent(context, GuardService::class.java))
                                }
                            }
                        )
                    }

                    if (protectOn) {
                        Spacer(modifier = Modifier.height(16.dp))
                        HorizontalDivider()
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            "✅ 屏幕状态监控\n✅ 黑名单应用拦截\n✅ 新装应用检测\n✅ 权限降级监控\n✅ 双进程互守保活",
                            fontSize = 13.sp,
                            color = Color(0xFF4CAF50),
                            lineHeight = 22.sp
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // 服务状态
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text("服务状态", fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    Spacer(modifier = Modifier.height(12.dp))
                    StatusRow("防护服务", ProtectService.isRunning)
                    StatusRow("守护进程", GuardService.isRunning)
                    StatusRow("定时保活", protectOn)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // 说明
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text("防护说明", fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        "防锁机守护会持续监控设备状态：\n\n" +
                        "• 屏幕关闭时检测是否有恶意应用在锁屏\n" +
                        "• 新安装应用时自动检测是否含锁机高危权限\n" +
                        "• 定期扫描已安装应用中的黑名单/病毒特征\n" +
                        "• 守护进程与主服务互相监视，防止被杀\n" +
                        "• 发现威胁时立即弹出警告并通知",
                        fontSize = 13.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        lineHeight = 20.sp
                    )
                }
            }
        }
    }
}

@Composable
fun StatusRow(label: String, active: Boolean) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, fontSize = 14.sp)
        Text(
            text = if (active) "运行中" else "已停止",
            color = if (active) Color(0xFF4CAF50) else Color(0xFFF44336),
            fontSize = 14.sp,
            fontWeight = FontWeight.Medium
        )
    }
}