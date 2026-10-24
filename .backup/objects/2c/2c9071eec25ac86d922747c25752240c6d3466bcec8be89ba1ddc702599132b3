package com.zhiwei.security.ui

import android.content.Intent
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.service.ProtectService
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(navController: NavController) {
    val context = LocalContext.current
    var protectOn by remember { mutableStateOf(Prefs.protectOn) }
    val lastScanTime = remember { Prefs.lastScanTime }
    val lastThreatCount = remember { Prefs.lastScanThreatCount }
    val lastAppCount = remember { Prefs.lastScanAppCount }

    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f, targetValue = 1.05f,
        animationSpec = infiniteRepeatable(tween(1500), RepeatMode.Reverse),
        label = "pulse"
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("知微安全", fontWeight = FontWeight.Bold) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                ),
                actions = {
                    IconButton(onClick = { navController.navigate("settings") }) {
                        Icon(Icons.Default.Settings, "设置")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(32.dp))

            // 安全状态圆环
            Box(
                modifier = Modifier
                    .size(180.dp)
                    .scale(if (protectOn) pulseScale else 1f)
                    .clip(CircleShape)
                    .background(
                        if (protectOn)
                            Brush.radialGradient(listOf(Color(0xFF4CAF50), Color(0xFF2E7D32)))
                        else
                            Brush.radialGradient(listOf(Color(0xFFF44336), Color(0xFFC62828)))
                    ),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = if (protectOn) "🛡️" else "⚠️",
                        fontSize = 40.sp
                    )
                    Text(
                        text = if (protectOn) "已防护" else "未防护",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 18.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // 上次扫描信息
            if (lastScanTime > 0) {
                val sdf = SimpleDateFormat("MM-dd HH:mm", Locale.getDefault())
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("上次扫描: ${sdf.format(Date(lastScanTime))}", fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text("扫描 $lastAppCount 个应用，发现 $lastThreatCount 个威胁", fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }

            Spacer(modifier = Modifier.height(32.dp))

            // 功能入口
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                FeatureButton("🔍", "病毒扫描", Color(0xFF4CAF50)) {
                    navController.navigate("scan")
                }
                FeatureButton("📱", "应用管理", Color(0xFF2196F3)) {
                    navController.navigate("apps")
                }
                FeatureButton("🛡️", "防护设置", Color(0xFFFF9800)) {
                    navController.navigate("protect")
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // 一键防护开关
            Button(
                onClick = {
                    protectOn = !protectOn
                    Prefs.protectOn = protectOn
                    if (protectOn) {
                        context.startForegroundService(Intent(context, ProtectService::class.java))
                    } else {
                        context.stopService(Intent(context, ProtectService::class.java))
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                shape = RoundedCornerShape(28.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (protectOn) Color(0xFFF44336) else Color(0xFF4CAF50)
                )
            ) {
                Text(
                    text = if (protectOn) "关闭防护" else "开启防护",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

@Composable
fun FeatureButton(icon: String, label: String, color: Color, onClick: () -> Unit) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Card(
            onClick = onClick,
            modifier = Modifier.size(80.dp),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.15f))
        ) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Text(icon, fontSize = 32.sp)
            }
        }
        Spacer(modifier = Modifier.height(8.dp))
        Text(label, fontSize = 13.sp, fontWeight = FontWeight.Medium)
    }
}