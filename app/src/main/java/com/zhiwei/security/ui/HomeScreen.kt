package com.zhiwei.security.ui

import android.content.Intent
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
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
import com.zhiwei.security.core.Privilege
import com.zhiwei.security.service.ProtectService
import java.text.SimpleDateFormat
import java.util.*

private val BgDark = Color(0xFF0F0F1A)
private val CardDark = Color(0xFF1A1A2E)
private val Pink = Color(0xFFFF6B9D)
private val Ice = Color(0xFF7EC8E3)
private val TextGray = Color(0xFF9090A0)

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
        initialValue = 1f, targetValue = 1.04f,
        animationSpec = infiniteRepeatable(tween(1600), RepeatMode.Reverse),
        label = "pulse"
    )

    Scaffold(
        containerColor = BgDark,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("知微安全", fontWeight = FontWeight.Bold, color = Color.White)
                        Text("zhiwei security", fontSize = 11.sp, color = Pink)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = BgDark),
                actions = {
                    IconButton(onClick = { navController.navigate("settings") }) {
                        Icon(Icons.Default.Settings, "设置", tint = Color.White)
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(16.dp))

            // 安全状态圆环（品牌渐变）
            Box(
                modifier = Modifier
                    .size(172.dp)
                    .scale(if (protectOn) pulseScale else 1f)
                    .clip(CircleShape)
                    .background(
                        if (protectOn)
                            Brush.radialGradient(listOf(Color(0xFFFF6B9D), Color(0xFF7EC8E3)))
                        else
                            Brush.radialGradient(listOf(Color(0xFF3A3A55), Color(0xFF23233D)))
                    ),
                contentAlignment = Alignment.Center
            ) {
                Box(
                    modifier = Modifier
                        .size(140.dp)
                        .clip(CircleShape)
                        .background(BgDark),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(if (protectOn) "🛡️" else "💤", fontSize = 36.sp)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = if (protectOn) "防护中" else "未开启",
                            color = if (protectOn) Pink else TextGray,
                            fontWeight = FontWeight.Bold,
                            fontSize = 17.sp
                        )
                        if (protectOn) {
                            Text(Privilege.statusText, fontSize = 10.sp, color = Ice)
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

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
                    .height(52.dp),
                shape = RoundedCornerShape(26.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (protectOn) Color(0xFF3A3A55) else Pink,
                    contentColor = Color.White
                )
            ) {
                Text(
                    text = if (protectOn) "关闭防护" else "开启防护",
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            Spacer(modifier = Modifier.height(20.dp))

            // 功能宫格 2x3
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                HomeTile("🔍", "病毒扫描", Modifier.weight(1f)) { navController.navigate("scan") }
                HomeTile("📱", "应用管理", Modifier.weight(1f)) { navController.navigate("apps") }
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                HomeTile("🛡️", "防护设置", Modifier.weight(1f)) { navController.navigate("protect") }
                HomeTile("🔑", "授权管理", Modifier.weight(1f)) { navController.navigate("auth") }
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                HomeTile("⚡", "提权中心", Modifier.weight(1f)) { navController.navigate("privilege") }
                HomeTile("ℹ️", "关于我们", Modifier.weight(1f)) { navController.navigate("about") }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // 上次扫描信息
            if (lastScanTime > 0) {
                val sdf = SimpleDateFormat("MM-dd HH:mm", Locale.getDefault())
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = CardDark)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text("上次扫描 · ${sdf.format(Date(lastScanTime))}",
                            fontSize = 12.sp, color = TextGray)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text("扫描 $lastAppCount 个应用 · 发现 $lastThreatCount 个威胁",
                            fontSize = 13.sp,
                            color = if (lastThreatCount > 0) Color(0xFFFF6B6B) else Ice)
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
            Text("见微知著 · 狂按音量键 3 次紧急斩杀", fontSize = 11.sp, color = Color(0xFF606070))
            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun HomeTile(icon: String, label: String, modifier: Modifier, onClick: () -> Unit) {
    Card(
        onClick = onClick,
        modifier = modifier.height(92.dp),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = CardDark)
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(14.dp),
            verticalArrangement = Arrangement.Center
        ) {
            Text(icon, fontSize = 26.sp)
            Spacer(modifier = Modifier.height(6.dp))
            Text(label, fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color.White)
        }
    }
}