package com.zhiwei.security.ui

import android.content.Intent
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
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
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.core.Privilege
import com.zhiwei.security.core.ShizukuManager
import com.zhiwei.security.dhizuku.ZhiweiDAReceiver
import com.zhiwei.security.service.ProtectService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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
    val scope = rememberCoroutineScope()
    var protectOn by remember { mutableStateOf(Prefs.protectOn) }
    var authRefresh by remember { mutableStateOf(0) }
    // 扫描信息不用 remember 缓存：从扫描页返回时取到的是最新值
    val lastScanTime = Prefs.lastScanTime
    val lastThreatCount = Prefs.lastScanThreatCount
    val lastAppCount = Prefs.lastScanAppCount

    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f, targetValue = 1.04f,
        animationSpec = infiniteRepeatable(tween(1600), RepeatMode.Reverse),
        label = "pulse"
    )

    // 入场动画：整页淡入+上移
    var entered by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { entered = true }
    val enterAlpha by animateFloatAsState(if (entered) 1f else 0f, tween(500), label = "enterA")
    val enterOffset by animateFloatAsState(if (entered) 0f else 40f, tween(500), label = "enterO")

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
                .graphicsLayer { alpha = enterAlpha; translationY = enterOffset }
                .padding(horizontal = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(12.dp))

            // Hero 横幅：蓝色安全渐变 + 防护状态环（开启/未开启）
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(24.dp))
                    .background(
                        Brush.linearGradient(listOf(Color(0xFF4A6CF7), Color(0xFF1E3FA8)))
                    )
                    .padding(20.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("知微，守护你的安全", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date()) +
                                "  ·  " + if (protectOn) "实时防护运行中" else "防护未开启",
                            fontSize = 13.sp, color = Color(0xFFD8E2FF)
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(Privilege.statusText, fontSize = 11.sp, color = Color(0xFFAEC4FF))
                    }
                    Spacer(modifier = Modifier.width(14.dp))
                    // 状态环：开启 = 满圈粉环，未开启 = 1/4 圈灰白环
                    Box(
                        modifier = Modifier
                            .size(88.dp)
                            .scale(if (protectOn) pulseScale else 1f),
                        contentAlignment = Alignment.Center
                    ) {
                        Canvas(modifier = Modifier.fillMaxSize()) {
                            val sw = 7.dp.toPx()
                            val r = (size.minDimension - sw) / 2f
                            val tl = androidx.compose.ui.geometry.Offset(
                                (size.width - r * 2f) / 2f, (size.height - r * 2f) / 2f
                            )
                            val sz = androidx.compose.ui.geometry.Size(r * 2f, r * 2f)
                            drawArc(
                                color = Color(0x40FFFFFF),
                                startAngle = -90f, sweepAngle = 360f, useCenter = false,
                                topLeft = tl, size = sz,
                                style = Stroke(width = sw, cap = StrokeCap.Round)
                            )
                            drawArc(
                                color = if (protectOn) Color(0xFFFF6B9D) else Color(0xB3FFFFFF),
                                startAngle = -90f, sweepAngle = if (protectOn) 360f else 100f,
                                useCenter = false, topLeft = tl, size = sz,
                                style = Stroke(width = sw, cap = StrokeCap.Round)
                            )
                        }
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(if (protectOn) "🛡️" else "💤", fontSize = 22.sp)
                            Text(
                                text = if (protectOn) "防护中" else "未开启",
                                color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp
                            )
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

            // ===== 提权授权快捷卡：Shizuku / Dhizuku =====
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = CardDark)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("提权授权", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color.White)
                    Text("授权后解锁强杀/卸载/权限收回等全部能力", fontSize = 11.sp, color = TextGray)
                    Spacer(modifier = Modifier.height(10.dp))
                    @Suppress("UNUSED_EXPRESSION") authRefresh
                    var authMsg by remember { mutableStateOf("") }
                    var authBusy by remember { mutableStateOf(false) }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        // Shizuku
                        val shizukuOk = ShizukuManager.isReady
                        Card(
                            onClick = {
                                when {
                                    shizukuOk -> authMsg = "Shizuku 已授权，无需操作"
                                    ShizukuManager.isBinderAlive -> ShizukuManager.requestPermission { authRefresh++ }
                                    else -> authMsg = "Shizuku 未运行：它是独立特权进程，任何应用都无法内嵌；本机 ADB 通道（uid 2000 shell）能力与之完全等价，在提权中心一键连接即可"
                                }
                            },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(12.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFF23233D))
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text("🔐 Shizuku", fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color.White)
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    if (shizukuOk) "✅ 已授权" else if (ShizukuManager.isBinderAlive) "点击授权" else "未运行 · 点说明",
                                    fontSize = 11.sp,
                                    color = if (shizukuOk) Color(0xFF9CCC65) else Ice
                                )
                            }
                        }
                        // Dhizuku（内置服务端·设备所有者）
                        val ownerOk = ZhiweiDAReceiver.isDeviceOwner(context)
                        Card(
                            onClick = {
                                when {
                                    ownerOk -> authMsg = "Dhizuku 设备所有者已激活，无需操作"
                                    authBusy -> { }
                                    Privilege.isReady -> {
                                        authBusy = true
                                        authMsg = "正在激活设备所有者…"
                                        scope.launch {
                                            val r = withContext(Dispatchers.IO) {
                                                Privilege.exec("dpm set-device-owner com.zhiwei.security/.dhizuku.ZhiweiDAReceiver")
                                            }
                                            authMsg = if (r.first == 0) "✅ 设备所有者激活成功"
                                                else "❌ 激活失败：${r.second.take(80)}（设备已有账号时需先在系统设置移除账号）"
                                            authBusy = false
                                            authRefresh++
                                        }
                                    }
                                    else -> authMsg = "需先连接提权通道（本机 ADB / Root）后才能激活"
                                }
                            },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(12.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFF23233D))
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text("👑 Dhizuku", fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color.White)
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    if (ownerOk) "✅ 已激活" else if (authBusy) "激活中…" else if (Privilege.isReady) "一键激活" else "需提权 · 点说明",
                                    fontSize = 11.sp,
                                    color = if (ownerOk) Color(0xFF9CCC65) else Pink
                                )
                            }
                        }
                    }
                    if (authMsg.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(authMsg, fontSize = 11.sp, color = Ice, lineHeight = 15.sp)
                    }
                }
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
            Text("见微知著 · 狂按音量键紧急斩杀（无障碍 3 连击 / 2 秒内上下交替 5 次）", fontSize = 11.sp, color = Color(0xFF606070))
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