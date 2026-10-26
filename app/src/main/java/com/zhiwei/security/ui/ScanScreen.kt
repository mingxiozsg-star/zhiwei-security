package com.zhiwei.security.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.zhiwei.security.core.AppScanner
import com.zhiwei.security.core.VirusDb
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(navController: NavController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val scanner = remember { AppScanner(context) }

    var isScanning by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0) }
    var totalApps by remember { mutableStateOf(0) }
    var currentApp by remember { mutableStateOf("") }
    var threats by remember { mutableStateOf<List<VirusDb.ScanResult>>(emptyList()) }
    var scanComplete by remember { mutableStateOf(false) }

    Scaffold(
        containerColor = Color(0xFF0F0F1A),
        topBar = {
            TopAppBar(
                title = { Text("病毒扫描", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "返回")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF0F0F1A), titleContentColor = Color.White,
                    navigationIconContentColor = Color.White
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 20.dp)
        ) {
            if (isScanning) {
                // 扫描进度
                Spacer(modifier = Modifier.height(32.dp))
                LinearProgressIndicator(
                    progress = { if (totalApps > 0) progress.toFloat() / totalApps else 0f },
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(16.dp))
                Text("正在扫描: $currentApp", fontSize = 14.sp, color = Color(0xFF9090A0))
                Text("$progress / $totalApps", fontSize = 13.sp, color = Color(0xFF9090A0))
                Spacer(modifier = Modifier.height(24.dp))

                if (threats.isNotEmpty()) {
                    Text("已发现 ${threats.size} 个威胁", fontWeight = FontWeight.Bold, color = Color(0xFFF44336))
                    Spacer(modifier = Modifier.height(12.dp))
                }
            }

            if (scanComplete) {
                Spacer(modifier = Modifier.height(16.dp))
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = if (threats.isEmpty()) Color(0xFF4CAF50).copy(alpha = 0.1f)
                        else Color(0xFFF44336).copy(alpha = 0.1f)
                    )
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = if (threats.isEmpty()) "✅ 未发现威胁" else "⚠️ 发现 ${threats.size} 个威胁",
                            fontWeight = FontWeight.Bold,
                            fontSize = 18.sp,
                            color = if (threats.isEmpty()) Color(0xFF4CAF50) else Color(0xFFF44336)
                        )
                        Text("共扫描 $totalApps 个应用", fontSize = 14.sp, color = Color(0xFF9090A0))
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
            }

            if (!isScanning && !scanComplete) {
                Spacer(modifier = Modifier.height(64.dp))
                Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    Text("🔍", fontSize = 64.sp)
                }
                Spacer(modifier = Modifier.height(24.dp))
                Text(
                    "点击下方按钮开始扫描",
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                    color = Color(0xFF9090A0)
                )
                Spacer(modifier = Modifier.height(32.dp))
            }

            // 威胁列表
            if (threats.isNotEmpty()) {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    items(threats) { threat ->
                        ThreatCard(threat)
                    }
                }
            } else if (scanComplete) {
                Spacer(modifier = Modifier.weight(1f))
            } else {
                Spacer(modifier = Modifier.weight(1f))
            }

            // 扫描按钮
            Button(
                onClick = {
                    isScanning = true
                    scanComplete = false
                    threats = emptyList()
                    progress = 0
                    scope.launch {
                        val result = scanner.scanAllApps { p ->
                            progress = p.current
                            totalApps = p.total
                            currentApp = p.currentApp
                            threats = p.threats
                        }
                        threats = result
                        isScanning = false
                        scanComplete = true
                        // 扫描完成 → 通知栏结果
                        com.zhiwei.security.core.NotifHelper.notify(
                            context,
                            if (result.isEmpty()) "✅ 扫描完成：未发现威胁" else "⚠️ 扫描完成：发现 ${result.size} 个威胁",
                            "共扫描 $totalApps 个应用" + if (result.isNotEmpty())
                                "，最高危：${result.first().appName}（评分 ${result.first().score}）" else ""
                        )
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
                    .padding(bottom = 16.dp),
                shape = RoundedCornerShape(26.dp),
                enabled = !isScanning,
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFF6B9D), contentColor = Color.White)
            ) {
                Text(
                    text = if (isScanning) "扫描中..." else "开始扫描",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

@Composable
fun ThreatCard(threat: VirusDb.ScanResult) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF1A1A2E)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // 风险等级标记
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(
                        when (threat.level) {
                            VirusDb.ThreatLevel.VIRUS -> Color(0xFF9C27B0).copy(alpha = 0.2f)
                            VirusDb.ThreatLevel.HIGH -> Color(0xFFF44336).copy(alpha = 0.2f)
                            VirusDb.ThreatLevel.MEDIUM -> Color(0xFFFF9800).copy(alpha = 0.2f)
                            else -> Color(0xFF8BC34A).copy(alpha = 0.2f)
                        }
                    ),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = when (threat.level) {
                        VirusDb.ThreatLevel.VIRUS -> "☠️"
                        VirusDb.ThreatLevel.HIGH -> "🔴"
                        VirusDb.ThreatLevel.MEDIUM -> "🟡"
                        else -> "🟢"
                    },
                    fontSize = 24.sp
                )
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(threat.appName, fontWeight = FontWeight.Bold, fontSize = 15.sp, color = Color.White)
                Text(threat.packageName, fontSize = 12.sp, color = Color(0xFF9090A0))
                if (threat.reasons.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        threat.reasons.joinToString("；"),
                        fontSize = 11.sp,
                        color = Color(0xFFF44336)
                    )
                }

                // 本地 AV 引擎核验区块
                com.zhiwei.security.core.LocalAvScannerManager.lastMatches[threat.packageName]?.let { matches ->
                    Spacer(modifier = Modifier.height(6.dp))
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(Color(0xFF12121F))
                            .padding(8.dp)
                    ) {
                        Text("🛡 本地 AV 引擎核验", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF7EC8E3))
                        matches.forEach { m ->
                            Text(
                                "${if (m.kind == "rule") "规则" else "特征"}「${m.name}」 ${m.detail}（${m.severity}）",
                                fontSize = 10.sp, color = Color(0xFFCE93D8)
                            )
                        }
                    }
                }

                // 云端哈希复核区块
                com.zhiwei.security.core.CloudHashVerifier.verdicts[threat.packageName]?.let { v ->
                    Spacer(modifier = Modifier.height(6.dp))
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(Color(0xFF12121F))
                            .padding(8.dp)
                    ) {
                        Text("☁️ 云端核验", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF7EC8E3))
                        Text("SHA256 ${v.sha256.take(16)}…", fontSize = 9.sp, color = Color(0xFF9090A0))
                        v.results.forEach { e ->
                            Text(
                                "${e.engine}：${if (e.malicious) "恶意 · ${e.family}" + (if (e.superHigh) " · 超级高危" else "") else "未检出"}" +
                                    (if (e.tags.isNotEmpty()) " [${e.tags.joinToString(",")}]" else "") +
                                    " · ${e.timeText}",
                                fontSize = 10.sp,
                                color = if (e.malicious) Color(0xFFF44336) else Color(0xFF8BC34A)
                            )
                        }
                        if (v.triggeredKill) {
                            Text("⚔️ 已触发斩杀", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF9C27B0))
                        }
                    }
                }
            }

            // 风险分数
            Text(
                text = "${threat.score}",
                fontWeight = FontWeight.Bold,
                fontSize = 20.sp,
                color = when (threat.level) {
                    VirusDb.ThreatLevel.VIRUS -> Color(0xFF9C27B0)
                    VirusDb.ThreatLevel.HIGH -> Color(0xFFF44336)
                    VirusDb.ThreatLevel.MEDIUM -> Color(0xFFFF9800)
                    else -> Color(0xFF8BC34A)
                }
            )
        }
    }
}