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
        topBar = {
            TopAppBar(
                title = { Text("病毒扫描", fontWeight = FontWeight.Bold) },
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
            if (isScanning) {
                // 扫描进度
                Spacer(modifier = Modifier.height(32.dp))
                LinearProgressIndicator(
                    progress = { if (totalApps > 0) progress.toFloat() / totalApps else 0f },
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(16.dp))
                Text("正在扫描: $currentApp", fontSize = 14.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text("$progress / $totalApps", fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
                        Text("共扫描 $totalApps 个应用", fontSize = 14.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
                    color = MaterialTheme.colorScheme.onSurfaceVariant
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
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
                    .padding(bottom = 16.dp),
                shape = RoundedCornerShape(26.dp),
                enabled = !isScanning
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
            containerColor = MaterialTheme.colorScheme.surfaceVariant
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
                Text(threat.appName, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                Text(threat.packageName, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (threat.reasons.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        threat.reasons.joinToString("；"),
                        fontSize = 11.sp,
                        color = Color(0xFFF44336)
                    )
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