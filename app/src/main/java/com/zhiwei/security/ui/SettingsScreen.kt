package com.zhiwei.security.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import com.zhiwei.security.core.DhizukuManager
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.core.ShizukuManager
import com.zhiwei.security.core.VirusDb
import com.zhiwei.security.service.NetGuardService
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(navController: NavController) {
    val context = LocalContext.current

    var intercept by remember { mutableStateOf(Prefs.interceptEnabled) }
    var volumeGuard by remember { mutableStateOf(Prefs.volumeGuardEnabled) }
    var a11yGuard by remember { mutableStateOf(Prefs.a11yGuardEnabled) }
    var installScan by remember { mutableStateOf(Prefs.installScanEnabled) }
    var netGuard by remember { mutableStateOf(Prefs.netGuardEnabled) }
    var hideRecents by remember { mutableStateOf(Prefs.hideRecentsEnabled) }

    // VPN 授权请求
    val vpnLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            Prefs.netGuardEnabled = true
            netGuard = true
            NetGuardService.start(context)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("设置", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF0F0F1A),
                    titleContentColor = Color.White
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
            // ===== 检测与拦截开关 =====
            SectionTitle("检测与拦截")

            SwitchItem("前台应用拦截", "黑名单/恶意应用进入前台时自动强杀并警告", intercept) {
                intercept = it; Prefs.interceptEnabled = it
            }
            SwitchItem("音量键管控", "音量上键三连击斩杀全部第三方应用；检测软件恶意拉满音量", volumeGuard) {
                volumeGuard = it; Prefs.volumeGuardEnabled = it
            }
            SwitchItem("无障碍霸占管控", "检测霸屏锁机行为，自动斩杀并吊销其无障碍权限", a11yGuard) {
                a11yGuard = it; Prefs.a11yGuardEnabled = it
            }
            SwitchItem("安装后自动扫描", "新应用安装完成后立即进行风险分析", installScan) {
                installScan = it; Prefs.installScanEnabled = it
            }
            SwitchItem("后台网络拦截", "VPN 黑洞模式：切断被拦截应用的一切网络连接（系统应用豁免）", netGuard) { want ->
                if (want) {
                    val intent = VpnService.prepare(context)
                    if (intent != null) {
                        vpnLauncher.launch(intent)
                    } else {
                        Prefs.netGuardEnabled = true; netGuard = true
                        NetGuardService.start(context)
                    }
                } else {
                    Prefs.netGuardEnabled = false; netGuard = false
                    NetGuardService.stop(context)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // ===== 自我防护 =====
            SectionTitle("自我防护")

            SwitchItem("隐藏后台卡片", "在最近任务列表中隐藏，防止被手动划掉杀掉", hideRecents) {
                hideRecents = it; Prefs.hideRecentsEnabled = it
            }

            // ===== 提权状态 =====
            SectionTitle("提权通道")

            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Shizuku", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                            Text(ShizukuManager.statusText, fontSize = 13.sp, color = Color(0xFF9090A0))
                        }
                        if (!ShizukuManager.isReady && ShizukuManager.isBinderAlive) {
                            TextButton(onClick = { ShizukuManager.requestPermission { } }) {
                                Text("授权", color = Color(0xFFFF6B9D))
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Dhizuku（设备所有者）", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                            Text(DhizukuManager.statusText(context), fontSize = 13.sp, color = Color(0xFF9090A0))
                        }
                        if (DhizukuManager.isInstalled(context)) {
                            TextButton(onClick = { DhizukuManager.openDhizuku(context) }) {
                                Text("打开", color = Color(0xFFFF6B9D))
                            }
                        }
                    }
                }
            }

            // ===== 通用 =====
            SectionTitle("通用")

            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    TextButton(onClick = { navController.navigate("permissions") }) {
                        Text("权限设置 →", color = Color(0xFF7EC8E3), fontSize = 15.sp)
                    }
                }
            }

            // ===== 病毒库信息 =====
            SectionTitle("病毒库")

            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    StatRow("恶意包名", "${VirusDb.maliciousPackages.size} 条")
                    StatRow("危险权限特征", "${VirusDb.dangerousPermissions.size} 条")
                    StatRow("高危权限组合", "${VirusDb.dangerousCombos.size} 组")
                    StatRow("恶意签名", "${VirusDb.maliciousSignatures.size} 条")
                    val lastScan = Prefs.lastScanTime
                    StatRow("上次扫描", if (lastScan > 0)
                        SimpleDateFormat("MM-dd HH:mm", Locale.getDefault()).format(Date(lastScan))
                    else "从未扫描")
                    StatRow("上次结果", "扫描 ${Prefs.lastScanAppCount} 应用 / 威胁 ${Prefs.lastScanThreatCount} 个")
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
            Text(
                "知微安全 v1.1 · 见微知著",
                fontSize = 12.sp,
                color = Color(0xFF606070),
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

@Composable
private fun SectionTitle(title: String) {
    Text(
        title,
        fontSize = 14.sp,
        fontWeight = FontWeight.Bold,
        color = Color(0xFFFF6B9D),
        modifier = Modifier.padding(vertical = 8.dp)
    )
}

@Composable
private fun SwitchItem(title: String, desc: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(title, fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                Spacer(modifier = Modifier.height(4.dp))
                Text(desc, fontSize = 13.sp, color = Color(0xFF9090A0))
            }
            Switch(
                checked = checked,
                onCheckedChange = onChange,
                colors = SwitchDefaults.colors(
                    checkedTrackColor = Color(0xFFFF6B9D),
                    checkedThumbColor = Color.White
                )
            )
        }
    }
}

@Composable
private fun StatRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, fontSize = 14.sp, color = Color(0xFF9090A0))
        Text(value, fontSize = 14.sp, color = Color.White)
    }
}