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
import com.zhiwei.security.core.AdbShell
import com.zhiwei.security.core.DhizukuManager
import com.zhiwei.security.core.PermissionRevoker
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.core.Privilege
import com.zhiwei.security.core.ShizukuManager
import com.zhiwei.security.core.VirusDb
import com.zhiwei.security.service.NetGuardService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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
    var abuseDetect by remember { mutableStateOf(Prefs.abuseDetectEnabled) }
    var autoRevoke by remember { mutableStateOf(Prefs.autoRevokeEnabled) }
    var revokeStatus by remember { mutableStateOf("") }
    var showAdbDialog by remember { mutableStateOf(false) }
    var adbRefresh by remember { mutableStateOf(0) } // 触发状态重组

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

    // ADB 状态刷新（adbRefresh 变化或进入页面时后台探测一次）
    LaunchedEffect(adbRefresh) {
        withContext(Dispatchers.IO) {
            try { AdbShell.refreshStatus() } catch (e: Throwable) { }
        }
    }

    if (showAdbDialog) {
        AdbActivationDialog(onDismiss = { showAdbDialog = false; adbRefresh++ })
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
            SwitchItem("越权行为检测", "监控冻结/删除系统应用等高危操作，自动恢复并斩杀嫌疑应用", abuseDetect) {
                abuseDetect = it; Prefs.abuseDetectEnabled = it
            }
            SwitchItem("系统权限自动收回", "新装应用的危险权限自动收回（权限白名单豁免）", autoRevoke) {
                autoRevoke = it; Prefs.autoRevokeEnabled = it
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
                            Text("当前提权状态", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                            Text(Privilege.statusText, fontSize = 13.sp, color = Color(0xFF7EC8E3))
                        }
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("系统级提权（android.uid.system）", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                            Text(
                                if (Privilege.isSystemUid) "已生效：当前运行于系统 uid"
                                else "未生效：需安装 system 渠道包（testkey 签名的系统可用）",
                                fontSize = 13.sp, color = Color(0xFF9090A0)
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("本机 ADB 自提权", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                            Text(
                                if (AdbShell.isConnected) "已连接 ${AdbShell.connectedDevice ?: \"\"}"
                                else "未连接 · 开启无线调试后在此配对",
                                fontSize = 13.sp, color = Color(0xFF9090A0)
                            )
                        }
                        TextButton(onClick = { showAdbDialog = true }) {
                            Text(if (AdbShell.isConnected) "重新连接" else "激活", color = Color(0xFFFF6B9D))
                        }
                    }
                    Spacer(modifier = Modifier.height(12.dp))
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
                            TextButton(onClick = {
                                if (DhizukuManager.isReady(context)) {
                                    DhizukuManager.openDhizuku(context)
                                } else {
                                    DhizukuManager.requestPermission { adbRefresh++ }
                                }
                            }) {
                                Text(if (DhizukuManager.isReady(context)) "打开" else "授权", color = Color(0xFFFF6B9D))
                            }
                        }
                    }
                }
            }

            // ===== 通用 =====
            SectionTitle("权限管控")

            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("危险权限收回", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("收回全部非白名单应用的短信/通讯录/录音/定位等危险权限（需提权通道）",
                        fontSize = 13.sp, color = Color(0xFF9090A0))
                    if (revokeStatus.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(revokeStatus, fontSize = 12.sp, color = Color(0xFF7EC8E3))
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Row {
                        TextButton(onClick = { navController.navigate("permissions") }) {
                            Text("权限设置 →", color = Color(0xFF7EC8E3), fontSize = 15.sp)
                        }
                        Spacer(modifier = Modifier.weight(1f))
                        TextButton(
                            enabled = Privilege.isReady,
                            onClick = {
                                revokeStatus = "正在收回…"
                                kotlin.concurrent.thread {
                                    var done = 0; var total = 0
                                    try {
                                        done = PermissionRevoker.revokeAll(context) { d, t, _ -> total = t }
                                    } catch (e: Throwable) { }
                                    revokeStatus = "完成：从 $total 个应用收回 $done 项危险权限"
                                }
                            }
                        ) {
                            Text("立即收回", color = Color(0xFFFF6B9D), fontSize = 15.sp)
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

/**
 * 本机 ADB 自提权激活对话框（LADB 方案）
 * 步骤：设置 → 开发者选项 → 无线调试 → 使用配对码配对设备（拿 IP:配对端口+配对码）
 *      回到无线调试首页拿 IP:连接端口
 */
@Composable
private fun AdbActivationDialog(onDismiss: () -> Unit) {
    var ip by remember { mutableStateOf(Prefs.adbHost.ifEmpty { "127.0.0.1" }) }
    var pairPort by remember { mutableStateOf("") }
    var pairCode by remember { mutableStateOf("") }
    var connectPort by remember { mutableStateOf(if (Prefs.adbPort > 0) Prefs.adbPort.toString() else "") }
    var log by remember { mutableStateOf("1. 打开「无线调试」→「使用配对码配对设备」\n2. 填入 IP / 配对端口 / 配对码，点「配对」\n3. 回到无线调试首页，看「IP 地址和端口」，填入连接端口，点「连接」") }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        containerColor = Color(0xFF1A1A2E),
        title = { Text("本机 ADB 自提权", color = Color.White, fontWeight = FontWeight.Bold) },
        text = {
            Column {
                Text(log, fontSize = 12.sp, color = Color(0xFF9090A0))
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = ip, onValueChange = { ip = it },
                    label = { Text("IP 地址") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = pairPort, onValueChange = { pairPort = it.filter { c -> c.isDigit() } },
                    label = { Text("配对端口（配对弹窗里）") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = pairCode, onValueChange = { pairCode = it.filter { c -> c.isDigit() } },
                    label = { Text("配对码（6位）") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = connectPort, onValueChange = { connectPort = it.filter { c -> c.isDigit() } },
                    label = { Text("连接端口（无线调试首页）") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            Row {
                TextButton(
                    enabled = !busy && pairPort.isNotEmpty() && pairCode.isNotEmpty(),
                    onClick = {
                        busy = true
                        scope.launch {
                            val (ok, out) = withContext(Dispatchers.IO) {
                                AdbShell.pair(ip, pairPort.toIntOrNull() ?: 0, pairCode)
                            }
                            log = if (ok) "✅ 配对成功，继续点「连接」" else "❌ 配对失败：$out"
                            busy = false
                        }
                    }
                ) { Text("配对") }
                TextButton(
                    enabled = !busy && connectPort.isNotEmpty(),
                    onClick = {
                        busy = true
                        scope.launch {
                            val (ok, out) = withContext(Dispatchers.IO) {
                                AdbShell.connect(ip, connectPort.toIntOrNull() ?: 0)
                            }
                            log = if (ok) "✅ 已连接，提权通道就绪" else "❌ 连接失败：$out"
                            busy = false
                            if (ok) onDismiss()
                        }
                    }
                ) { Text("连接") }
            }
        },
        dismissButton = {
            TextButton(enabled = !busy, onClick = onDismiss) { Text("关闭") }
        }
    )
}