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
import com.zhiwei.security.core.AdbPairing
import com.zhiwei.security.core.AdbShell
import com.zhiwei.security.core.AuthDb
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
    var fileFlood by remember { mutableStateOf(Prefs.fileFloodEnabled) }
    var c2Filter by remember { mutableStateOf(Prefs.c2FilterEnabled) }
    var hideRecents by remember { mutableStateOf(Prefs.hideRecentsEnabled) }
    var abuseDetect by remember { mutableStateOf(Prefs.abuseDetectEnabled) }
    var autoRevoke by remember { mutableStateOf(Prefs.autoRevokeEnabled) }
    var localAv by remember { mutableStateOf(Prefs.localAvEnabled) }
    var cloudRecheck by remember { mutableStateOf(Prefs.cloudRecheckEnabled) }
    var avdbStatus by remember { mutableStateOf("") }
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
            SwitchItem("音量键管控", "无障碍 3 连击（或兜底通道 2 秒内上下交替 5 次）斩杀全部第三方应用；检测软件恶意拉满音量", volumeGuard) {
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
            SwitchItem("文件洪泛检测", "监控公共目录文件暴增，识别持续创建垃圾文件的攻击", fileFlood) {
                fileFlood = it; Prefs.fileFloodEnabled = it
            }
            SwitchItem("C2 服务器封堵", "黑洞路由已知恶意服务器 IP，切断远控木马回连", c2Filter) {
                c2Filter = it; Prefs.c2FilterEnabled = it
                try { NetGuardService.restart(context) } catch (e: Throwable) { }
            }
            SwitchItem("本地离线病毒扫描", "LovelaceAV 引擎二级校验（特征库外置，缺失时自动降级）", localAv) {
                localAv = it; Prefs.localAvEnabled = it
                com.zhiwei.security.core.LocalAvScannerManager.reload()
            }
            SwitchItem("云端哈希复核", "仅可疑样本提交 SHA256 查询（MB/协同平台/VT），不上传样本本体", cloudRecheck) {
                cloudRecheck = it; Prefs.cloudRecheckEnabled = it
            }
            // 特征库管理
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("AV 特征库", fontSize = 15.sp, fontWeight = FontWeight.Medium, color = Color.White)
                    Text(
                        "状态：${com.zhiwei.security.core.LocalAvScannerManager.state.label}" +
                            (if (Prefs.avdbUpdatedAt > 0) " · 更新于 " + SimpleDateFormat("MM-dd HH:mm", Locale.getDefault()).format(Date(Prefs.avdbUpdatedAt)) else ""),
                        fontSize = 12.sp, color = Color(0xFF9090A0)
                    )
                    if (avdbStatus.isNotEmpty()) Text(avdbStatus, fontSize = 12.sp, color = Color(0xFF7EC8E3))
                    Spacer(modifier = Modifier.height(8.dp))
                    Row {
                        TextButton(onClick = {
                            avdbStatus = "更新中…"
                            kotlinx.coroutines.GlobalScope.launch(Dispatchers.IO) {
                                val ok = com.zhiwei.security.core.LocalAvScannerManager.updateDb(context)
                                withContext(Dispatchers.Main) {
                                    avdbStatus = if (ok) "✅ 特征库已更新" else "❌ 更新失败（未配置地址或网络不可用）"
                                }
                            }
                        }) { Text("更新特征库") }
                        TextButton(onClick = {
                            com.zhiwei.security.core.LocalAvScannerManager.clearDb()
                            avdbStatus = "特征库已清空"
                        }) { Text("清空", color = Color(0xFFF44336)) }
                    }
                }
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
            // ===== 提权中心入口 =====
            SectionTitle("提权通道")

            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E)),
                onClick = { navController.navigate("privilege") }
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("提权中心", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text("uid.system / 本机 ADB / Dhizuku 服务端 / Shizuku 一页管理", fontSize = 13.sp, color = Color(0xFF9090A0))
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(Privilege.statusText, fontSize = 13.sp, color = Color(0xFF7EC8E3))
                    }
                    Text("›", fontSize = 28.sp, color = Color(0xFFFF6B9D))
                }
            }


            // ===== 授权管理（知微特权服务） =====
            SectionTitle("授权管理")

            var cmdIntercept by remember { mutableStateOf(AuthDb.cmdInterceptEnabled) }
            var grantedApps by remember { mutableStateOf(AuthDb.grantedApps.toList()) }
            var cmdWhitelist by remember { mutableStateOf(AuthDb.cmdWhitelist.toList()) }

            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("知微特权服务", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("其他应用可申请授权，通过知微的提权通道执行命令（Shizuku 式架构）",
                        fontSize = 13.sp, color = Color(0xFF9090A0))
                    Spacer(modifier = Modifier.height(4.dp))
                    TextButton(onClick = { navController.navigate("auth") }) {
                        Text("手动授权管理（授予/撤销/白名单）→", color = Color(0xFFFF6B9D), fontSize = 14.sp)
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    SwitchItem("危险命令拦截", "已授权应用执行危险命令时弹窗确认（允许一次/不允许/加入白名单）；普通命令不拦截", cmdIntercept) {
                        cmdIntercept = it; AuthDb.cmdInterceptEnabled = it
                    }
                }
            }

            // 已授权应用列表
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("已授权应用（${grantedApps.size}）", fontSize = 16.sp,
                        fontWeight = FontWeight.Medium, color = Color.White)
                    Spacer(modifier = Modifier.height(4.dp))
                    if (grantedApps.isEmpty()) {
                        Text("暂无应用获得授权", fontSize = 13.sp, color = Color(0xFF9090A0))
                    } else {
                        grantedApps.forEach { pkg ->
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    val label = try {
                                        context.packageManager.getApplicationLabel(
                                            context.packageManager.getApplicationInfo(pkg, 0)).toString()
                                    } catch (e: Exception) { pkg }
                                    Text(label, fontSize = 14.sp, color = Color.White)
                                    Text(pkg, fontSize = 12.sp, color = Color(0xFF9090A0))
                                }
                                TextButton(onClick = {
                                    AuthDb.revoke(pkg)
                                    grantedApps = AuthDb.grantedApps.toList()
                                    cmdWhitelist = AuthDb.cmdWhitelist.toList()
                                }) { Text("撤销", color = Color(0xFFFF6B6B), fontSize = 14.sp) }
                            }
                        }
                    }
                }
            }

            // 命令白名单
            if (cmdWhitelist.isNotEmpty()) {
                Card(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("命令白名单（${cmdWhitelist.size}）", fontSize = 16.sp,
                            fontWeight = FontWeight.Medium, color = Color.White)
                        Spacer(modifier = Modifier.height(4.dp))
                        cmdWhitelist.forEach { entry ->
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(entry.replace("|", " → "), fontSize = 12.sp,
                                    color = Color(0xFF9CCC65), modifier = Modifier.weight(1f))
                                TextButton(onClick = {
                                    AuthDb.removeCmdWhitelist(entry)
                                    cmdWhitelist = AuthDb.cmdWhitelist.toList()
                                }) { Text("删除", color = Color(0xFFFF6B6B), fontSize = 13.sp) }
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

            // ===== 关于入口 =====
            SectionTitle("其他")

            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E)),
                onClick = { navController.navigate("about") }
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("关于我们", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text("版本信息 · 软件更新（应用内下载）", fontSize = 13.sp, color = Color(0xFF9090A0))
                    }
                    Text("›", fontSize = 28.sp, color = Color(0xFFFF6B9D))
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
            val verName = remember {
                try { context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "" } catch (e: Exception) { "" }
            }
            Text(
                "知微安全 v$verName · 见微知著",
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
 * 本机 ADB 自提权激活对话框（内置一键配对，Shizuku 同款 mDNS 方案）
 * 默认自动模式：App 自动发现配对/连接端口，用户只需填 6 位配对码。
 * 「手动模式」作为老旧设备/发现失败时的兜底。
 */
@Composable
internal fun AdbActivationDialog(onDismiss: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var pairCode by remember { mutableStateOf("") }
    var log by remember { mutableStateOf("一键激活：\n1. 打开 开发者选项 → 无线调试\n2. 点「使用配对码配对设备」，弹窗别关\n3. 回来填 6 位配对码，点「一键激活」\n（IP/端口自动发现，不用手抄）") }
    var busy by remember { mutableStateOf(false) }
    var manual by remember { mutableStateOf(false) }
    // 手动模式字段
    var ip by remember { mutableStateOf(Prefs.adbHost.ifEmpty { "127.0.0.1" }) }
    var pairPort by remember { mutableStateOf("") }
    var connectPort by remember { mutableStateOf(if (Prefs.adbPort > 0) Prefs.adbPort.toString() else "") }
    val scope = rememberCoroutineScope()

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        containerColor = Color(0xFF1A1A2E),
        title = { Text("本机 ADB 自提权", color = Color.White, fontWeight = FontWeight.Bold) },
        text = {
            Column {
                Text(log, fontSize = 12.sp, color = Color(0xFF9090A0))
                Spacer(modifier = Modifier.height(10.dp))
                if (!manual) {
                    OutlinedTextField(
                        value = pairCode, onValueChange = { pairCode = it.filter { c -> c.isDigit() }.take(6) },
                        label = { Text("配对码（6 位）") }, singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    TextButton(onClick = { manual = true }) {
                        Text("自动发现失败？切手动模式 →", color = Color(0xFF7EC8E3), fontSize = 13.sp)
                    }
                } else {
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
                    TextButton(onClick = { manual = false }) {
                        Text("← 返回一键模式", color = Color(0xFF7EC8E3), fontSize = 13.sp)
                    }
                }
            }
        },
        confirmButton = {
            Row {
                if (!manual) {
                    TextButton(
                        enabled = !busy && pairCode.length == 6,
                        onClick = {
                            busy = true
                            scope.launch {
                                val ok = AdbPairing.autoActivate(context, pairCode) { log = it }
                                busy = false
                                if (ok) onDismiss()
                            }
                        }
                    ) { Text(if (busy) "激活中…" else "一键激活", color = Color(0xFFFF6B9D)) }
                } else {
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
            }
        },
        dismissButton = {
            TextButton(enabled = !busy, onClick = onDismiss) { Text("关闭") }
        }
    )
}
