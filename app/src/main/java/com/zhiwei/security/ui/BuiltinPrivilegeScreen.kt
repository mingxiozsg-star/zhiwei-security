package com.zhiwei.security.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
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
import com.zhiwei.security.core.AuthDb
import com.zhiwei.security.core.BuiltinPrivilege
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.core.Privilege
import com.zhiwei.security.core.SecurityJournal
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 内置特权（Stellar 对标层）控制台
 *
 * 这一页就是「知微作为特权宿主」的总开关面板：
 *  - 服务运行状态 / 运行方式 / 运行时长 / 内核与协议版本
 *  - 激活与配对：无线调试（mDNS 自动发现 + 6 位配对码）、有线 ADB
 *  - 已授权应用：数量 + 逐个撤销 + 进入完整授权管理
 *  - 对外授权：总开关、危险命令拦截、审计日志、给开发者的接入代码
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BuiltinPrivilegeScreen(navController: NavController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var enabled by remember { mutableStateOf(Prefs.builtinPrivilegeEnabled) }
    var autoStart by remember { mutableStateOf(Prefs.builtinAutoStart) }
    var intercept by remember { mutableStateOf(AuthDb.cmdInterceptEnabled) }
    var granted by remember { mutableStateOf(AuthDb.grantedApps) }
    var audit by remember { mutableStateOf(AuthDb.auditLog()) }
    var refresh by remember { mutableStateOf(0) }
    var showAdb by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var log by remember { mutableStateOf("") }
    var showSdk by remember { mutableStateOf(false) }

    // 提权等级的 Compose State 订阅（通道变化自动重绘）
    val level by Privilege.levelState

    LaunchedEffect(refresh) {
        withContext(Dispatchers.IO) {
            try { AdbShell.refreshStatus() } catch (e: Throwable) { }
        }
        enabled = Prefs.builtinPrivilegeEnabled
        granted = AuthDb.grantedApps
        audit = AuthDb.auditLog()
        intercept = AuthDb.cmdInterceptEnabled
    }

    if (showAdb) {
        AdbActivationDialog(onDismiss = { showAdb = false; refresh++ })
    }

    val state = if (enabled) BuiltinPrivilege.state() else BuiltinPrivilege.State.STOPPED

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("内置特权", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF0F0F1A), titleContentColor = Color.White)
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
            // ===== 主状态卡 =====
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("⚡", fontSize = 26.sp)
                        Spacer(Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text("知微内置特权服务", fontSize = 17.sp,
                                fontWeight = FontWeight.Bold, color = Color.White)
                            Text(
                                when (state) {
                                    BuiltinPrivilege.State.RUNNING -> "● 运行中"
                                    BuiltinPrivilege.State.NO_PRIVILEGE -> "● 已开启·等待提权通道"
                                    BuiltinPrivilege.State.STOPPED -> "○ 未运行"
                                    BuiltinPrivilege.State.STARTING -> "● 启动中"
                                },
                                fontSize = 13.sp,
                                color = when (state) {
                                    BuiltinPrivilege.State.RUNNING -> Color(0xFF66D9A0)
                                    BuiltinPrivilege.State.NO_PRIVILEGE -> Color(0xFFFFB74D)
                                    else -> Color(0xFF9090A0)
                                }
                            )
                        }
                        Switch(
                            checked = enabled,
                            onCheckedChange = { want ->
                                enabled = want
                                if (want) {
                                    BuiltinPrivilege.start(context)
                                    log = BuiltinPrivilege.lastMessage
                                    SecurityJournal.log("内置特权", "对外特权服务已开启")
                                } else {
                                    BuiltinPrivilege.stop()
                                    log = "服务已关闭，第三方已无法发现本服务"
                                    SecurityJournal.log("内置特权", "对外特权服务已关闭")
                                }
                                refresh++
                            },
                            colors = SwitchDefaults.colors(
                                checkedTrackColor = Color(0xFFFF6B9D), checkedThumbColor = Color.White)
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    HorizontalDivider(color = Color(0xFF2A2A40))
                    Spacer(Modifier.height(10.dp))
                    RowInfo("运行方式", BuiltinPrivilege.runMode)
                    RowInfo("提权等级", level.label)
                    RowInfo("运行时长", if (enabled) BuiltinPrivilege.uptimeText() else "—")
                    RowInfo("内核版本", "${BuiltinPrivilege.CORE_VERSION}（协议 v${BuiltinPrivilege.PROTOCOL_VERSION}）")
                    RowInfo("已授权应用", "${granted.size} 个")
                    if (log.isNotEmpty()) {
                        Spacer(Modifier.height(6.dp))
                        Text(log, fontSize = 12.sp, color = Color(0xFF7EC8E3))
                    }
                    if (enabled && !Privilege.isReady) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "⚠ 服务已开启，但当前没有可用提权通道。第三方能发现服务、能提交申请，" +
                                "但无法执行命令。请先激活下方任一通道。",
                            fontSize = 12.sp, color = Color(0xFFFFB74D), lineHeight = 17.sp
                        )
                    }
                }
            }

            if (!enabled) {
                Text(
                    "开启后，其他应用可通过 ContentProvider 发现知微并申请特权；" +
                        "每一次授权与命令执行都会留下可追溯的记录。",
                    fontSize = 12.sp, color = Color(0xFF707088),
                    lineHeight = 17.sp, modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp)
                )
            }

            // ===== 激活与配对 =====
            SectionTitleText("激活与配对")
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    // 无线调试
                    ChannelRow(
                        title = "无线调试配对",
                        status = if (AdbShell.isConnected) "✅ 已连接 ${AdbShell.connectedDevice ?: ""}"
                                 else "Android 11+ · 只需输入 6 位配对码",
                        active = AdbShell.isConnected,
                        action = "配对",
                        onAction = { showAdb = true }
                    )
                    Spacer(Modifier.height(8.dp))
                    HorizontalDivider(color = Color(0xFF2A2A40))
                    Spacer(Modifier.height(8.dp))
                    // 有线 ADB
                    ChannelRow(
                        title = "有线 ADB（USB 调试）",
                        status = if (AdbShell.isConnected) "✅ 通道就绪"
                                 else "尝试 127.0.0.1:5555 与上次记忆地址",
                        active = AdbShell.isConnected,
                        action = if (busy) "连接中" else "连接",
                        onAction = {
                            if (!busy) {
                                busy = true; log = "正在尝试 USB 调试端口…"
                                scope.launch {
                                    val r = withContext(Dispatchers.IO) { BuiltinPrivilege.connectUsbDebugging() }
                                    log = r.second
                                    busy = false
                                    if (r.first) {
                                        Prefs.adbHost = "127.0.0.1"
                                        Prefs.adbPort = 5555
                                        Privilege.refresh()
                                    }
                                    refresh++
                                }
                            }
                        }
                    )
                    Spacer(Modifier.height(8.dp))
                    HorizontalDivider(color = Color(0xFF2A2A40))
                    Spacer(Modifier.height(8.dp))
                    // 已有通道
                    ChannelRow(
                        title = "Root / 系统签名通道",
                        status = when (level) {
                            Privilege.Level.ROOT -> "✅ Root 已就绪（uid 0）"
                            Privilege.Level.SYSTEM -> "✅ 系统 uid 已生效"
                            Privilege.Level.SHIZUKU -> "✅ 经 Shizuku 通道就绪"
                            else -> "未检测到（安装 system 渠道包或 Root 后自动生效）"
                        },
                        active = level == Privilege.Level.ROOT || level == Privilege.Level.SYSTEM || level == Privilege.Level.SHIZUKU,
                        action = "提权中心",
                        onAction = { navController.navigate("privilege") }
                    )
                    Spacer(Modifier.height(10.dp))
                    Text(
                        "配对步骤：设置 → 开发者选项 → 无线调试 → 使用配对码配对设备，" +
                            "把 6 位配对码填进知微弹窗即可，无需电脑。",
                        fontSize = 11.sp, color = Color(0xFF707088), lineHeight = 16.sp
                    )
                }
            }

            // ===== 对外授权管理 =====
            SectionTitleText("对外授权管理")
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("已授权应用", fontSize = 15.sp,
                                fontWeight = FontWeight.Medium, color = Color.White)
                            Text("申请过并获准调用知微特权的第三方应用",
                                fontSize = 12.sp, color = Color(0xFF9090A0))
                        }
                        Text("${granted.size}", fontSize = 22.sp,
                            fontWeight = FontWeight.Bold, color = Color(0xFFFF6B9D))
                    }
                    Spacer(Modifier.height(10.dp))
                    if (granted.isEmpty()) {
                        Text("暂无第三方应用获得授权。其他应用调用知微特权时会弹出授权框。",
                            fontSize = 12.sp, color = Color(0xFF707088), lineHeight = 17.sp)
                    } else {
                        granted.forEach { pkg ->
                            val label = appLabel(context, pkg)
                            val calls = AuthDb.callCount(pkg)
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(label, fontSize = 14.sp, color = Color.White, maxLines = 1)
                                    Text(
                                        pkg + (if (calls > 0) " · 已调用 $calls 次" else ""),
                                        fontSize = 11.sp, color = Color(0xFF9090A0), maxLines = 1
                                    )
                                }
                                TextButton(onClick = {
                                    AuthDb.revoke(pkg)
                                    granted = AuthDb.grantedApps
                                    audit = AuthDb.auditLog()
                                    SecurityJournal.log("内置特权", "已撤销 $pkg 的特权授权")
                                }) {
                                    Text("撤销", color = Color(0xFFFF6B6B), fontSize = 13.sp)
                                }
                            }
                        }
                    }
                    Spacer(Modifier.height(6.dp))
                    Row {
                        TextButton(onClick = { navController.navigate("auth") }) {
                            Text("完整授权管理（全应用列表 / 命令白名单） →",
                                color = Color(0xFF7EC8E3), fontSize = 13.sp)
                        }
                    }
                    if (granted.isNotEmpty()) {
                        TextButton(onClick = {
                            AuthDb.revokeAll()
                            granted = AuthDb.grantedApps
                            audit = AuthDb.auditLog()
                            log = "已撤销全部授权"
                            SecurityJournal.log("内置特权", "已撤销全部第三方授权")
                        }) {
                            Text("撤销全部授权", color = Color(0xFFFF6B6B), fontSize = 13.sp)
                        }
                    }
                }
            }

            // 开关项
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    SettingSwitchRow(
                        title = "危险命令拦截",
                        desc = "第三方执行 rm -rf / pm uninstall / 改锁屏等 22 类命令时逐条弹窗确认",
                        checked = intercept,
                        onChange = {
                            intercept = it
                            AuthDb.cmdInterceptEnabled = it
                            SecurityJournal.log("内置特权", "危险命令拦截：${if (it) "开启" else "关闭"}")
                        }
                    )
                    Spacer(Modifier.height(8.dp))
                    SettingSwitchRow(
                        title = "开机自动恢复服务",
                        desc = "设备重启后若曾开启，自动恢复对外服务状态（提权通道仍需重新配对）",
                        checked = autoStart,
                        onChange = { autoStart = it; Prefs.builtinAutoStart = it }
                    )
                }
            }

            // ===== 审计日志 =====
            SectionTitleText("调用审计（最近 ${audit.size} 条）")
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    if (audit.isEmpty()) {
                        Text("暂无第三方调用记录", fontSize = 12.sp, color = Color(0xFF707088))
                    } else {
                        val fmt = remember { SimpleDateFormat("MM-dd HH:mm:ss", Locale.getDefault()) }
                        audit.take(15).forEach { e ->
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                                verticalAlignment = Alignment.Top
                            ) {
                                Text(
                                    if (e.allowed) "✓" else "✕",
                                    fontSize = 12.sp,
                                    color = if (e.allowed) Color(0xFF66D9A0) else Color(0xFFFF6B6B)
                                )
                                Spacer(Modifier.width(6.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text("${e.pkg} · ${e.action}",
                                        fontSize = 12.sp, color = Color(0xFFDDDDDD), maxLines = 2)
                                    Text(fmt.format(Date(e.time)),
                                        fontSize = 10.sp, color = Color(0xFF606070))
                                }
                            }
                        }
                        if (audit.size > 15) {
                            Text("…共 ${audit.size} 条，完整记录见安全日志",
                                fontSize = 11.sp, color = Color(0xFF606070))
                        }
                        Spacer(Modifier.height(6.dp))
                        TextButton(onClick = {
                            AuthDb.clearAudit()
                            audit = AuthDb.auditLog()
                        }) { Text("清空审计", color = Color(0xFFFF6B6B), fontSize = 12.sp) }
                    }
                }
            }

            // ===== 开发者接入 =====
            SectionTitleText("其他应用如何接入")
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        "知微内置特权对外暴露标准 ContentProvider 发现接口：\n" +
                            "· authority：${BuiltinPrivilege.AUTHORITY}\n" +
                            "· getStatus：探测服务是否开启 / 通道是否就绪\n" +
                            "· getBinder：拿到 IZhiweiService（协议 v${BuiltinPrivilege.PROTOCOL_VERSION}）\n" +
                            "· requestPermissionWithReason：申请授权（理由会显示在知微弹窗）\n" +
                            "· execCommand：执行命令，返回 \"exitCode\\noutput\"\n" +
                            "· releasePermission：主动放弃授权",
                        fontSize = 12.sp, color = Color(0xFF9090A0), lineHeight = 18.sp
                    )
                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = { showSdk = !showSdk }) {
                        Text(if (showSdk) "收起接入代码" else "查看接入代码",
                            color = Color(0xFF7EC8E3), fontSize = 13.sp)
                    }
                    if (showSdk) {
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = Color(0xFF0B0B14),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                BuiltinPrivilege.sdkSnippet(),
                                fontSize = 10.sp, color = Color(0xFF9CCC65),
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                lineHeight = 15.sp,
                                modifier = Modifier.padding(12.dp)
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        TextButton(onClick = {
                            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                            cm?.setPrimaryClip(ClipData.newPlainText("zhiwei_sdk", BuiltinPrivilege.sdkSnippet()))
                            Toast.makeText(context, "接入代码已复制", Toast.LENGTH_SHORT).show()
                        }) { Text("复制接入代码", color = Color(0xFFFF6B9D), fontSize = 13.sp) }
                    }
                }
            }

            // ===== 安全声明 =====
            Text(
                "\n安全声明：知微对第三方开放的是 shell 级能力，不是 root；调用方身份一律用 " +
                    "Binder.getCallingUid() 反查，绝不采信自报包名；关闭总开关后 Provider 立即停止" +
                    "下发 Binder，已授权的应用也拿不到命令通道。\n",
                fontSize = 11.sp, color = Color(0xFF606070), lineHeight = 16.sp,
                modifier = Modifier.padding(horizontal = 4.dp)
            )
        }
    }
}

@Composable
private fun RowInfo(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(label, fontSize = 12.sp, color = Color(0xFF9090A0))
        Spacer(Modifier.width(10.dp))
        Text(value, fontSize = 12.sp, color = Color(0xFFDDDDDD))
    }
}

@Composable
private fun SectionTitleText(title: String) {
    Text(
        title,
        fontSize = 13.sp,
        fontWeight = FontWeight.Bold,
        color = Color(0xFFFF6B9D),
        modifier = Modifier.padding(start = 4.dp, top = 14.dp, bottom = 2.dp)
    )
}

@Composable
private fun ChannelRow(
    title: String,
    status: String,
    active: Boolean,
    action: String,
    onAction: () -> Unit
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, fontSize = 15.sp, fontWeight = FontWeight.Medium, color = Color.White)
            Text(
                status, fontSize = 12.sp,
                color = if (active) Color(0xFF66D9A0) else Color(0xFF9090A0),
                lineHeight = 16.sp
            )
        }
        TextButton(onClick = onAction) {
            Text(action, color = Color(0xFFFF6B9D), fontSize = 13.sp)
        }
    }
}

@Composable
private fun SettingSwitchRow(
    title: String,
    desc: String,
    checked: Boolean,
    onChange: (Boolean) -> Unit
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, fontSize = 14.sp, color = Color.White)
            Text(desc, fontSize = 11.sp, color = Color(0xFF9090A0), lineHeight = 15.sp)
        }
        Switch(
            checked = checked,
            onCheckedChange = onChange,
            colors = SwitchDefaults.colors(
                checkedTrackColor = Color(0xFFFF6B9D), checkedThumbColor = Color.White)
        )
    }
}

/** 取应用显示名，取不到就回落包名 */
private fun appLabel(context: Context, pkg: String): String = try {
    val pm = context.packageManager
    pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
} catch (e: Throwable) { pkg }
