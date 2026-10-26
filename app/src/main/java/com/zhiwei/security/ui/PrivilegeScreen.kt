package com.zhiwei.security.ui

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
import com.zhiwei.security.core.Privilege
import com.zhiwei.security.core.ShizukuManager
import com.zhiwei.security.dhizuku.ZhiweiDAReceiver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 提权中心：一页管完所有提权通道
 * uid.system / 本机 ADB / Shizuku / Dhizuku（内置服务端·设备所有者）
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PrivilegeScreen(navController: NavController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var showAdbDialog by remember { mutableStateOf(false) }
    var refresh by remember { mutableStateOf(0) }
    var ownerLog by remember { mutableStateOf("") }
    var ownerBusy by remember { mutableStateOf(false) }

    LaunchedEffect(refresh) {
        withContext(Dispatchers.IO) {
            try { AdbShell.refreshStatus() } catch (e: Throwable) { }
        }
    }

    if (showAdbDialog) {
        AdbActivationDialog(onDismiss = { showAdbDialog = false; refresh++ })
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("提权中心", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF0F0F1A), titleContentColor = Color.White
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
            // 当前状态总览
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("当前提权状态", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                    Text(Privilege.statusText, fontSize = 13.sp, color = Color(0xFF7EC8E3))
                    Text("优先级：Root > uid.system > 本机 ADB > Shizuku",
                        fontSize = 12.sp, color = Color(0xFF9090A0))
                }
            }

            // uid.system
            PrivChannelCard(
                title = "系统级提权（android.uid.system）",
                status = if (Privilege.isSystemUid) "✅ 已生效：当前运行于系统 uid"
                    else "未生效：安装 system 渠道包（testkey 签名系统可用）",
                active = Privilege.isSystemUid
            )

            // 本机 ADB
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("本机 ADB 自提权", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                        Text(
                            if (AdbShell.isConnected) "✅ 已连接 ${AdbShell.connectedDevice ?: ""}"
                            else "未连接 · 一键配对激活（只需 6 位配对码）",
                            fontSize = 13.sp,
                            color = if (AdbShell.isConnected) Color(0xFF9CCC65) else Color(0xFF9090A0)
                        )
                    }
                    TextButton(onClick = { showAdbDialog = true }) {
                        Text(if (AdbShell.isConnected) "重新连接" else "激活", color = Color(0xFFFF6B9D))
                    }
                }
            }

            // Dhizuku（内置服务端·设备所有者）
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Dhizuku 服务端（内置）", fontSize = 16.sp,
                                fontWeight = FontWeight.Medium, color = Color.White)
                            Text(
                                if (ZhiweiDAReceiver.isDeviceOwner(context))
                                    "✅ 已激活：知微是设备所有者，Dhizuku 服务端运行中"
                                else "未激活：一键设为设备所有者（经 ADB/Root 通道执行 dpm 命令）",
                                fontSize = 13.sp,
                                color = if (ZhiweiDAReceiver.isDeviceOwner(context))
                                    Color(0xFF9CCC65) else Color(0xFF9090A0)
                            )
                        }
                        if (!ZhiweiDAReceiver.isDeviceOwner(context)) {
                            TextButton(
                                enabled = !ownerBusy && Privilege.isReady,
                                onClick = {
                                    ownerBusy = true
                                    ownerLog = "正在激活…"
                                    scope.launch {
                                        val r = withContext(Dispatchers.IO) {
                                            Privilege.exec("dpm set-device-owner com.zhiwei.security/.dhizuku.ZhiweiDAReceiver")
                                        }
                                        ownerBusy = false
                                        ownerLog = if (r.first == 0) "✅ 激活成功"
                                            else "❌ 失败：${r.second.take(200)}\n（设备已有账号时需先移除账号）"
                                        refresh++
                                    }
                                }
                            ) { Text("一键激活", color = Color(0xFFFF6B9D)) }
                        }
                    }
                    if (ownerLog.isNotEmpty()) {
                        Spacer(Modifier.height(6.dp))
                        Text(ownerLog, fontSize = 12.sp, color = Color(0xFF7EC8E3))
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "激活后，任何使用 Dhizuku-API 的应用自动对接知微，可申请授权调用设备所有者能力（remoteTransact / UserService / 远程进程）。授权管理在设置页。",
                        fontSize = 12.sp, color = Color(0xFF9090A0), lineHeight = 17.sp
                    )
                }
            }

            // Shizuku（外部）
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Shizuku（外部）", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                        Text(ShizukuManager.statusText, fontSize = 13.sp, color = Color(0xFF9090A0))
                    }
                    if (!ShizukuManager.isReady && ShizukuManager.isBinderAlive) {
                        TextButton(onClick = { ShizukuManager.requestPermission { refresh++ } }) {
                            Text("授权", color = Color(0xFFFF6B9D))
                        }
                    }
                }
            }

            // Dhizuku（外部，兼容）
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Dhizuku 客户端（外部，兼容）", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                        Text(DhizukuManager.statusText(context), fontSize = 13.sp, color = Color(0xFF9090A0))
                        Text("仅用于兼容第三方 Dhizuku 客户端接入；本应用全部能力均在应用内完成，无需打开外部应用。", fontSize = 11.sp, color = Color(0xFF707088), lineHeight = 15.sp)
                    }
                    if (DhizukuManager.isInstalled(context) && !DhizukuManager.isReady(context)) {
                        TextButton(onClick = { DhizukuManager.requestPermission { refresh++ } }) {
                            Text("授权", color = Color(0xFFFF6B9D))
                        }
                    }
                }
            }

            // 全机型兼容指南
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("📖 全机型激活指南", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "【Dhizuku 设备所有者】要求设备无已登录账号，各厂商移除路径：\n" +
                        "· 小米/红米：设置 → 小米账号 → 退出登录\n" +
                        "· 华为/荣耀：设置 → 华为账号 → 退出账号\n" +
                        "· OPPO/一加：设置 → 欢太账号 → 退出\n" +
                        "· vivo/iQOO：设置 → vivo 账号 → 退出登录\n" +
                        "· 三星：设置 → 账户与备份 → 移除三星/Google 账户\n" +
                        "· 其他：设置 → 账号/用户与账户 → 移除全部账户\n\n" +
                        "【本机 ADB / Shizuku】Android 11+ 开启「无线调试」：\n" +
                        "设置 → 开发者选项 → 无线调试 → 使用配对码配对 → 在本应用弹窗输入 6 位配对码\n\n" +
                        "【优先级】知微自动按 Root > 系统签名 > 本机 ADB > Shizuku 选择可用通道，任一就绪即可强杀/卸载。",
                        fontSize = 12.sp, color = Color(0xFF9090A0), lineHeight = 18.sp
                    )
                }
            }
        }
    }
}

@Composable
private fun PrivChannelCard(title: String, status: String, active: Boolean) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(title, fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
            Text(status, fontSize = 13.sp,
                color = if (active) Color(0xFF9CCC65) else Color(0xFF9090A0))
        }
    }
}