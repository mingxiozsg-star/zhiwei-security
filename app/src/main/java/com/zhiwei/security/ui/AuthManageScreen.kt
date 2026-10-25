package com.zhiwei.security.ui

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import androidx.navigation.NavController
import com.zhiwei.security.core.AuthDb
import com.zhiwei.security.core.Privilege
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 授权管理页：手动给其他应用授予/撤销知微特权（知微特权服务 + Dhizuku 服务端共用）
 * 顶部：拦截总开关 + 命令白名单管理；下方：全部第三方应用列表（可搜索）
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthManageScreen(navController: NavController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var cmdIntercept by remember { mutableStateOf(AuthDb.cmdInterceptEnabled) }
    var granted by remember { mutableStateOf(AuthDb.grantedApps) }
    var cmdWhitelist by remember { mutableStateOf(AuthDb.cmdWhitelist.toList()) }
    var query by remember { mutableStateOf("") }
    var showOnlyGranted by remember { mutableStateOf(false) }

    data class AppEntry(val pkg: String, val label: String, val icon: android.graphics.Bitmap?)

    var apps by remember { mutableStateOf<List<AppEntry>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val list = if (Build.VERSION.SDK_INT >= 33)
                pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
            else @Suppress("DEPRECATION") pm.getInstalledApplications(0)
            list.filter {
                it.flags and ApplicationInfo.FLAG_SYSTEM == 0 &&
                    it.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP == 0 &&
                    it.packageName != context.packageName
            }.map { ai ->
                AppEntry(
                    ai.packageName,
                    pm.getApplicationLabel(ai).toString(),
                    try { pm.getApplicationIcon(ai).toBitmap(96, 96) } catch (e: Throwable) { null }
                )
            }.sortedBy { it.label }
        }
        loading = false
    }

    val shown = apps.filter {
        (query.isEmpty() || it.label.contains(query, true) || it.pkg.contains(query, true)) &&
            (!showOnlyGranted || it.pkg in granted)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("授权管理", fontWeight = FontWeight.Bold) },
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
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp)) {

            // 状态说明卡
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("已授权 ${granted.size} 个应用", color = Color.White,
                        fontSize = 16.sp, fontWeight = FontWeight.Medium)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "授权后应用可通过知微特权服务 / Dhizuku 服务端执行特权操作。" +
                            (if (Privilege.isReady) "提权通道就绪：${Privilege.statusText}"
                             else "⚠ 提权通道未就绪，授权的应用暂时无法执行命令"),
                        fontSize = 12.sp,
                        color = if (Privilege.isReady) Color(0xFF7EC8E3) else Color(0xFFFFB74D)
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("危险命令拦截", color = Color.White, fontSize = 14.sp)
                            Text("已授权应用执行危险命令时弹窗确认", fontSize = 12.sp, color = Color(0xFF9090A0))
                        }
                        Switch(
                            checked = cmdIntercept,
                            onCheckedChange = { cmdIntercept = it; AuthDb.cmdInterceptEnabled = it },
                            colors = SwitchDefaults.colors(
                                checkedTrackColor = Color(0xFFFF6B9D), checkedThumbColor = Color.White)
                        )
                    }
                }
            }

            // 命令白名单
            if (cmdWhitelist.isNotEmpty()) {
                Card(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text("命令白名单（${cmdWhitelist.size}）", color = Color.White,
                            fontSize = 14.sp, fontWeight = FontWeight.Medium)
                        Spacer(Modifier.height(6.dp))
                        cmdWhitelist.take(8).forEach { entry ->
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(entry.replace("|", " → "), fontSize = 12.sp,
                                    color = Color(0xFF9CCC65), modifier = Modifier.weight(1f))
                                TextButton(onClick = {
                                    AuthDb.removeCmdWhitelist(entry)
                                    cmdWhitelist = AuthDb.cmdWhitelist.toList()
                                }) { Text("删除", color = Color(0xFFFF6B6B), fontSize = 12.sp) }
                            }
                        }
                        if (cmdWhitelist.size > 8) {
                            Text("…共 ${cmdWhitelist.size} 条", fontSize = 11.sp, color = Color(0xFF606070))
                        }
                    }
                }
            }

            // 搜索 + 过滤
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                placeholder = { Text("搜索应用名或包名", color = Color(0xFF606070)) },
                singleLine = true,
                shape = RoundedCornerShape(24.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Color(0xFFFF6B9D),
                    unfocusedBorderColor = Color(0xFF3A3A55),
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White,
                    cursorColor = Color(0xFFFF6B9D)
                )
            )
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(bottom = 4.dp)
            ) {
                FilterChip(
                    selected = showOnlyGranted,
                    onClick = { showOnlyGranted = !showOnlyGranted },
                    label = { Text("只看已授权") },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = Color(0xFFFF6B9D),
                        selectedLabelColor = Color(0xFF0F0F1A),
                        containerColor = Color(0xFF1A1A2E),
                        labelColor = Color(0xFF9090A0)
                    )
                )
                Spacer(Modifier.width(8.dp))
                Text("${shown.size} 个应用", fontSize = 12.sp, color = Color(0xFF606070))
            }

            if (loading) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = Color(0xFFFF6B9D))
                }
            } else {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(shown, key = { it.pkg }) { app ->
                        val isGranted = app.pkg in granted
                        Card(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            shape = RoundedCornerShape(12.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = if (isGranted) Color(0xFF23233D) else Color(0xFF161625))
                        ) {
                            Row(
                                modifier = Modifier.padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                if (app.icon != null) {
                                    Image(
                                        bitmap = app.icon.asImageBitmap(),
                                        contentDescription = null,
                                        modifier = Modifier.size(40.dp)
                                    )
                                } else {
                                    Text("📦", fontSize = 24.sp, modifier = Modifier.size(40.dp))
                                }
                                Spacer(Modifier.width(12.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(app.label, color = Color.White, fontSize = 15.sp,
                                        fontWeight = FontWeight.Medium, maxLines = 1)
                                    Text(app.pkg, color = Color(0xFF9090A0), fontSize = 11.sp, maxLines = 1)
                                }
                                Switch(
                                    checked = isGranted,
                                    onCheckedChange = { want ->
                                        scope.launch {
                                            if (want) AuthDb.grant(app.pkg) else AuthDb.revoke(app.pkg)
                                            granted = AuthDb.grantedApps
                                            cmdWhitelist = AuthDb.cmdWhitelist.toList()
                                        }
                                    },
                                    colors = SwitchDefaults.colors(
                                        checkedTrackColor = Color(0xFFFF6B9D),
                                        checkedThumbColor = Color.White)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
