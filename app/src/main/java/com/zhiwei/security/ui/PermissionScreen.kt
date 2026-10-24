package com.zhiwei.security.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationManagerCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.navigation.NavController
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.core.ShizukuManager
import com.zhiwei.security.service.ProtectService

/**
 * 权限引导页
 * 逐项检测核心权限状态并跳转系统设置，返回时自动刷新
 */
private fun isA11yEnabled(context: android.content.Context): Boolean {
    val enabled = android.provider.Settings.Secure.getString(
        context.contentResolver,
        android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
    ) ?: return false
    return enabled.contains(context.packageName)
}
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PermissionScreen(navController: NavController) {
    val context = LocalContext.current
    var refreshTick by remember { mutableStateOf(0) }

    // 从系统设置返回时刷新状态
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) refreshTick++
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    data class PermItem(
        val title: String,
        val desc: String,
        val granted: Boolean,
        val onClick: () -> Unit
    )

    val items = remember(refreshTick) {
        listOf(
            PermItem(
                "无障碍守护服务",
                "音量键三连击紧急斩杀、软件音量攻击检测、霸屏锁机检测（独立进程驻留，最核心权限）",
                isA11yEnabled(context)
            ) {
                context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                })
            },
            PermItem(
                "使用情况访问",
                "用于监控前台应用，发现黑名单应用启动时立即拦截（核心权限）",
                ProtectService.hasUsageAccess(context)
            ) {
                context.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                })
            },
            PermItem(
                "Shizuku 提权",
                "用于强制停止/卸载恶意应用。当前状态：${ShizukuManager.statusText}",
                ShizukuManager.isReady
            ) {
                if (ShizukuManager.isBinderAlive && !ShizukuManager.isGranted) {
                    ShizukuManager.requestPermission { }
                } else if (!ShizukuManager.isBinderAlive) {
                    // 跳转到 Shizuku 应用（如果已安装）
                    try {
                        context.startActivity(
                            context.packageManager.getLaunchIntentForPackage("moe.shizuku.privileged.api")
                        )
                    } catch (e: Exception) { }
                }
            },
            PermItem(
                "通知权限",
                "用于推送威胁警告",
                NotificationManagerCompat.from(context).areNotificationsEnabled()
            ) {
                context.startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
                    putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                })
            },
            PermItem(
                "忽略电池优化",
                "防止系统杀掉守护服务，保证 24 小时防护",
                (context.getSystemService(Context.POWER_SERVICE) as PowerManager)
                    .isIgnoringBatteryOptimizations(context.packageName)
            ) {
                context.startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:${context.packageName}")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                })
            },
            PermItem(
                "悬浮窗权限",
                "用于在恶意应用界面上层显示警告",
                Settings.canDrawOverlays(context)
            ) {
                context.startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION).apply {
                    data = Uri.parse("package:${context.packageName}")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                })
            }
        )
    }

    val grantedCount = items.count { it.granted }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("权限设置", fontWeight = FontWeight.Bold) },
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
            // 总进度卡片
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (grantedCount == items.size) Color(0xFF1B3A2D) else Color(0xFF3A2A1B)
                )
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text(
                        if (grantedCount == items.size) "✓ 全部权限已就绪" else "已完成 $grantedCount / ${items.size} 项",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (grantedCount == items.size) Color(0xFF4CAF50) else Color(0xFFFF9800)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    LinearProgressIndicator(
                        progress = { grantedCount.toFloat() / items.size },
                        modifier = Modifier.fillMaxWidth(),
                        color = Color(0xFFFF6B9D),
                        trackColor = Color(0xFF2A2A3E)
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            items.forEach { item ->
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 6.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(item.title, fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color.White)
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(item.desc, fontSize = 13.sp, color = Color(0xFF9090A0))
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        if (item.granted) {
                            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = Color(0xFF4CAF50))
                        } else {
                            Button(
                                onClick = item.onClick,
                                shape = RoundedCornerShape(20.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFF6B9D))
                            ) {
                                Text("去开启", fontSize = 13.sp)
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = {
                    Prefs.onboardingDone = true
                    navController.navigate("home") {
                        popUpTo("permissions") { inclusive = true }
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                shape = RoundedCornerShape(26.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFF6B9D))
            ) {
                Text("完成设置", fontSize = 16.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
}