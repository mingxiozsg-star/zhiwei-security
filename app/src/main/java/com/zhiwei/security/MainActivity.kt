package com.zhiwei.security

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.service.GuardService
import com.zhiwei.security.service.GuardService2
import com.zhiwei.security.service.GuardService3
import com.zhiwei.security.service.ProtectService
import com.zhiwei.security.ui.*
import com.zhiwei.security.ui.theme.ZhiweiSecurityTheme
import kotlin.concurrent.thread

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        Prefs.init(this)

        // Android 13+ 通知权限：启动时弹系统授权框（声明的 POST_NOTIFICATIONS 需运行时申请，
        // 否则威胁告警通知发不出来）。只在未授权时申请，用户拒绝后不反复骚扰。
        if (android.os.Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
                android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 42)
        }

        // 后台线程尝试恢复本机 ADB 提权通道
        thread(start = true, isDaemon = true) {
            try { com.zhiwei.security.core.AdbShell.autoReconnect() } catch (e: Throwable) { }
        }

        setContent {
            ZhiweiSecurityTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val navController = rememberNavController()
                    val startDest = "home" // 旧首启授权引导页已停用：通知权限改由启动时系统弹窗申请，提权授权在主页卡片/提权页完成
                    NavHost(navController = navController, startDestination = startDest) {
                        composable("home") { HomeScreen(navController) }
                        composable("scan") { ScanScreen(navController) }
                        composable("apps") { AppListScreen(navController) }
                        composable("protect") { ProtectScreen(navController) }
                        composable("settings") { SettingsScreen(navController) }
                        composable("permissions") { PermissionScreen(navController) }
                        composable("about") { AboutScreen(navController) }
                        composable("privilege") { PrivilegeScreen(navController) }
                        composable("journal") { JournalScreen(navController) }
                        composable("licenses") { LicenseScreen(navController) }
                        composable("auth") { AuthManageScreen(navController) }
                    }
                }
            }
        }

        // 如果防护已开启，确保服务在运行
        if (Prefs.protectOn) {
            startServices()
        }
    }

    private fun startServices() {
        try {
            startForegroundService(Intent(this, ProtectService::class.java))
        } catch (e: Exception) { }
        try {
            startForegroundService(Intent(this, GuardService::class.java))
        } catch (e: Exception) { }
        try {
            startForegroundService(Intent(this, GuardService2::class.java))
        } catch (e: Exception) { }
        try {
            startForegroundService(Intent(this, GuardService3::class.java))
        } catch (e: Exception) { }
        // 网络拦截（需用户先在设置里开启并完成 VPN 授权）
        if (Prefs.netGuardEnabled) {
            try { com.zhiwei.security.service.NetGuardService.start(this) } catch (e: Exception) { }
        }
    }

    override fun onResume() {
        super.onResume()
        // 隐藏后台卡片（防手动划掉）
        try {
            val am = getSystemService(ACTIVITY_SERVICE) as android.app.ActivityManager
            am.appTasks?.forEach { it.setExcludeFromRecents(Prefs.hideRecentsEnabled) }
        } catch (e: Exception) { }
    }
}