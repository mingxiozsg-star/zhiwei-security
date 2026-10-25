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
                    val startDest = if (Prefs.onboardingDone) "home" else "permissions"
                    NavHost(navController = navController, startDestination = startDest) {
                        composable("home") { HomeScreen(navController) }
                        composable("scan") { ScanScreen(navController) }
                        composable("apps") { AppListScreen(navController) }
                        composable("protect") { ProtectScreen(navController) }
                        composable("settings") { SettingsScreen(navController) }
                        composable("permissions") { PermissionScreen(navController) }
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