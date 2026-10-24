package com.zhiwei.security.service

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.media.AudioManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import com.zhiwei.security.MainActivity
import com.zhiwei.security.R
import com.zhiwei.security.ZhiweiApp
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.core.VirusDb

/**
 * 防锁机守护前台服务
 * 核心功能：
 * 1. 监听屏幕关闭事件，检测是否有恶意应用触发锁屏
 * 2. 监听音量键长按，作为紧急救援触发
 * 3. 定期扫描已安装应用，发现黑名单应用立即弹窗警告
 * 4. 监控权限降级（设备管理器被撤销等）
 */
class ProtectService : Service() {

    private var wakeLock: PowerManager.WakeLock? = null
    private val handler = Handler(Looper.getMainLooper())
    private var screenReceiver: BroadcastReceiver? = null
    private var packageReceiver: BroadcastReceiver? = null
    private val scanRunnable = object : Runnable {
        override fun run() {
            scanBlacklistedApps()
            handler.postDelayed(this, SCAN_INTERVAL)
        }
    }

    companion object {
        private const val SCAN_INTERVAL = 60_000L // 每分钟扫描一次
        private const val NOTIFICATION_ID = 1001
        var isRunning = false
            private set
    }

    override fun onCreate() {
        super.onCreate()
        isRunning = true
        Prefs.init(this)
        acquireWakeLock()
        registerScreenReceiver()
        registerPackageReceiver()
        handler.post(scanRunnable)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, buildNotification())
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        isRunning = false
        handler.removeCallbacks(scanRunnable)
        unregisterReceivers()
        releaseWakeLock()
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, ZhiweiApp.CHANNEL_PROTECT)
            .setContentTitle("知微安全守护中")
            .setContentText("防锁机保护已激活")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pi)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    private fun acquireWakeLock() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "zhiwei:protect").apply {
            acquire(10 * 60 * 1000L) // 10分钟
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
    }

    // 屏幕关闭监听：检测是否有恶意应用正在锁屏
    private fun registerScreenReceiver() {
        screenReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                when (intent.action) {
                    Intent.ACTION_SCREEN_OFF -> {
                        checkLockScreenThreat()
                    }
                    Intent.ACTION_SCREEN_ON -> {
                        // 屏幕亮起，检查是否有锁机应用在运行
                        checkLockScreenThreat()
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(screenReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(screenReceiver, filter)
        }
    }

    // 应用安装/卸载监听
    private fun registerPackageReceiver() {
        packageReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val pkg = intent.data?.schemeSpecificPart ?: return
                when (intent.action) {
                    Intent.ACTION_PACKAGE_ADDED -> {
                        checkNewAppThreat(pkg)
                    }
                    Intent.ACTION_PACKAGE_REMOVED -> {
                        // 卸载时清理名单缓存
                        Prefs.removeFromBlacklist(pkg)
                        Prefs.removeFromWhitelist(pkg)
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(packageReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(packageReceiver, filter)
        }
    }

    private fun unregisterReceivers() {
        try { screenReceiver?.let { unregisterReceiver(it) } } catch (e: Exception) { }
        try { packageReceiver?.let { unregisterReceiver(it) } } catch (e: Exception) { }
    }

    // 检测锁屏威胁
    private fun checkLockScreenThreat() {
        // 检查是否有黑名单应用正在前台运行
        val am = getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
        val tasks = try {
            am.getRunningTasks(5)
        } catch (e: SecurityException) {
            return
        }
        tasks?.forEach { task ->
            task.topActivity?.packageName?.let { pkg ->
                if (pkg in Prefs.blacklist || pkg in VirusDb.maliciousPackages) {
                    showThreatWarning(pkg, "检测到黑名单应用正在运行并尝试锁屏")
                }
            }
        }
    }

    // 检测新安装应用
    private fun checkNewAppThreat(pkg: String) {
        if (pkg in VirusDb.maliciousPackages) {
            showThreatWarning(pkg, "检测到已知恶意应用被安装")
        }
        // 检查是否申请了锁机相关权限
        try {
            val pm = packageManager
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS)
            }
            val perms = info.requestedPermissions?.toList() ?: emptyList()
            val hasLockCombo = perms.contains("android.permission.SYSTEM_ALERT_WINDOW") &&
                    perms.contains("android.permission.BIND_DEVICE_ADMIN")
            if (hasLockCombo) {
                showThreatWarning(pkg, "新安装应用请求锁机高危权限组合")
            }
        } catch (e: Exception) { }
    }

    // 定期扫描黑名单应用
    private fun scanBlacklistedApps() {
        val pm = packageManager
        val installed = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledApplications(0)
            }
        } catch (e: Exception) { return }

        installed.forEach { app ->
            if (app.packageName in VirusDb.maliciousPackages && app.packageName !in Prefs.whitelist) {
                showThreatWarning(app.packageName, "检测到已知恶意应用")
            }
        }
    }

    // 弹出威胁警告
    private fun showThreatWarning(pkg: String, reason: String) {
        // 如果用户已加入白名单，跳过
        if (pkg in Prefs.whitelist) return

        val appName = try {
            val pm = packageManager
            val appInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(pkg, 0)
            }
            appInfo.loadLabel(pm).toString()
        } catch (e: Exception) { pkg }

        // 发送高优先级通知
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as android.app.NotificationManager
        val pi = PendingIntent.getActivity(
            this, pkg.hashCode(),
            Intent(this, com.zhiwei.security.ui.ShieldWarnActivity::class.java).apply {
                putExtra("pkg", pkg)
                putExtra("app_name", appName)
                putExtra("reason", reason)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(this, ZhiweiApp.CHANNEL_WARN)
            .setContentTitle("⚠️ 安全警告")
            .setContentText("$appName: $reason")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .build()

        nm.notify(pkg.hashCode(), notification)

        // 同时弹出警告 Activity（锁屏上也能显示）
        val intent = Intent(this, com.zhiwei.security.ui.ShieldWarnActivity::class.java).apply {
            putExtra("pkg", pkg)
            putExtra("app_name", appName)
            putExtra("reason", reason)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        startActivity(intent)
    }
}