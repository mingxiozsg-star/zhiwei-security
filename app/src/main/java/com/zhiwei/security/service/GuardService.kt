package com.zhiwei.security.service

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.core.app.NotificationCompat
import com.zhiwei.security.MainActivity
import com.zhiwei.security.R
import com.zhiwei.security.ZhiweiApp
import com.zhiwei.security.core.Prefs

/**
 * 守护进程服务（独立 :guard 进程）
 * 与 ProtectService 互相监视，发现对方被杀后自动拉起
 */
class GuardService : Service() {

    private val handler = Handler(Looper.getMainLooper())
    private val checkRunnable = object : Runnable {
        override fun run() {
            checkAndRevive()
            handler.postDelayed(this, CHECK_INTERVAL)
        }
    }

    companion object {
        private const val CHECK_INTERVAL = 15_000L // 每15秒检查一次
        private const val NOTIFICATION_ID = 1002
        var isRunning = false
            private set
    }

    override fun onCreate() {
        super.onCreate()
        isRunning = true
        Prefs.init(this)
        handler.post(checkRunnable)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, buildNotification())
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        isRunning = false
        handler.removeCallbacks(checkRunnable)
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, ZhiweiApp.CHANNEL_GUARD)
            .setContentTitle("知微守护进程")
            .setContentText("正在保护安全服务")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pi)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    private fun checkAndRevive() {
        if (!Prefs.protectOn) return

        // 检查 ProtectService 是否在运行
        if (!isServiceRunning(ProtectService::class.java)) {
            try {
                val intent = Intent(this, ProtectService::class.java)
                startForegroundService(intent)
            } catch (e: Exception) { }
        }
    }

    private fun isServiceRunning(serviceClass: Class<*>): Boolean {
        val am = getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
        return try {
            @Suppress("DEPRECATION")
            am.getRunningServices(Integer.MAX_VALUE).any {
                it.service.className == serviceClass.name
            }
        } catch (e: SecurityException) {
            // Android 8+ 限制，用其他方式判断
            ProtectService.isRunning
        }
    }
}