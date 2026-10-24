package com.zhiwei.security.service

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
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
 * 守护进程 2（:guard2 进程）
 * 策略：不探测，直接周期性拉起——服务已在运行时 startForegroundService 无害
 */
class GuardService2 : Service() {

    private val handler = Handler(Looper.getMainLooper())
    private val checkRunnable = object : Runnable {
        override fun run() {
            revive()
            handler.postDelayed(this, CHECK_INTERVAL)
        }
    }

    companion object {
        private const val CHECK_INTERVAL = 20_000L
        private const val NOTIFICATION_ID = 1003
    }

    override fun onCreate() {
        super.onCreate()
        Prefs.init(this)
        handler.post(checkRunnable)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, buildNotification())
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
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
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pi)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    private fun revive() {
        if (!Prefs.protectOn) return
        try { startForegroundService(Intent(this, ProtectService::class.java)) } catch (e: Exception) { }
        try { startForegroundService(Intent(this, GuardService::class.java)) } catch (e: Exception) { }
    }
}