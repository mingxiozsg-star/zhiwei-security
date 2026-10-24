package com.zhiwei.security.service

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import com.zhiwei.security.core.Prefs

class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return

        Prefs.init(context)
        if (!Prefs.protectOn) return

        // 启动防护服务
        try {
            val serviceIntent = Intent(context, ProtectService::class.java)
            context.startForegroundService(serviceIntent)
        } catch (e: Exception) { }

        // 启动守护进程
        try {
            val guardIntent = Intent(context, GuardService::class.java)
            context.startForegroundService(guardIntent)
        } catch (e: Exception) { }

        // 设置定时保活
        setupKeepAliveAlarm(context)
    }

    private fun setupKeepAliveAlarm(context: Context) {
        val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val intent = Intent(context, KeepAliveReceiver::class.java)
        val pi = PendingIntent.getBroadcast(
            context, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val interval = 10 * 60 * 1000L // 10分钟
        am.setRepeating(
            AlarmManager.RTC_WAKEUP,
            System.currentTimeMillis() + interval,
            interval,
            pi
        )
    }
}