package com.zhiwei.security.service

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.zhiwei.security.core.Prefs

class KeepAliveReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        Prefs.init(context)
        if (!Prefs.protectOn) return

        // 检查并拉起 ProtectService
        if (!ProtectService.isRunning) {
            try {
                val serviceIntent = Intent(context, ProtectService::class.java)
                context.startForegroundService(serviceIntent)
            } catch (e: Exception) { }
        }

        // 检查并拉起 GuardService
        if (!GuardService.isRunning) {
            try {
                val guardIntent = Intent(context, GuardService::class.java)
                context.startForegroundService(guardIntent)
            } catch (e: Exception) { }
        }

        // 重新设置下次闹钟
        setupNextAlarm(context)
    }

    companion object {
        fun setupNextAlarm(context: Context) {
            val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            val intent = Intent(context, KeepAliveReceiver::class.java)
            val pi = PendingIntent.getBroadcast(
                context, 0, intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            val interval = 10 * 60 * 1000L
            am.setRepeating(
                AlarmManager.RTC_WAKEUP,
                System.currentTimeMillis() + interval,
                interval,
                pi
            )
        }
    }
}