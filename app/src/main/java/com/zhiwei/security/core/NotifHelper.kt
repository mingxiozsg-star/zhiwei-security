package com.zhiwei.security.core

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.zhiwei.security.R

/**
 * 操作结果通知中心
 * 所有后台动作（斩杀/扫描/安装监控/病毒清除）的结果统一走通知，不依赖 Toast
 */
object NotifHelper {

    const val CHANNEL_OPS = "zhiwei_ops"
    private var seq = 1000

    private fun ensureChannel(context: Context) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_OPS) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_OPS, "安全操作结果", NotificationManager.IMPORTANCE_DEFAULT).apply {
                    description = "斩杀/扫描/安装监控等操作结果通知"
                }
            )
        }
    }

    /** 普通操作结果通知 */
    fun notify(context: Context, title: String, text: String) {
        post(context, title, text, null, false)
    }

    /** 高优先级告警通知（病毒/静默安装），可带点击动作 */
    fun alert(context: Context, title: String, text: String, tapIntent: Intent? = null) {
        post(context, title, text, tapIntent, true)
    }

    private fun post(context: Context, title: String, text: String, tapIntent: Intent?, high: Boolean) {
        try {
            ensureChannel(context)
            val pi = tapIntent?.let {
                it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                PendingIntent.getActivity(
                    context, (seq++).and(0x7FFFFFFF), it,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
            }
            val n = NotificationCompat.Builder(context, CHANNEL_OPS)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setAutoCancel(true)
                .setPriority(if (high) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
                .apply { if (pi != null) setContentIntent(pi) }
                .build()
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.notify((seq++).and(0x7FFFFFFF), n)
        } catch (e: Throwable) { }
    }
}
