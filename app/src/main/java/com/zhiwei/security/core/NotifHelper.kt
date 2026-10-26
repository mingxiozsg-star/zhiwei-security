package com.zhiwei.security.core

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.AudioAttributes
import android.net.Uri
import androidx.core.app.NotificationCompat
import com.zhiwei.security.R

/**
 * 操作结果通知中心
 * 所有后台动作（斩杀/扫描/安装监控/病毒清除）的结果统一走通知，不依赖 Toast
 *
 * 需要权限：android.permission.POST_NOTIFICATIONS（Android 13+ 运行时权限，
 * 已在 Manifest 声明，权限引导页/首次启动会弹系统授权框）
 */
object NotifHelper {

    const val CHANNEL_OPS = "zhiwei_ops"
    /** 威胁告警专用渠道：专属警报提示音（双音 siren）+ 震动，高重要性抬头显示 */
    const val CHANNEL_ALERT = "zhiwei_alert"
    private var seq = 1000

    private fun alertSoundUri(context: Context): Uri =
        Uri.parse("android.resource://${context.packageName}/${R.raw.zhiwei_alert}")

    private fun ensureChannel(context: Context) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_OPS) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_OPS, "安全操作结果", NotificationManager.IMPORTANCE_DEFAULT).apply {
                    description = "斩杀/扫描/安装监控等操作结果通知"
                }
            )
        }
        // 告警渠道独立创建：声音/震动在渠道上固化（渠道一旦建好后属性不可再改，
        // 老版本升级过来的设备没有此渠道，首次发告警时创建即可生效）
        if (nm.getNotificationChannel(CHANNEL_ALERT) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ALERT, "威胁告警", NotificationManager.IMPORTANCE_HIGH).apply {
                    description = "病毒斩杀/锁机拦截/霸屏处置等紧急告警（专属警报音）"
                    setSound(
                        alertSoundUri(context),
                        AudioAttributes.Builder()
                            .setUsage(AudioAttributes.USAGE_NOTIFICATION_EVENT)
                            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                            .build()
                    )
                    enableVibration(true)
                    vibrationPattern = longArrayOf(0, 250, 120, 250)
                    setShowBadge(true)
                }
            )
        }
    }

    /** 普通操作结果通知（默认提示音） */
    fun notify(context: Context, title: String, text: String) {
        post(context, title, text, null, false)
    }

    /** 高优先级告警通知（病毒斩杀/静默安装/霸屏处置）：专属警报音 + 震动，可带点击动作 */
    fun alert(context: Context, title: String, text: String, tapIntent: Intent? = null) {
        post(context, title, text, tapIntent, true)
    }

    private fun post(context: Context, title: String, text: String, tapIntent: Intent?, high: Boolean) {
        try {
            // Android 13+ 无通知权限时静默放弃（权限申请在 UI 层引导）
            if (android.os.Build.VERSION.SDK_INT >= 33 &&
                context.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
                    android.content.pm.PackageManager.PERMISSION_GRANTED) return
            ensureChannel(context)
            val pi = tapIntent?.let {
                it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                PendingIntent.getActivity(
                    context, (seq++).and(0x7FFFFFFF), it,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
            }
            val n = NotificationCompat.Builder(context, if (high) CHANNEL_ALERT else CHANNEL_OPS)
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
