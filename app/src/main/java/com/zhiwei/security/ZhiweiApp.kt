package com.zhiwei.security

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build

class ZhiweiApp : Application() {

    companion object {
        const val CHANNEL_PROTECT = "channel_protect"
        const val CHANNEL_GUARD = "channel_guard"
        const val CHANNEL_WARN = "channel_warn"

        lateinit var instance: ZhiweiApp
            private set
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        com.zhiwei.security.core.Prefs.init(this)
        com.zhiwei.security.core.ShizukuManager.init()
        com.zhiwei.security.core.AdbShell.init(this)
        com.zhiwei.security.core.Privilege.warmup()
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        val nm = getSystemService(NotificationManager::class.java) ?: return

        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_PROTECT, "防锁机守护", NotificationManager.IMPORTANCE_LOW).apply {
                description = "防锁机守护服务通知"
                setShowBadge(false)
            }
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_GUARD, "守护进程", NotificationManager.IMPORTANCE_MIN).apply {
                description = "守护进程服务通知"
                setShowBadge(false)
            }
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_WARN, "安全警告", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "病毒/风险警告通知"
                enableVibration(true)
            }
        )
    }
}
