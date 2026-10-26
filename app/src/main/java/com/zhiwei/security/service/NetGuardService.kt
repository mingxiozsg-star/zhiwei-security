package com.zhiwei.security.service

import android.app.Notification
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.zhiwei.security.MainActivity
import com.zhiwei.security.R
import com.zhiwei.security.ZhiweiApp
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.core.VirusDb
import java.io.FileInputStream
import kotlin.concurrent.thread

/**
 * 后台网络拦截服务（VPN 黑洞模式）
 *
 * 原理：本地 VpnService 只把「被拦截应用」的流量路由进来，
 * 读到的包直接丢弃不转发——该应用的网络等于被物理切断。
 * 其他应用和系统应用不走 VPN，完全不受影响。
 *
 * 被拦截对象：
 * - Prefs.netBlocked（手动加入）
 * - Prefs.blacklist（黑名单应用自动断网）
 * - 病毒库命中且有敏感权限的第三方应用
 */
class NetGuardService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    @Volatile private var running = false

    companion object {
        private const val NOTIFICATION_ID = 1005
        var isRunning = false
            private set

        fun start(context: android.content.Context) {
            val intent = Intent(context, NetGuardService::class.java)
            context.startForegroundService(intent)
        }

        fun stop(context: android.content.Context) {
            context.stopService(Intent(context, NetGuardService::class.java))
        }

        /** 名单/配置变化后重建 VPN（未开启则不动） */
        fun restart(context: android.content.Context) {
            if (!Prefs.netGuardEnabled) return
            try { stop(context) } catch (e: Throwable) { }
            // stopService 是异步的，立刻 start 可能新旧实例并存导致新实例 establish 失败 → 稍等再拉
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                try { start(context) } catch (e: Throwable) { }
            }, 400)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, buildNotification())
        // 用 vpnInterface 判空而不是 running：restart() 竞态下新实例能正确重建
        if (vpnInterface == null) establishVpn()
        return START_STICKY
    }

    private fun establishVpn() {
        Prefs.init(this)
        val blockedApps = collectBlockedApps()
        // F3：C2 失陷指标 IP（"ip:port" 格式 → 提取 ip 做 /32 黑洞路由）
        val c2Ips = if (Prefs.c2FilterEnabled) VirusDb.c2Indicators.mapNotNull {
            it.substringBefore(":").takeIf { ip -> ip.matches(Regex("""\d+\.\d+\.\d+\.\d+""")) }
        } else emptyList()

        if (blockedApps.isEmpty() && c2Ips.isEmpty()) {
            // 没有要拦的对象就不起 VPN，省电
            stopSelf()
            return
        }

        val builder = Builder()
            .setSession("知微网络拦截")
            .addAddress("10.0.0.2", 32)
            .setBlocking(true)

        // C2 IP 黑洞路由：任何应用连 C2 服务器的流量进 VPN 被丢弃
        c2Ips.forEach { ip ->
            try { builder.addRoute(ip, 32) } catch (e: Exception) { }
        }

        // 只让被拦截的应用进 VPN（其他应用流量绕行，零影响）
        var added = 0
        blockedApps.forEach { pkg ->
            try {
                builder.addAllowedApplication(pkg)
                added++
            } catch (e: Exception) { }
        }
        if (blockedApps.isNotEmpty()) {
            if (added == 0 && c2Ips.isEmpty()) { stopSelf(); return }
            builder.addRoute("0.0.0.0", 0)
        }

        vpnInterface = builder.establish()
        if (vpnInterface == null) { stopSelf(); return }

        running = true
        isRunning = true

        // 黑洞：读包即丢弃
        thread {
            val input = FileInputStream(vpnInterface!!.fileDescriptor)
            val buffer = ByteArray(32767)
            try {
                while (running) {
                    val len = input.read(buffer)
                    if (len < 0) break
                    // 丢弃，不转发——被拦应用的网络请求全部石沉大海
                }
            } catch (e: Exception) { }
        }
    }

    /** 收集需要断网的应用（系统应用一律豁免） */
    private fun collectBlockedApps(): Set<String> {
        val pm = packageManager
        val result = mutableSetOf<String>()
        result += Prefs.netBlocked
        result += Prefs.blacklist
        result += VirusDb.maliciousPackages

        return result.filter { pkg ->
            pkg != packageName && !isSystemApp(pm, pkg) && pkg !in Prefs.whitelist
        }.toSet()
    }

    private fun isSystemApp(pm: PackageManager, pkg: String): Boolean {
        return try {
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(pkg, 0)
            }
            info.flags and ApplicationInfo.FLAG_SYSTEM != 0
        } catch (e: Exception) { true }
    }

    private fun buildNotification(): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, ZhiweiApp.CHANNEL_PROTECT)
            .setContentTitle("知微网络拦截运行中")
            .setContentText("被拦截应用的后台连接已被切断")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pi)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    override fun onDestroy() {
        running = false
        isRunning = false
        try { vpnInterface?.close() } catch (e: Exception) { }
        vpnInterface = null
        super.onDestroy()
    }
}