package com.zhiwei.security.service

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
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
import com.zhiwei.security.core.SecurityJournal
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
 * 关闭可靠性（v1.7.0 重写，修「VPN 开了关不掉」）：
 * - START_NOT_STICKY：stopService 后系统不再自动重建（旧版 START_STICKY 是关不掉的根因）
 * - 读线程持有独立 FileInputStream，shutdown 先关流让阻塞 read 立刻抛错退出
 * - stopRequested 静态标记跨实例生效，杜绝 restart 竞态下旧实例残留
 * - onRevoke 完整清理；服务内自检 Prefs.netGuardEnabled，配置为关则自杀
 * - 通知栏内置「关闭拦截」按钮
 */
class NetGuardService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var pumpThread: Thread? = null
    private var pumpStream: FileInputStream? = null
    @Volatile private var running = false

    companion object {
        private const val NOTIFICATION_ID = 1005
        const val ACTION_STOP = "com.zhiwei.security.action.NETGUARD_STOP"

        @Volatile var isRunning = false
            private set

        /** 主动停止标记：跨实例生效，阻止任何路径把服务重新拉起来 */
        @Volatile private var stopRequested = false

        fun start(context: Context) {
            stopRequested = false
            val intent = Intent(context, NetGuardService::class.java)
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            } catch (e: Throwable) { }
        }

        /** 停止：置标记 → 发停止指令 → stopService 双保险 */
        fun stop(context: Context) {
            stopRequested = true
            try { Prefs.netGuardEnabled = false } catch (e: Throwable) { }
            try {
                context.startService(
                    Intent(context, NetGuardService::class.java).setAction(ACTION_STOP)
                )
            } catch (e: Throwable) { }
            try { context.stopService(Intent(context, NetGuardService::class.java)) } catch (e: Throwable) { }
        }

        /** 名单/配置变化后重建 VPN（未开启则不动） */
        fun restart(context: Context) {
            if (try { Prefs.netGuardEnabled } catch (e: Throwable) { false }) return
            stopRequested = true
            try { context.stopService(Intent(context, NetGuardService::class.java)) } catch (e: Throwable) { }
            // stopService 异步，立刻 start 可能新旧实例并存导致新实例 establish 失败 → 稍等再拉
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                try {
                    stopRequested = false
                    start(context)
                } catch (e: Throwable) { }
            }, 600)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Prefs 必须在使用前初始化（onStartCommand 会比 establishVpn 更早读到开关）
        try { Prefs.init(applicationContext) } catch (e: Throwable) { }

        // 显式停止指令：清理后返回 NOT_STICKY，系统不会复活
        if (intent?.action == ACTION_STOP || stopRequested || !Prefs.netGuardEnabled) {
            shutdown()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, buildNotification())

        // 用 vpnInterface 判空而不是 running：restart() 竞态下新实例能正确重建
        if (vpnInterface == null) establishVpn()

        // 关键：NOT_STICKY。是否重启交给 GuardService 按用户开关判断，
        // 绝不能让系统无条件复活——那是「VPN 关不掉」的直接原因。
        return START_NOT_STICKY
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
            shutdown()
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
            if (added == 0 && c2Ips.isEmpty()) { shutdown(); return }
            builder.addRoute("0.0.0.0", 0)
        }

        val fd = try { builder.establish() } catch (e: Throwable) { null }
        if (fd == null) { shutdown(); return }

        vpnInterface = fd
        running = true
        isRunning = true
        SecurityJournal.log("网络拦截", "已开启（${blockedApps.size} 个应用被断网）")

        // 黑洞：读包即丢弃。线程持有自己的流引用，关闭时才能可靠打断阻塞 read
        pumpThread = thread(name = "netguard-pump") {
            val input = try { FileInputStream(fd.fileDescriptor) } catch (e: Throwable) { null }
            pumpStream = input
            if (input == null) {
                if (isRunning) shutdown()
                return@thread
            }
            val buffer = ByteArray(32767)
            try {
                while (running && !stopRequested) {
                    val len = input.read(buffer)
                    if (len < 0) break
                    // 丢弃，不转发——被拦应用的网络请求全部石沉大海
                }
            } catch (e: Throwable) {
                // close() 会让这里抛 IOException，属正常退出路径
            } finally {
                try { input.close() } catch (e: Throwable) { }
                if (isRunning && !stopRequested) shutdown()
            }
        }
    }

    /** 统一收尾：先断读线程、再关 fd、再撤通知，顺序错会让线程卡死 */
    private fun shutdown() {
        val wasRunning = isRunning
        running = false
        isRunning = false

        // 1. 关流与 fd —— 让阻塞在 read 的线程立即抛错
        try { pumpStream?.close() } catch (e: Throwable) { }
        pumpStream = null
        try { vpnInterface?.close() } catch (e: Throwable) { }
        vpnInterface = null

        // 2. 线程兜底中断
        try { pumpThread?.interrupt() } catch (e: Throwable) { }
        pumpThread = null

        // 3. 撤前台通知（不撤会留下永久通知栏卡片）
        try { stopForeground(true) } catch (e: Throwable) { }
        try {
            val nm = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
            nm.cancel(NOTIFICATION_ID)
        } catch (e: Throwable) { }

        if (wasRunning) SecurityJournal.log("网络拦截", "已关闭")
        try { stopSelf() } catch (e: Throwable) { }
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
        // 通知栏直接给「关闭」按钮，不必回应用也能停
        val stopPi = PendingIntent.getService(
            this, 1,
            Intent(this, NetGuardService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, ZhiweiApp.CHANNEL_PROTECT)
            .setContentTitle("知微网络拦截运行中")
            .setContentText("被拦截应用的后台连接已被切断")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pi)
            .addAction(0, "关闭拦截", stopPi)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    override fun onDestroy() {
        running = false
        isRunning = false
        try { pumpStream?.close() } catch (e: Throwable) { }
        pumpStream = null
        try { vpnInterface?.close() } catch (e: Throwable) { }
        vpnInterface = null
        try { pumpThread?.interrupt() } catch (e: Throwable) { }
        pumpThread = null
        try { stopForeground(true) } catch (e: Throwable) { }
        super.onDestroy()
    }

    /** 用户/系统在「设置→网络→VPN」里撤销，或被其他 VPN 抢占时回调 */
    override fun onRevoke() {
        stopRequested = true
        Prefs.netGuardEnabled = false
        shutdown()
        try { super.onRevoke() } catch (e: Throwable) { }
    }
}