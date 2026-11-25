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
import com.zhiwei.security.core.BlockAdsRules
import com.zhiwei.security.core.DnsPacket
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.core.SecurityJournal
import com.zhiwei.security.core.VirusDb
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/**
 * 后台网络防护服务（VPN 模式）
 *
 * 两种能力可独立/叠加开启：
 *
 * A. 应用级断网（黑洞）：把名单内的应用流量路由进 tun 后直接丢弃，
 *    该应用网络等于被物理切断；系统应用一律豁免。
 *
 * B. 域名级过滤（DNS）：只把「公网 DNS 服务器 IP」的 /32 路由引进来，
 *    在 tun 内解 DNS 查询 —— 命中规则回 A=0.0.0.0，未命中用 protect() 过的
 *    socket 真正转发到原上游。普通上网流量完全不经过 VPN，零性能损失。
 *
 * 关闭可靠性（v1.7.0 起）：
 * - START_NOT_STICKY：stopService 后系统不再自动重建（旧版 START_STICKY 是关不掉的根因）
 * - 读线程持有独立 FileInputStream，shutdown 先关流让阻塞 read 立刻抛错退出
 * - stopRequested 静态标记跨实例生效，杜绝 restart 竞态下旧实例残留
 * - onRevoke 完整清理；服务自检配置为关则自杀；通知栏内置「关闭拦截」按钮
 */
class NetGuardService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var pumpThread: Thread? = null
    private var pumpStream: FileInputStream? = null
    private var pumpOut: FileOutputStream? = null
    private val writeLock = Any()
    @Volatile private var running = false

    /** 本次会话累计拦截数（内存计数，退出时落盘） */
    @Volatile private var blockedInSession = 0L

    /** DNS 转发线程池（小固定池，避免慢上游堵住读循环） */
    private val dnsPool: ExecutorService = Executors.newFixedThreadPool(2)

    companion object {
        private const val NOTIFICATION_ID = 1005
        const val ACTION_STOP = "com.zhiwei.security.action.NETGUARD_STOP"

        /** 需要导入 tun 的公网 DNS 服务器（域名过滤只拦这些） */
        private val DNS_SERVERS = arrayOf(
            "8.8.8.8", "8.8.4.4",              // Google
            "1.1.1.1", "1.0.0.1",              // Cloudflare
            "9.9.9.9", "149.112.112.112",      // Quad9
            "208.67.222.222", "208.67.220.220", // OpenDNS
            "114.114.114.114", "114.114.115.115", // 114DNS
            "223.5.5.5", "223.6.6.6",          // 阿里
            "119.29.29.29", "182.254.116.116", // 腾讯
            "180.76.76.76",                    // 百度
            "101.226.4.6", "218.30.118.6"      // 电信
        )

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
            // v1.8.0 修：原条件写反（enabled 时直接 return），导致开着 VPN 改名单永不生效
            val enabled = try { Prefs.netGuardEnabled } catch (e: Throwable) { false }
            if (!enabled) return
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
        // C2 失陷指标 IP（"ip:port" 格式 → 提取 ip 做 /32 黑洞路由）
        val c2Ips = if (Prefs.c2FilterEnabled) VirusDb.c2Indicators.mapNotNull {
            it.substringBefore(":").takeIf { ip -> ip.matches(Regex("""\d+\.\d+\.\d+\.\d+""")) }
        } else emptyList()
        // 域名过滤（全局生效，不限应用）
        val dnsFilter = Prefs.blockAdsEnabled
        if (dnsFilter) try { BlockAdsRules.load(this) } catch (e: Throwable) { }

        if (blockedApps.isEmpty() && c2Ips.isEmpty() && !dnsFilter) {
            // 没有要拦的对象就不起 VPN，省电
            shutdown()
            return
        }

        val builder = Builder()
            .setSession(if (dnsFilter) "知微网络防护（域名过滤）" else "知微网络拦截")
            .addAddress("10.0.0.2", 32)
            .setBlocking(true)

        // C2 IP 黑洞路由：任何应用连 C2 服务器的流量进 VPN 被丢弃
        c2Ips.forEach { ip ->
            try { builder.addRoute(ip, 32) } catch (e: Exception) { }
        }

        // 应用级断网：只让被拦截的应用进 VPN（其他应用流量绕行，零影响）
        var added = 0
        blockedApps.forEach { pkg ->
            try {
                builder.addAllowedApplication(pkg)
                added++
            } catch (e: Exception) { }
        }

        if (blockedApps.isNotEmpty()) {
            // 有应用级断网时，这些应用的流量才需要全量导入
            if (added == 0 && c2Ips.isEmpty() && !dnsFilter) { shutdown(); return }
            try { builder.addRoute("0.0.0.0", 0) } catch (e: Exception) { }
        }

        if (dnsFilter) {
            // 域名过滤是全局能力：只把公网 DNS 的 /32 路由引进 tun，
            // 其余流量（含被断网应用之外的普通上网）不受影响。
            DNS_SERVERS.forEach { ip ->
                try { builder.addRoute(ip, 32) } catch (e: Exception) { }
            }
        }
        // 自身流量绕开 VPN，避免自己探测更新/上传特征库被断网
        try { builder.addDisallowedApplication(packageName) } catch (e: Exception) { }

        val fd = try { builder.establish() } catch (e: Throwable) { null }
        if (fd == null) { shutdown(); return }

        vpnInterface = fd
        try { pumpOut = FileOutputStream(fd.fileDescriptor) } catch (e: Throwable) { pumpOut = null }
        running = true
        isRunning = true

        val mode = when {
            dnsFilter && blockedApps.isNotEmpty() -> "域名过滤 + ${blockedApps.size} 个应用断网"
            dnsFilter -> "域名过滤（${BlockAdsRules.ruleCount} 条规则）"
            else -> "${blockedApps.size} 个应用被断网"
        }
        SecurityJournal.log("网络拦截", "已开启（$mode）")

        // 线程持有自己的流引用，关闭时才能可靠打断阻塞 read
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
                    val len = try { input.read(buffer) } catch (e: Throwable) { -1 }
                    if (len < 0) break
                    if (len == 0) continue
                    // 域名过滤开启时，先看是不是 DNS 查询并裁决
                    if (dnsFilter) {
                        try { handleDns(buffer, len) } catch (e: Throwable) { }
                    }
                    // 其余一律丢弃，不转发（被拦应用的包就断在这里）
                }
            } catch (e: Throwable) {
                // close() 会让这里抛 IOException，属正常退出路径
            } finally {
                try { input.close() } catch (e: Throwable) { }
                if (isRunning && !stopRequested) shutdown()
            }
        }
    }

    /**
     * DNS 过滤核心（含真实转发，缺了转发会全网 DNS 瘫痪）：
     * - 命中规则 → 本地造 A=0.0.0.0 应答，直接回写 tun
     * - 未命中   → 用 protect() 过的独立 socket 代发到原上游 DNS，把响应回写 tun
     *
     * 转发必须走 protect()：否则转发出去的包又会回到 tun，形成死循环。
     */
    private fun handleDns(buf: ByteArray, len: Int) {
        if (DnsPacket.udpDstPort(buf, len) != DnsPacket.DNS_PORT_NUM) return
        val off = DnsPacket.payloadOffset(buf, len)
        if (off < 0) return
        val dnsLen = len - off
        val query = ByteArray(dnsLen)
        System.arraycopy(buf, off, query, 0, dnsLen)
        val domain = DnsPacket.questionName(query, dnsLen) ?: return

        if (BlockAdsRules.shouldBlock(domain)) {
            val answer = DnsPacket.buildZeroAnswer(query, dnsLen) ?: return
            val resp = DnsPacket.buildUdpResponse(buf, len, answer, answer.size) ?: return
            writeToTun(resp)
            // 计数走内存，避免每个被拦请求都写一次 SharedPreferences（磁盘 IO）
            blockedInSession++
            return
        }

        // 未命中：异步转发，避免慢 DNS 卡死整条读循环
        val pkt = buf.copyOf(len)
        val upstream = DnsPacket.dstIp(buf, len) ?: return
        try {
            dnsPool.execute { forwardAndReply(upstream, query, pkt, len) }
        } catch (e: Throwable) { }
    }

    /** 代查上游 DNS 并把响应写回 tun */
    private fun forwardAndReply(upstream: String, query: ByteArray, clientPacket: ByteArray, clientLen: Int) {
        var socket: java.net.DatagramSocket? = null
        try {
            socket = java.net.DatagramSocket()
            // 关键：protect 让这个 socket 的流量绕过 VPN，直接走底层网络
            if (!protect(socket)) return
            socket.soTimeout = 4000
            val addr = java.net.InetAddress.getByName(upstream)
            socket.send(java.net.DatagramPacket(query, query.size, addr, DnsPacket.DNS_PORT_NUM))
            val rbuf = ByteArray(4096)
            val rp = java.net.DatagramPacket(rbuf, rbuf.size)
            socket.receive(rp)
            if (rp.length <= 0) return
            val payload = rp.data.copyOf(rp.length)
            val out = DnsPacket.buildUdpResponse(clientPacket, clientLen, payload, payload.size) ?: return
            writeToTun(out)
        } catch (e: Throwable) {
            // 超时或上游不可达：不回应，客户端会自行重试（等价于弱网表现）
        } finally {
            try { socket?.close() } catch (e: Throwable) { }
        }
    }

    /** 向 tun 写包（持有持久输出流，避免每次 open 的开销） */
    private fun writeToTun(packet: ByteArray): Boolean {
        return try {
            val out = pumpOut ?: return false
            synchronized(writeLock) { out.write(packet) }
            true
        } catch (e: Throwable) {
            false
        }
    }

    /** 统一收尾：先断读线程、再关 fd、再撤通知，顺序错会让线程卡死 */
    private fun shutdown() {
        val wasRunning = isRunning
        running = false
        isRunning = false
        // 会话计数落盘（一次写，避免热路径频繁 IO）
        if (blockedInSession > 0) {
            try { Prefs.dnsBlockedCount = Prefs.dnsBlockedCount + blockedInSession } catch (e: Throwable) { }
            blockedInSession = 0L
        }

        // 1. 关流与 fd —— 让阻塞在 read 的线程立即抛错
        try { pumpStream?.close() } catch (e: Throwable) { }
        pumpStream = null
        try { pumpOut?.close() } catch (e: Throwable) { }
        pumpOut = null
        try { vpnInterface?.close() } catch (e: Throwable) { }
        vpnInterface = null

        // 2. 线程兜底中断
        try { pumpThread?.interrupt() } catch (e: Throwable) { }
        pumpThread = null
        try { dnsPool.shutdownNow() } catch (e: Throwable) { }

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
        val dns = try { Prefs.blockAdsEnabled } catch (e: Throwable) { false }
        val blocked = try { Prefs.dnsBlockedCount } catch (e: Throwable) { 0 }
        return NotificationCompat.Builder(this, ZhiweiApp.CHANNEL_PROTECT)
            .setContentTitle("知微网络防护运行中")
            .setContentText(
                if (dns) "域名过滤已启用 · 已拦截 $blocked 次"
                else "被拦截应用的后台连接已被切断"
            )
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
        try { pumpOut?.close() } catch (e: Throwable) { }
        pumpOut = null
        try { vpnInterface?.close() } catch (e: Throwable) { }
        vpnInterface = null
        try { pumpThread?.interrupt() } catch (e: Throwable) { }
        pumpThread = null
        try { dnsPool.shutdownNow() } catch (e: Throwable) { }
        try { stopForeground(true) } catch (e: Throwable) { }
        super.onDestroy()
    }

    /** 用户/系统在「设置→网络→VPN」里撤销，或被其他 VPN 抢占时回调 */
    override fun onRevoke() {
        stopRequested = true
        try { Prefs.netGuardEnabled = false } catch (e: Throwable) { }
        shutdown()
        try { super.onRevoke() } catch (e: Throwable) { }
    }
}