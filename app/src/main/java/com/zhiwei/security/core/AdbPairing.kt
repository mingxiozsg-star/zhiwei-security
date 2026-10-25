package com.zhiwei.security.core

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import android.util.Log
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

/**
 * ADB 无线调试 mDNS 自动发现（Shizuku 同款方案）
 *
 * 开启无线调试后，adbd 会在局域网广播两个服务：
 *  - _adb-tls-pairing._tcp  配对端口（出现在「使用配对码配对设备」弹窗打开时）
 *  - _adb-tls-connect._tcp  连接端口（无线调试首页常驻广播）
 * App 通过 NsdManager 自动拿到 IP+端口，用户只需输入 6 位配对码，
 * 不再手动抄 IP/端口——真正的应用内一键激活。
 */
object AdbPairing {

    private const val TAG = "AdbPairing"
    const val SERVICE_PAIRING = "_adb-tls-pairing._tcp."
    const val SERVICE_CONNECT = "_adb-tls-connect._tcp."

    data class Discovered(val host: String, val port: Int)

    /** 发现指定服务，超时返回 null。pairing 服务只在配对弹窗打开时广播。 */
    suspend fun discover(context: Context, serviceType: String, timeoutMs: Long = 15_000): Discovered? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return null
        val nsd = context.getSystemService(Context.NSD_SERVICE) as? NsdManager ?: return null
        return withTimeoutOrNull(timeoutMs) {
            suspendCancellableCoroutine<Discovered?> { cont ->
                var listener: NsdManager.DiscoveryListener? = null
                var resolveListener: NsdManager.ResolveListener? = null
                fun cleanup() {
                    try { listener?.let { nsd.stopServiceDiscovery(it) } } catch (e: Throwable) { }
                    listener = null
                }
                val dl = object : NsdManager.DiscoveryListener {
                    override fun onDiscoveryStarted(regType: String) { }
                    override fun onServiceFound(service: NsdServiceInfo) {
                        val rl = object : NsdManager.ResolveListener {
                            override fun onResolveFailed(si: NsdServiceInfo, errorCode: Int) { }
                            override fun onServiceResolved(si: NsdServiceInfo) {
                                val host = si.host?.hostAddress ?: "127.0.0.1"
                                val d = Discovered(host, si.port)
                                Log.i(TAG, "resolved $serviceType -> $d")
                                cleanup()
                                if (cont.isActive) cont.resume(d)
                            }
                        }
                        resolveListener = rl
                        try { nsd.resolveService(service, rl) } catch (e: Throwable) { }
                    }
                    override fun onServiceLost(service: NsdServiceInfo) { }
                    override fun onDiscoveryStopped(serviceType: String) { }
                    override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                        if (cont.isActive) cont.resume(null)
                    }
                    override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) { }
                }
                listener = dl
                cont.invokeOnCancellation { cleanup() }
                try {
                    nsd.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, dl)
                } catch (e: Throwable) {
                    if (cont.isActive) cont.resume(null)
                }
            }
        }
    }

    /**
     * 全自动一键激活：
     * 1. 发现配对端口 → adb pair
     * 2. 发现连接端口 → adb connect
     * 全程只需用户提供 6 位配对码。
     */
    suspend fun autoActivate(context: Context, pairCode: String, onLog: (String) -> Unit): Boolean {
        onLog("正在搜索配对服务…（请确保「使用配对码配对设备」弹窗已打开）")
        val p = discover(context, SERVICE_PAIRING, 20_000)
        if (p == null) {
            onLog("未发现配对服务。请打开 开发者选项 → 无线调试 → 使用配对码配对设备")
            return false
        }
        onLog("发现配对服务 ${p.host}:${p.port}，正在配对…")
        val (ok, out) = AdbShell.pair(p.host, p.port, pairCode)
        if (!ok) {
            onLog("配对失败：${out.take(120)}")
            return false
        }
        onLog("配对成功，正在搜索连接端口…")
        val c = discover(context, SERVICE_CONNECT, 15_000)
        if (c == null) {
            onLog("未发现连接服务，请保持无线调试开启后重试")
            return false
        }
        onLog("连接 ${c.host}:${c.port}…")
        val (cok, cout) = AdbShell.connect(c.host, c.port)
        onLog(if (cok) "✅ 提权成功（shell uid=2000）" else "连接失败：${cout.take(120)}")
        return cok
    }
}