package com.zhiwei.security.core

import android.content.Context
import android.content.Intent
import android.os.ServiceManager
import android.util.Log
import com.rosan.dhizuku.api.Dhizuku
import com.rosan.dhizuku.api.DhizukuRequestPermissionListener

/**
 * Dhizuku 管理器（内置官方 Dhizuku-API 源码，直接调用）
 *
 * Dhizuku 是「设备所有者(DeviceOwner)权限共享」框架：
 * 用户安装 Dhizuku 应用并把它设为 DeviceOwner 后，本应用可通过其 API
 * 借道系统服务的隐藏 binder 调用 DeviceOwner 特权能力（冻结应用等）。
 */
object DhizukuManager {

    private const val TAG = "DhizukuManager"
    private const val DHIZUKU_PKG = "com.rosan.dhizuku"

    private var inited = false

    fun init(context: Context) {
        if (inited) return
        if (!isInstalled(context)) return
        try {
            inited = Dhizuku.init(context.applicationContext)
        } catch (e: Throwable) {
            Log.w(TAG, "Dhizuku init failed", e)
        }
    }

    /** Dhizuku 应用是否已安装 */
    fun isInstalled(context: Context): Boolean {
        return try {
            context.packageManager.getPackageInfo(DHIZUKU_PKG, 0)
            true
        } catch (e: Exception) { false }
    }

    /** Dhizuku binder 是否可用且已授权 */
    fun isReady(context: Context): Boolean {
        if (!isInstalled(context)) return false
        init(context)
        if (!inited) return false
        return try {
            Dhizuku.isPermissionGranted()
        } catch (e: Throwable) {
            Log.w(TAG, "Dhizuku check failed", e)
            false
        }
    }

    /** 向 Dhizuku 请求授权（异步回调） */
    fun requestPermission(onResult: (Boolean) -> Unit) {
        if (!inited) { onResult(false); return }
        try {
            Dhizuku.requestPermission(object : DhizukuRequestPermissionListener() {
                override fun onRequestPermission(grant: Int) {
                    onResult(grant == 0) // PackageManager.PERMISSION_GRANTED
                }
            })
        } catch (e: Throwable) {
            Log.w(TAG, "requestPermission failed", e)
            onResult(false)
        }
    }

    /** 状态描述 */
    fun statusText(context: Context): String = when {
        !isInstalled(context) -> "Dhizuku 未安装"
        isReady(context) -> "已授权（DeviceOwner 共享可用）"
        else -> "已安装但未授权"
    }

    /**
     * 冻结/解冻应用（DeviceOwner 能力）
     * 经 Dhizuku 包装 device_policy binder，反射调用 setApplicationHidden
     * （反射适配各 Android 版本的方法签名差异）
     */
    fun setAppFrozen(context: Context, pkg: String, frozen: Boolean): Boolean {
        if (!isReady(context)) return false
        return try {
            val raw = ServiceManager.getService(Context.DEVICE_POLICY_SERVICE)
                ?: return false
            val wrapped = Dhizuku.binderWrapper(raw)
            val stubClass = Class.forName("android.app.admin.IDevicePolicyManager\$Stub")
            val dpm = stubClass.getMethod("asInterface", android.os.IBinder::class.java)
                .invoke(null, wrapped) ?: return false
            val admin = Dhizuku.getOwnerComponent()
            // 按参数个数匹配签名（不同 Android 版本有 3/5 参版本）
            val method = dpm.javaClass.methods.firstOrNull {
                it.name == "setApplicationHidden"
            } ?: return false
            val args: Array<Any?> = when (method.parameterCount) {
                3 -> arrayOf(admin, pkg, frozen)
                5 -> arrayOf(admin, pkg, frozen, 0, false)
                else -> return false
            }
            (method.invoke(dpm, *args) as? Boolean) == true
        } catch (e: Throwable) {
            Log.w(TAG, "setAppFrozen failed", e)
            false
        }
    }

    /** 打开 Dhizuku 应用（引导用户授权） */
    fun openDhizuku(context: Context) {
        try {
            context.startActivity(
                context.packageManager.getLaunchIntentForPackage(DHIZUKU_PKG)?.apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            )
        } catch (e: Exception) { }
    }
}