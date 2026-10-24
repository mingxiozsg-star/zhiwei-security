package com.zhiwei.security.core

import android.content.Context
import android.util.Log

/**
 * Dhizuku 管理器（反射接入，不引入编译期依赖）
 *
 * Dhizuku 是「设备所有者(DeviceOwner)权限共享」框架：
 * 用户安装 Dhizuku 并把它设为 DeviceOwner 后，其他应用可通过其 API
 * 调用 DevicePolicyManager 的特权能力（冻结应用、静默卸载、权限授予等）。
 *
 * 本类全部用反射调用，装了 Dhizuku 应用即可用，没装也不影响编译和运行。
 */
object DhizukuManager {

    private const val TAG = "DhizukuManager"
    private const val DHIZUKU_PKG = "com.rosan.dhizuku"

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
        return try {
            val clazz = Class.forName("com.rosan.dhizuku.api.Dhizuku")
            val init = clazz.getMethod("init", Context::class.java)
            init.invoke(null, context.applicationContext)
            val check = clazz.getMethod("checkSelfPermission")
            (check.invoke(null) as Int) == 0 // PackageManager.PERMISSION_GRANTED
        } catch (e: Throwable) {
            Log.w(TAG, "Dhizuku check failed", e)
            false
        }
    }

    /** 状态描述 */
    fun statusText(context: Context): String = when {
        !isInstalled(context) -> "Dhizuku 未安装"
        isReady(context) -> "已授权（DeviceOwner 共享可用）"
        else -> "已安装但未授权"
    }

    /**
     * 通过 Dhizuku 的 DeviceOwner 能力执行设备管理操作
     * （冻结/解冻应用：setApplicationHidden 需要 DeviceOwner）
     */
    fun setAppFrozen(context: Context, pkg: String, frozen: Boolean): Boolean {
        if (!isReady(context)) return false
        return try {
            // 通过 Dhizuku 拿到 DevicePolicyManager 的远程 binder 调用
            val clazz = Class.forName("com.rosan.dhizuku.api.Dhizuku")
            val getDPM = clazz.getMethod("getDevicePolicyManager")
            val dpm = getDPM.invoke(null)
            val dpmClass = dpm.javaClass
            val method = dpmClass.getMethod(
                "setApplicationHidden",
                android.content.ComponentName::class.java,
                String::class.java,
                Boolean::class.java
            )
            // DeviceOwner 的 ComponentName 属于 Dhizuku 自己
            val adminField = clazz.getMethod("getAdminComponent")
            val admin = adminField.invoke(null) as android.content.ComponentName
            method.invoke(dpm, admin, pkg, frozen) as Boolean
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
                    addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            )
        } catch (e: Exception) { }
    }
}