package com.zhiwei.security.dhizuku

import android.app.admin.DeviceAdminReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent

/**
 * 知微设备所有者接收器（内置 Dhizuku 的服务端锚点）
 * 一键激活命令（App 内 ADB/Root 通道执行）：
 *   dpm set-device-owner com.zhiwei.security/.dhizuku.ZhiweiDAReceiver
 */
class ZhiweiDAReceiver : DeviceAdminReceiver() {

    companion object {
        val COMPONENT = ComponentName(
            "com.zhiwei.security",
            "com.zhiwei.security.dhizuku.ZhiweiDAReceiver"
        )

        fun isDeviceOwner(context: Context): Boolean {
            return try {
                val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE)
                    as android.app.admin.DevicePolicyManager
                dpm.isDeviceOwnerApp(context.packageName)
            } catch (e: Throwable) { false }
        }
    }

    override fun onEnabled(context: Context, intent: Intent) {
        DhizukuServer.notifyOwnerStateChanged()
    }

    override fun onDisabled(context: Context, intent: Intent) {
        DhizukuServer.notifyOwnerStateChanged()
    }

    override fun onLockTaskModeEntering(context: Context, intent: Intent, pkg: String) {
        DhizukuServer.dispatchLockTaskMode(true)
    }

    override fun onLockTaskModeExiting(context: Context, intent: Intent) {
        DhizukuServer.dispatchLockTaskMode(false)
    }
}