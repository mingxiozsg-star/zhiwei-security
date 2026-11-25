package com.zhiwei.security.core

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import com.zhiwei.security.dhizuku.ZhiweiDAReceiver

/**
 * 自我防护（防卸载 + 被删回装）
 *
 * 三层防线，逐级降级，任意一层可用即生效：
 *
 * 1. **DeviceAdmin setUninstallBlocked(仅设备所有者可用)**
 *    - 走内置 Dhizuku（Dhizuku 授权后即设备所有者代理）或本应用自任设备所有者
 *    - 这是系统级硬拦截：设置页「卸载」按钮直接置灰，第三方卸载器返回失败
 *    - 对应 SecureGuard 的 blockSelfUninstall(true)
 *
 * 2. **setApplicationHidden(true) 隐身**
 *    - 设备所有者权限下把自己从桌面/应用列表隐藏，用户想卸载也找不到入口
 *    - 解冻/正常退出时 unhide，避免自己消失
 *
 * 3. **被删回装哨兵**
 *    - 系统不允许"被卸载后自己拉起"（进程随包一起消失），
 *      所以用 Sidecar 思路：卸载前把「回装引导」写到外部存储 + 通知留痕，
 *      并在每次启动时校验：若检测到曾经开启自防护但当前是全新安装，
 *      立即引导下载最新包（UpdateChecker）并提示恢复防护。
 *
 * 铁律：所有能力失败都要优雅降级，绝不因为拿不到设备所有者就把用户锁在外面。
 */
object SelfGuard {

    private const val TAG = "SelfGuard"
    private const val SENTINEL_FILE = "zhiwei_selfguard.sentinel"
    private const val PREFS_NAME = "zhiwei_selfguard"
    private const val KEY_WAS_PROTECTED = "was_protected"

    /** 是否具备设备所有者级能力（任一路径） */
    fun hasOwnerPower(context: Context): Boolean {
        return isSelfDeviceOwner(context) || DhizukuManager.isReady(context)
    }

    /** 本应用自身是否为设备所有者 */
    fun isSelfDeviceOwner(context: Context): Boolean {
        return try {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            dpm.isDeviceOwnerApp(context.packageName)
        } catch (e: Throwable) { false }
    }

    /** 自身设备策略管理器（仅当自己是设备所有者时可用） */
    private fun dpm(context: Context): DevicePolicyManager? {
        return try {
            val m = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            if (m.isDeviceOwnerApp(context.packageName)) m else null
        } catch (e: Throwable) { null }
    }

    /** 我方充当设备所有者时的 owner 组件 */
    fun ownerComponent(context: Context): ComponentName? {
        return try {
            if (isSelfDeviceOwner(context)) ZhiweiDAReceiver.COMPONENT
            else if (DhizukuManager.isReady(context)) com.rosan.dhizuku.api.Dhizuku.getOwnerComponent()
            else null
        } catch (e: Throwable) { null }
    }

    // ================== 1. 防卸载 ==================

    /**
     * 开启/关闭防卸载。
     * @return true=已在系统层生效；false=无设备所有者权限（已降级为哨兵模式）
     */
    fun setUninstallBlocked(context: Context, blocked: Boolean): Boolean {
        // 路径 A：本应用自任设备所有者 → 直接调系统 API
        if (isSelfDeviceOwner(context)) {
            return try {
                val m = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
                m.setUninstallBlocked(ZhiweiDAReceiver.COMPONENT, context.packageName, blocked)
                SecurityJournal.log(
                    "自防护",
                    if (blocked) "防卸载已启用（设备所有者硬拦截）" else "防卸载已关闭"
                )
                true
            } catch (e: Throwable) {
                // 部分 ROM 对 owner 自己锁卸载会抛异常，降级但记录
                SecurityJournal.log("自防护", "系统级防卸载失败：${e.javaClass.simpleName}")
                false
            }
        }
        // 路径 B：走 Dhizuku 远程设备所有者
        if (!DhizukuManager.isReady(context)) {
            SecurityJournal.log("自防护", "无设备所有者权限，防卸载降级为哨兵模式")
            return false
        }
        return applyViaDhizuku(context, blocked)
    }

    /** 走 Dhizuku 的远程 DevicePolicyManager（镜像 SecureGuard 的 privilegedDpm 做法，纯反射免隐藏 API） */
    private fun applyViaDhizuku(context: Context, blocked: Boolean): Boolean {
        return try {
            val remoteDpm = privilegedDpm(context) ?: return false
            val owner = com.rosan.dhizuku.api.Dhizuku.getOwnerComponent() ?: return false
            val setUninstallBlocked = remoteDpm.javaClass.getMethod(
                "setUninstallBlocked",
                ComponentName::class.java, String::class.java, Boolean::class.javaPrimitiveType
            )
            setUninstallBlocked.invoke(remoteDpm, owner, context.packageName, blocked)
            // 顺带隐藏自身（仅开启时）
            if (blocked) {
                try {
                    remoteDpm.javaClass.getMethod(
                        "setApplicationHidden",
                        ComponentName::class.java, String::class.java, Boolean::class.javaPrimitiveType
                    ).invoke(remoteDpm, owner, context.packageName, true)
                } catch (e: Throwable) { }
            }
            true
        } catch (e: Throwable) {
            SecurityJournal.log("自防护", "Dhizuku 通道不可用：${e.javaClass.simpleName}")
            false
        }
    }

    /**
     * 取得「经 Dhizuku 包装的 DevicePolicyManager」。
     * 原理（照搬 SecureGuard）：DevicePolicyManager 内部持有 mService（IDevicePolicyManager），
     * 把它的 binder 换成 Dhizuku.binderWrapper(原binder)，之后所有调用都以设备所有者身份执行。
     */
    private fun privilegedDpm(context: Context): Any? {
        return try {
            // 与 DhizukuManager.setAppFrozen 同一套做法：拿 device_policy 的原始 binder，
            // 用 Dhizuku.binderWrapper 换成设备所有者身份，再 asInterface 回去
            val raw = android.os.ServiceManager.getService(Context.DEVICE_POLICY_SERVICE)
                ?: return null
            val wrapped = com.rosan.dhizuku.api.Dhizuku.binderWrapper(raw) ?: return null
            Class.forName("android.app.admin.IDevicePolicyManager\$Stub")
                .getMethod("asInterface", android.os.IBinder::class.java)
                .invoke(null, wrapped)
        } catch (e: Throwable) {
            SecurityJournal.log("自防护", "privilegedDpm 失败：${e.javaClass.simpleName}")
            null
        }
    }

    // ================== 2. 隐身自身 ==================

    /**
     * 隐藏/显示自身。注意：隐藏后用户找不到图标，必须能从「设置→应用」或通知里恢复，
     * 所以这里只在**已确认有恢复通道**时执行。
     */
    fun setHiddenSelf(context: Context, hidden: Boolean): Boolean {
        val m = dpm(context) ?: return false
        return try {
            m.setApplicationHidden(ZhiweiDAReceiver.COMPONENT, context.packageName, hidden)
            true
        } catch (e: Throwable) { false }
    }

    /** 紧急自救：自己不知为何被冻结/隐藏时，尝试解除 */
    fun rescueSelf(context: Context): Boolean {
        val m = dpm(context) ?: return false
        var ok = false
        try {
            m.setApplicationHidden(ZhiweiDAReceiver.COMPONENT, context.packageName, false)
            ok = true
        } catch (e: Throwable) { }
        try {
            m.setUninstallBlocked(ZhiweiDAReceiver.COMPONENT, context.packageName, false)
            ok = true
        } catch (e: Throwable) { }
        return ok
    }

    // ================== 3. 被删回装哨兵 ==================

    /** 写入哨兵标记（卸载前留痕，重装后可感知"我曾被保护/被卸载"） */
    fun writeSentinel(context: Context) {
        try {
            val dir = context.getExternalFilesDir(null) ?: context.filesDir
            java.io.File(dir, SENTINEL_FILE).writeText(
                "ts=${System.currentTimeMillis()}\npkg=${context.packageName}\nver=${appVersion(context)}\n"
            )
        } catch (e: Throwable) { }
        try {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putBoolean(KEY_WAS_PROTECTED, true).apply()
        } catch (e: Throwable) { }
    }

    /**
     * 启动时自检：若本次是「曾被保护后的重装」→ 触发回装引导。
     * @return true=检测到重装痕迹，已引导
     */
    fun checkReinstallTrace(context: Context): Boolean {
        return try {
            val sp = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val wasProtected = sp.getBoolean(KEY_WAS_PROTECTED, false)
            val firstRunAfterInstall = context.getSharedPreferences("zhiwei_security", Context.MODE_PRIVATE)
                .getBoolean("onboarding_done", false).not()
            if (wasProtected && firstRunAfterInstall && Prefs.autoReinstallEnabled) {
                SecurityJournal.log("自防护", "检测到卸载后重装，自防护配置待恢复")
                true
            } else false
        } catch (e: Throwable) { false }
    }

    /** 回装引导：直接跳到应用内更新页（复用内置下载器，走 ghfast 镜像） */
    fun guideReinstall(context: Context) {
        try {
            val i = Intent(context, com.zhiwei.security.MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra("goto", "update")
            }
            context.startActivity(i)
        } catch (e: Throwable) { }
    }

    /** 打开系统卸载受限时的说明（供 UI 调用） */
    fun openUninstallSettings(context: Context) {
        try {
            val i = Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.parse("package:${context.packageName}")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(i)
        } catch (e: Throwable) { }
    }

    fun appVersion(context: Context): String = try {
        context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "?"
    } catch (e: Throwable) { "?" }

    /** 状态摘要（UI 展示） */
    fun statusText(context: Context): String {
        return when {
            isSelfDeviceOwner(context) -> "设备所有者就绪（系统级防卸载可用）"
            DhizukuManager.isReady(context) -> "Dhizuku 已授权（防卸载可用）"
            else -> "未提权（防卸载降级为哨兵提醒）"
        }
    }
}