package com.zhiwei.security.service

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import com.zhiwei.security.IZhiweiCallback
import com.zhiwei.security.IZhiweiService
import com.zhiwei.security.core.AuthDb
import com.zhiwei.security.core.BuiltinPrivilege
import com.zhiwei.security.core.DangerousCommands
import com.zhiwei.security.core.Privilege
import com.zhiwei.security.core.SecurityJournal
import com.zhiwei.security.ui.AuthGrantActivity
import com.zhiwei.security.ui.CommandConfirmActivity

/**
 * 知微内置特权服务（对第三方应用开放，Shizuku 式架构）
 *
 * 完整链路：
 * 1. 第三方 App `contentResolver.call("content://com.zhiwei.security.provider", "getBinder")` 拿到 Binder
 *    （对外总开关关闭时 Provider 不下发 Binder，第三方直接拿不到）
 * 2. `requestPermissionWithReason(reason, callback)` → 知微弹授权框（显示申请方 + 理由）
 * 3. 已授权 App 调 `execCommand(cmd)` → 走知微提权通道执行
 *    - 普通命令：直接执行返回
 *    - 危险命令（22 类）：弹「命令拦截」窗口 → 允许一次 / 不允许 / 加入白名单
 * 4. 每次授权变更与命令执行都写入审计（AuthDb.audit），用户可在「授权管理」里翻账
 *
 * 安全边界（诚实声明）：
 * - 调用方身份一律用 `Binder.getCallingUid()` 反查包名，绝不采信参数里的包名。
 * - 知微自己调用自己直接拒绝（uid 相同），避免内部越权。
 * - 对第三方开放的是 shell 级能力（ADB/Root 通道实际等级），不是无条件的 root。
 */
class ZhiweiApiService : Service() {

    companion object {
        /** 协议版本：2（新增理由申请 / release / 运行时信息） */
        const val VERSION = 2

        /** 供 Provider 返回给第三方的服务 Binder（进程内单例） */
        val binder: IBinder by lazy { ZhiweiBinder() }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    private class ZhiweiBinder : IZhiweiService.Stub() {

        /** 按调用方 uid 反查包名；拒绝自身调用与无法识别的调用方 */
        private fun callerPackage(): String? {
            val uid = Binder.getCallingUid()
            val ctx = ZhiweiApiServiceHolder.context ?: return null
            if (uid == android.os.Process.myUid()) return null
            val pkgs = ctx.packageManager.getPackagesForUid(uid) ?: return null
            return pkgs.firstOrNull()
        }

        override fun getVersion(): Int = VERSION

        override fun checkPermission(): Int {
            val pkg = callerPackage() ?: return 0
            return if (AuthDb.isGranted(pkg)) 1 else 0
        }

        override fun requestPermission(callback: IZhiweiCallback?) {
            requestPermissionWithReason("", callback)
        }

        override fun requestPermissionWithReason(reason: String?, callback: IZhiweiCallback?) {
            val ctx = ZhiweiApiServiceHolder.context
            val pkg = callerPackage()
            if (ctx == null || pkg == null || callback == null) {
                try { callback?.onResult(false) } catch (e: Throwable) { }
                return
            }
            if (AuthDb.isGranted(pkg)) {
                try { callback.onResult(true) } catch (e: Throwable) { }
                return
            }
            // 记录申请理由（供授权弹窗展示与用户事后追溯）
            if (!reason.isNullOrBlank()) AuthDb.setRequestReason(pkg, reason)
            AuthGrantActivity.request(ctx, pkg) { granted ->
                AuthDb.audit(pkg, if (granted) "申请授权-用户允许" else "申请授权-用户拒绝", granted)
                try { callback.onResult(granted) } catch (e: Throwable) { }
            }
        }

        override fun releasePermission() {
            val pkg = callerPackage() ?: return
            if (AuthDb.isGranted(pkg)) {
                AuthDb.revoke(pkg)
                SecurityJournal.log("内置特权", "$pkg 主动放弃授权")
            }
        }

        override fun isPrivilegeReady(): Boolean = Privilege.isReady

        override fun getCoreVersion(): String = BuiltinPrivilege.CORE_VERSION

        override fun getRunMode(): String = BuiltinPrivilege.runMode

        override fun getGrantedCount(): Int = try { AuthDb.grantedApps.size } catch (e: Throwable) { 0 }

        override fun execCommand(cmd: String?): String {
            val ctx = ZhiweiApiServiceHolder.context ?: return "-1\n服务未就绪"
            val pkg = callerPackage() ?: return "-1\n无法识别调用方"

            // 0. 对外总开关（用户在设置里一键关停后，立即生效）
            if (!com.zhiwei.security.core.Prefs.builtinPrivilegeEnabled) {
                AuthDb.audit(pkg, "拒绝：对外服务已关闭", false)
                return "-2\n知微内置特权服务未开启"
            }
            // 1. 授权检查
            if (!AuthDb.isGranted(pkg)) {
                AuthDb.audit(pkg, "拒绝：未授权", false)
                return "-1\n未授权：请先 requestPermission"
            }
            if (cmd.isNullOrBlank()) return "-1\n空命令"
            // 2. 提权通道检查
            if (!Privilege.isReady) {
                AuthDb.audit(pkg, "拒绝：提权通道不可用", false)
                return "-1\n知微侧无可用提权通道"
            }

            // 3. 危险命令拦截（只拦命中危险模式的）
            val danger = DangerousCommands.match(cmd)
            if (danger != null && AuthDb.cmdInterceptEnabled && !AuthDb.isCmdWhitelisted(pkg, cmd)) {
                val decision = CommandConfirmActivity.requestBlocking(
                    ctx, pkg, cmd, danger, 60_000L
                )
                when (decision) {
                    CommandConfirmActivity.Decision.DENY,
                    CommandConfirmActivity.Decision.TIMEOUT -> {
                        AuthDb.audit(pkg, "拦截[${danger.category}]：$cmd", false)
                        return "-1\n用户拒绝执行该命令（${danger.category}）"
                    }
                    CommandConfirmActivity.Decision.WHITELIST -> {
                        AuthDb.addCmdWhitelist(pkg, AuthDb.cmdPrefixOf(cmd))
                        AuthDb.audit(pkg, "加入白名单[${danger.category}]：$cmd", true)
                    }
                    CommandConfirmActivity.Decision.ALLOW_ONCE -> {
                        AuthDb.audit(pkg, "放行一次[${danger.category}]：$cmd", true)
                    }
                }
            }

            // 4. 执行
            val (code, out) = Privilege.exec(cmd)
            AuthDb.bumpCallCount(pkg)
            if (danger == null) {
                // 普通命令只记一条短审计（被拦截的危险命令已在上面单独记账）
                AuthDb.audit(pkg, "执行：${cmd.take(40)}", code == 0)
            }
            return "$code\n$out"
        }
    }
}

/** 进程内持有 context，供 Binder 使用（ZhiweiApp.onCreate 注入） */
object ZhiweiApiServiceHolder {
    @Volatile var context: android.content.Context? = null
}
