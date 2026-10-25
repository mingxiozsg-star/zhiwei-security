package com.zhiwei.security.service

import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Binder
import android.os.IBinder
import com.zhiwei.security.IZhiweiCallback
import com.zhiwei.security.IZhiweiService
import com.zhiwei.security.core.AuthDb
import com.zhiwei.security.core.DangerousCommands
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.core.Privilege
import com.zhiwei.security.ui.AuthGrantActivity
import com.zhiwei.security.ui.CommandConfirmActivity

/**
 * 知微特权服务（对第三方应用开放，Shizuku 式架构）
 *
 * 流程：
 * 1. 第三方应用 contentResolver.call(ZhiweiProvider) 拿到 Binder
 * 2. requestPermission() → 知微弹授权框（允许/拒绝），结果经 IZhiweiCallback 返回
 * 3. 已授权应用调 execCommand() → 走知微提权通道执行
 *    - 普通命令：直接执行返回
 *    - 危险命令（rm -rf/pm uninstall/改无障碍/改锁屏密码等 22 类）：
 *      弹「命令拦截」窗口 → 允许一次 / 不允许 / 加入白名单
 */
class ZhiweiApiService : Service() {

    companion object {
        const val VERSION = 1

        /** 供 Provider 返回给第三方的服务 Binder（进程内单例） */
        val binder: IBinder by lazy { ZhiweiBinder() }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    private class ZhiweiBinder : IZhiweiService.Stub() {

        private fun callerPackage(service: ZhiweiApiService?): String? {
            val uid = Binder.getCallingUid()
            val ctx = ZhiweiApiServiceHolder.context ?: return null
            // 拒绝知微自己调用自己
            if (uid == android.os.Process.myUid()) return null
            val pkgs = ctx.packageManager.getPackagesForUid(uid) ?: return null
            return pkgs.firstOrNull()
        }

        override fun getVersion(): Int = VERSION

        override fun checkPermission(): Int {
            val pkg = callerPackage(null) ?: return 0
            return if (AuthDb.isGranted(pkg)) 1 else 0
        }

        override fun requestPermission(callback: IZhiweiCallback?) {
            val ctx = ZhiweiApiServiceHolder.context
            val pkg = callerPackage(null)
            if (ctx == null || pkg == null || callback == null) {
                try { callback?.onResult(false) } catch (e: Throwable) { }
                return
            }
            if (AuthDb.isGranted(pkg)) {
                try { callback.onResult(true) } catch (e: Throwable) { }
                return
            }
            // 弹授权框（允许/拒绝），结果异步回调
            AuthGrantActivity.request(ctx, pkg) { granted ->
                try { callback.onResult(granted) } catch (e: Throwable) { }
            }
        }

        override fun isPrivilegeReady(): Boolean = Privilege.isReady

        override fun execCommand(cmd: String?): String {
            val ctx = ZhiweiApiServiceHolder.context ?: return "-1\n服务未就绪"
            val pkg = callerPackage(null) ?: return "-1\n无法识别调用方"

            // 1. 授权检查
            if (!AuthDb.isGranted(pkg)) return "-1\n未授权：请先 requestPermission"

            if (cmd.isNullOrBlank()) return "-1\n空命令"

            // 2. 提权通道检查
            if (!Privilege.isReady) return "-1\n知微侧无可用提权通道"

            // 3. 危险命令拦截（不是所有命令都拦，只拦命中危险模式的）
            if (AuthDb.cmdInterceptEnabled && !AuthDb.isCmdWhitelisted(pkg, cmd)) {
                val danger = DangerousCommands.match(cmd)
                if (danger != null) {
                    // 弹「命令拦截」窗口，同步等待用户决定（60 秒超时视为拒绝）
                    val decision = CommandConfirmActivity.requestBlocking(
                        ctx, pkg, cmd, danger, 60_000L
                    )
                    when (decision) {
                        CommandConfirmActivity.Decision.DENY,
                        CommandConfirmActivity.Decision.TIMEOUT ->
                            return "-1\n用户拒绝执行该命令（${danger.category}）"
                        CommandConfirmActivity.Decision.WHITELIST ->
                            AuthDb.addCmdWhitelist(pkg, AuthDb.cmdPrefixOf(cmd))
                        CommandConfirmActivity.Decision.ALLOW_ONCE -> { /* 放行这一次 */ }
                    }
                }
            }

            // 4. 执行
            val (code, out) = Privilege.exec(cmd)
            return "$code\n$out"
        }
    }
}

/** 进程内持有 context，供 Binder 使用（ZhiweiApp.onCreate 注入） */
object ZhiweiApiServiceHolder {
    @Volatile var context: android.content.Context? = null
}