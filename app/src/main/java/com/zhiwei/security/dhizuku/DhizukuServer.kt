package com.zhiwei.security.dhizuku

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.RemoteException
import com.rosan.dhizuku.aidl.IDhizuku
import com.rosan.dhizuku.aidl.IDhizukuLockTaskModeListener
import com.rosan.dhizuku.aidl.IDhizukuRemoteProcess
import com.rosan.dhizuku.aidl.IDhizukuUserServiceConnection
import com.rosan.dhizuku.shared.DhizukuVariables
import com.zhiwei.security.core.AuthDb
import com.zhiwei.security.core.DangerousCommands
import com.zhiwei.security.core.Privilege
import com.zhiwei.security.service.ZhiweiApiServiceHolder
import com.zhiwei.security.ui.CommandConfirmActivity
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * 内置 Dhizuku 服务端（完整实现官方协议，非空壳）
 *
 * 发现机制与官方一致：客户端通过「设备所有者组件 → 包名 → provider」找到我们，
 * 我们成为 Device Owner 后，任何使用 Dhizuku-API 的应用自动对接知微。
 *
 * 已实现能力：
 * - getVersionCode/getVersionName
 * - isPermissionGranted（按调用方 uid → 包名查授权库）
 * - remote binder transact（code 11，以知微身份转发任意 Binder 调用——Dhizuku 的核心能力）
 * - remoteProcess（在知微进程启动进程，stdin/stdout/stderr 全双工管道）
 * - bindUserService（加载客户端 UserService 类并在知微进程实例化，官方同款机制）
 * - get/setDelegatedScopes（作用域存储）
 * - LockTaskMode 事件转发
 */
object DhizukuServer {

    const val SERVER_VERSION_CODE = 8
    const val SERVER_VERSION_NAME = "zhiwei-dhizuku-1.0"

    private val lockTaskListeners = CopyOnWriteArrayList<IDhizukuLockTaskModeListener>()
    private val delegatedScopes = ConcurrentHashMap<String, Array<out String>>()
    private val userServices = ConcurrentHashMap<String, android.app.Service>()

    @Volatile var context: Context? = null

    val binder: IBinder by lazy { DhizukuBinder() }

    fun notifyOwnerStateChanged() { }

    fun dispatchLockTaskMode(entering: Boolean, pkg: String = "") {
        for (l in lockTaskListeners) {
            try { l.onLockTaskModeChanged(entering, pkg) } catch (e: Throwable) { }
        }
    }

    private fun callerPackage(): String? {
        val uid = Binder.getCallingUid()
        val ctx = context ?: return null
        if (uid == android.os.Process.myUid()) return ctx.packageName
        return ctx.packageManager.getPackagesForUid(uid)?.firstOrNull()
    }

    private fun requireGranted(): String {
        val pkg = callerPackage() ?: throw RemoteException("unknown caller")
        if (!AuthDb.isGranted(pkg)) throw RemoteException("permission denied: $pkg")
        return pkg
    }

    private class DhizukuBinder : IDhizuku.Stub() {

        // ===== 官方协议核心：remote binder transact（code = FIRST_CALL_TRANSACTION + 10）=====
        // 客户端把任意系统服务 Binder 的调用打包发来，我们以知微（设备所有者）身份转发
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code == DhizukuVariables.TRANSACT_CODE_REMOTE_BINDER) {
                data.enforceInterface(DhizukuVariables.BINDER_DESCRIPTOR)
                val pkg = requireGranted()
                val target = data.readStrongBinder()
                    ?: throw RemoteException("no target binder")
                val transactCode = data.readInt()
                val transactFlags = data.readInt()
                // 以知微身份转发（此时调用方 uid 是我们，拥有设备所有者特权）
                val token = Binder.clearCallingIdentity()
                try {
                    val result = target.transact(transactCode, data, reply, transactFlags)
                    return result
                } finally {
                    Binder.restoreCallingIdentity(token)
                }
            }
            return super.onTransact(code, data, reply, flags)
        }

        override fun getVersionCode(): Int = SERVER_VERSION_CODE

        override fun getVersionName(): String = SERVER_VERSION_NAME

        override fun isPermissionGranted(): Boolean {
            val pkg = callerPackage() ?: return false
            return AuthDb.isGranted(pkg)
        }

        override fun remoteProcess(cmd: Array<out String>?, env: Array<out String>?, dir: String?): IDhizukuRemoteProcess {
            val pkg = requireGranted()
            if (cmd.isNullOrEmpty()) throw RemoteException("empty cmd")
            // 危险命令拦截：remoteProcess 与知微特权服务同等对待，不能成为绕过弹窗的后门
            val cmdLine = cmd.joinToString(" ")
            if (AuthDb.cmdInterceptEnabled && !AuthDb.isCmdWhitelisted(pkg, cmdLine)) {
                val danger = DangerousCommands.match(cmdLine)
                if (danger != null) {
                    val ctx = context ?: throw RemoteException("no context")
                    when (CommandConfirmActivity.requestBlocking(ctx, pkg, cmdLine, danger, 60_000L)) {
                        CommandConfirmActivity.Decision.DENY,
                        CommandConfirmActivity.Decision.TIMEOUT ->
                            throw RemoteException("用户拒绝执行该命令（${danger.category}）")
                        CommandConfirmActivity.Decision.WHITELIST ->
                            AuthDb.addCmdWhitelist(pkg, AuthDb.cmdPrefixOf(cmdLine))
                        CommandConfirmActivity.Decision.ALLOW_ONCE -> { /* 放行这一次 */ }
                    }
                }
            }
            val pb = ProcessBuilder(*cmd)
            if (env != null) {
                pb.environment().clear()
                env.forEach { e ->
                    val i = e.indexOf('=')
                    if (i > 0) pb.environment()[e.substring(0, i)] = e.substring(i + 1)
                }
            }
            if (dir != null) pb.directory(java.io.File(dir))
            pb.redirectErrorStream(false)
            val proc = pb.start()
            return RemoteProcess(proc)
        }

        override fun bindUserService(connection: IDhizukuUserServiceConnection?, bundle: Bundle?) {
            val pkg = requireGranted()
            if (connection == null || bundle == null) return
            bundle.setClassLoader(ComponentName::class.java.classLoader)
            val component: ComponentName? = if (android.os.Build.VERSION.SDK_INT >= 33) {
                bundle.getParcelable(DhizukuVariables.PARAM_COMPONENT, ComponentName::class.java)
            } else {
                @Suppress("DEPRECATION") bundle.getParcelable(DhizukuVariables.PARAM_COMPONENT)
            }
            if (component == null) {
                try { connection.died(bundle) } catch (e: Throwable) { }
                return
            }
            val token = component.flattenToString()
            try {
                // 官方同款机制：加载客户端 APK 的 UserService 类，在知微进程实例化
                val ctx = context ?: throw RemoteException("no context")
                val svc = userServices.getOrPut(token) {
                    val clientCtx = ctx.createPackageContext(
                        component.packageName,
                        Context.CONTEXT_INCLUDE_CODE or Context.CONTEXT_IGNORE_SECURITY
                    )
                    val cls = Class.forName(component.className, true, clientCtx.classLoader)
                    val instance = cls.newInstance() as android.app.Service
                    // attach base context（反射，官方 Dhizuku 同样的做法）
                    val attach = android.app.Service::class.java.getDeclaredMethod(
                        "attach", Context::class.java,
                        android.app.ActivityThread::class.java, String::class.java,
                        android.os.IBinder::class.java, android.app.Application::class.java,
                        Any::class.java
                    )
                    attach.isAccessible = true
                    attach.invoke(instance, ctx, null, cls.name, null, ctx.applicationContext, null)
                    instance.onCreate()
                    instance
                }
                val serviceBinder = svc.onBind(Intent().setComponent(component))
                    ?: throw RemoteException("user service onBind returned null")
                connection.connected(bundle, serviceBinder)
            } catch (e: Throwable) {
                userServices.remove(token)
                try { connection.died(bundle) } catch (ignored: Throwable) { }
            }
        }

        override fun unbindUserService(bundle: Bundle?) {
            bundle ?: return
            bundle.setClassLoader(ComponentName::class.java.classLoader)
            val component: ComponentName = (if (android.os.Build.VERSION.SDK_INT >= 33) {
                bundle.getParcelable(DhizukuVariables.PARAM_COMPONENT, ComponentName::class.java)
            } else {
                @Suppress("DEPRECATION") bundle.getParcelable(DhizukuVariables.PARAM_COMPONENT)
            }) ?: return
            userServices.remove(component.flattenToString())?.let { svc ->
                try { svc.onUnbind(Intent().setComponent(component)) } catch (e: Throwable) { }
                try { svc.onDestroy() } catch (e: Throwable) { }
            }
        }

        override fun unbindUserServiceByConnection(connection: IDhizukuUserServiceConnection?, bundle: Bundle?) {
            unbindUserService(bundle)
        }

        override fun getDelegatedScopes(packageName: String?): Array<out String> {
            requireGranted()
            return delegatedScopes[packageName] ?: arrayOf()
        }

        override fun setDelegatedScopes(packageName: String?, scopes: Array<out String>?) {
            requireGranted()
            if (packageName != null) {
                delegatedScopes[packageName] = scopes ?: arrayOf()
            }
        }

        override fun addLockTaskModeListener(listener: IDhizukuLockTaskModeListener?) {
            requireGranted()
            if (listener != null) lockTaskListeners.addIfAbsent(listener)
        }

        override fun removeLockTaskModeListener(listener: IDhizukuLockTaskModeListener?) {
            if (listener != null) lockTaskListeners.remove(listener)
        }
    }

    /** remoteProcess 的全双工实现（ParcelFileDescriptor 管道对） */
    private class RemoteProcess(private val proc: Process) : IDhizukuRemoteProcess.Stub() {

        private val stdinPfd: ParcelFileDescriptor
        private val stdoutPfd: ParcelFileDescriptor
        private val stderrPfd: ParcelFileDescriptor

        init {
            // 客户端写 → 进程 stdin
            val stdinPair = ParcelFileDescriptor.createPipe()
            stdinPfd = stdinPair[1]
            pump(stdinPair[0], proc.outputStream)
            // 进程 stdout → 客户端读
            val stdoutPair = ParcelFileDescriptor.createPipe()
            stdoutPfd = stdoutPair[0]
            pump(proc.inputStream, ParcelFileDescriptor.AutoCloseOutputStream(stdoutPair[1]))
            // 进程 stderr → 客户端读
            val stderrPair = ParcelFileDescriptor.createPipe()
            stderrPfd = stderrPair[0]
            pump(proc.errorStream, ParcelFileDescriptor.AutoCloseOutputStream(stderrPair[1]))
        }

        private fun pump(input: Any, output: java.io.OutputStream) {
            val inStream = when (input) {
                is ParcelFileDescriptor -> ParcelFileDescriptor.AutoCloseInputStream(input)
                is java.io.InputStream -> input
                else -> return
            }
            kotlin.concurrent.thread(isDaemon = true) {
                try {
                    val buf = ByteArray(8192)
                    while (true) {
                        val n = inStream.read(buf)
                        if (n < 0) break
                        output.write(buf, 0, n)
                        output.flush()
                    }
                } catch (e: Throwable) { }
                try { inStream.close() } catch (e: Throwable) { }
                try { output.close() } catch (e: Throwable) { }
            }
        }

        override fun getOutputStream(): ParcelFileDescriptor = stdinPfd
        override fun getInputStream(): ParcelFileDescriptor = stdoutPfd
        override fun getErrorStream(): ParcelFileDescriptor = stderrPfd
        override fun exitValue(): Int = proc.exitValue()
        override fun destroy() { proc.destroy() }
        override fun alive(): Boolean = proc.isAlive
        override fun waitFor(): Int = proc.waitFor()
        override fun waitForTimeout(timeout: Long, unit: String?): Boolean {
            val tu = try { java.util.concurrent.TimeUnit.valueOf(unit ?: "MILLISECONDS") }
            catch (e: Throwable) { java.util.concurrent.TimeUnit.MILLISECONDS }
            return proc.waitFor(timeout, tu)
        }
    }
}