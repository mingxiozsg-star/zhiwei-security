package com.zhiwei.security.core

import android.content.Context

/**
 * 设备管理器反制（DeviceAdminCounter）
 *
 * 定位：这是「锁机勒索 / 恶意设备管理员」反制层，不是普通权限管理。
 *
 * 恶意软件的典型锁机路径：
 *   诱导用户点「激活设备管理器」→ 调 `device_policies.set-password` 改锁屏密码
 *   → `set-lock-task-mode` 锁死前台 → 用户既解不了锁也卸载不掉。
 *
 * 本类的反制能力（全部只读探测 + 白名单短路）：
 * 1. **枚举**全机已激活的设备管理员（`dpm list-active-admins`）
 * 2. **判别风险**：区分「我们自己的」「可信库内的」「未知第三方」三类
 * 3. **反制**：对未知第三方管理员执行强制移除（`dpm remove-active-admin`），
 *    必要时先 force-stop 其宿主应用
 * 4. **自我保护**：自己的管理员组件永不被反制，且在扫描/处置链路上豁免
 *
 * 铁律：本类**绝不**自动移除白名单应用的设备管理员，也绝不静默卸载任何应用。
 * 移除设备管理员是可逆操作（应用仍在，历史数据仍在），风险远低于卸载。
 */
object DeviceAdminCounter {

    private const val TAG = "DeviceAdmin"

    /** 设备管理员条目 */
    data class AdminEntry(
        val pkg: String,
        val receiverClass: String,
        val appName: String,
        /** 完整组件名 pkg/receiverClass，供 dpm 命令使用 */
        val component: String,
        val isSelf: Boolean,
        val isTrusted: Boolean
    ) {
        /** 是否为需要反制的未知第三方管理员 */
        val isHostile: Boolean get() = !isSelf && !isTrusted
    }

    /** 自身的管理员组件（.dhizuku.ZhiweiDAReceiver），永不自残 */
    private fun selfComponent(context: Context): String =
        context.packageName + "/.dhizuku.ZhiweiDAReceiver"

    /** 缓存快照（避免全盘扫描时对每个应用都跑一次 dpm 命令） */
    @Volatile private var cache: List<AdminEntry> = emptyList()
    @Volatile private var cacheAt = 0L
    @Volatile private var cachePkg: String = ""

    /** 缓存有效期：扫描一轮通常数秒，30 秒足够新 */
    private const val CACHE_TTL = 30_000L

    /**
     * 枚举当前已激活的设备管理员（带 30 秒缓存）。
     *
     * 全盘扫描会对上百个应用调用 [hasLockCapableAdmin]，
     * 每次都跑 `dpm list-active-admins` 会让扫描慢到不可接受，
     * 因此这里做进程内缓存；需要强制刷新时调 [invalidateCache]。
     */
    fun listActiveAdmins(context: Context): List<AdminEntry> {
        val now = System.currentTimeMillis()
        if (cachePkg == context.packageName && now - cacheAt < CACHE_TTL) return cache
        val fresh = queryAdmins(context)
        cache = fresh
        cacheAt = now
        cachePkg = context.packageName
        return fresh
    }

    /** 作废缓存（反制后、用户手动刷新时调用） */
    fun invalidateCache() {
        cache = emptyList()
        cacheAt = 0L
    }

    @Suppress("DEPRECATION")
    private fun queryAdmins(context: Context): List<AdminEntry> {
        if (!Privilege.isReady) return emptyList()
        val out = try {
            Privilege.exec("dpm list-active-admins 2>/dev/null").second
        } catch (e: Throwable) { return emptyList() }

        val pm = context.packageManager
        val self = context.packageName
        val selfComp = selfComponent(context)
        val result = ArrayList<AdminEntry>()

        out.lineSequence().forEach { rawLine ->
            // dpm 输出格式：  Admin #0: com.foo.bar/.SomeReceiver
            var line = rawLine.trim()
            if (line.isEmpty() || !line.contains('/')) return@forEach
            // 剥掉 "Admin #0:" 之类前缀
            val idx = line.indexOf(": ")
            if (idx >= 0) line = line.substring(idx + 2).trim()

            val pkg = line.substringBefore('/').trim()
            val cls = line.substringAfter('/').trim()
            if (pkg.isEmpty() || cls.isEmpty()) return@forEach

            val component = "$pkg/$cls"
            if (result.any { it.component == component }) return@forEach

            val appName = try {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(pkg, 0).loadLabel(pm).toString()
            } catch (e: Throwable) { pkg }

            val isSelf = component == selfComp || pkg == self
            result.add(
                AdminEntry(
                    pkg = pkg,
                    receiverClass = cls,
                    appName = appName,
                    component = component,
                    isSelf = isSelf,
                    isTrusted = !isSelf && KnownSafeApps.isTrusted(pkg)
                )
            )
        }
        return result
    }

    /** 仅返回需要反制的未知第三方管理员（已排除自己与可信库） */
    fun listHostileAdmins(context: Context): List<AdminEntry> =
        listActiveAdmins(context).filter { it.isHostile }

    /**
     * 反制单个管理员：移除设备管理员身份。
     *
     * 顺序：先 `dpm remove-active-admin`，失败则先 force-stop 宿主再重试。
     * **不卸载应用**——移除管理员已足以解除锁机能力，卸载权仍属用户。
     *
     * @return true 表示移除成功
     */
    fun counter(entry: AdminEntry): Boolean {
        if (entry.isSelf || entry.isTrusted) return false
        invalidateCache()
        return try {
            Privilege.exec("dpm remove-active-admin '${entry.component}'").let { (code, out) ->
                if (code == 0 && !out.contains("Error", true) && !out.contains("Exception", true)) {
                    SecurityJournal.log(
                        "设备管理员反制",
                        "已移除 ${entry.appName}（${entry.component}）的管理员身份"
                    )
                    return true
                }
            }
            // 兜底：宿主进程可能正在反复重注册，先停掉再移除
            Privilege.forceStop(entry.pkg)
            Thread.sleep(300)
            val ok = Privilege.exec("dpm remove-active-admin '${entry.component}'").first == 0
            SecurityJournal.log(
                "设备管理员反制",
                "重试移除 ${entry.appName}（${entry.component}）：" + if (ok) "成功" else "失败（可能为设备所有者，需先解除）"
            )
            ok
        } catch (e: Throwable) {
            SecurityJournal.log("设备管理员反制", "移除 ${entry.component} 异常：${e.message}")
            false
        }
    }

    /**
     * 批量反制全部未知第三方管理员。
     *
     * @param context 上下文
     * @return 成功移除的数量
     */
    fun counterAllHostile(context: Context): Int {
        val hostile = listHostileAdmins(context)
        if (hostile.isEmpty()) return 0
        var ok = 0
        hostile.forEach { if (counter(it)) ok++ }
        return ok
    }

    /**
     * 自身是否已激活为设备管理员（自防护依赖此能力做 setUninstallBlocked）。
     */
    fun isSelfActive(context: Context): Boolean = try {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE)
                as android.app.admin.DevicePolicyManager
        dpm.isAdminActive(
            android.content.ComponentName(context, com.zhiwei.security.dhizuku.ZhiweiDAReceiver::class.java)
        )
    } catch (e: Throwable) { false }

    /**
     * 某应用是否持有「可锁屏改密码」的设备管理员权限。
     * 用于扫描结果展示风险来源，不做处置。
     */
    fun hasLockCapableAdmin(context: Context, pkg: String): Boolean {
        val admins = try { listActiveAdmins(context) } catch (e: Throwable) { return false }
        return admins.any { it.pkg == pkg && !it.isSelf }
    }
}
