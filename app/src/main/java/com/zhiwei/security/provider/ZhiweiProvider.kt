package com.zhiwei.security.provider

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Bundle
import com.zhiwei.security.api.BinderContainer
import com.zhiwei.security.core.AuthDb
import com.zhiwei.security.core.BuiltinPrivilege
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.service.ZhiweiApiService
import com.zhiwei.security.service.ZhiweiApiServiceHolder

/**
 * 知微内置特权服务发现入口（Shizuku 式 Provider 机制）
 *
 * 第三方应用用法：
 * ```kotlin
 * val bundle = contentResolver.call(
 *     Uri.parse("content://com.zhiwei.security.provider"), "getBinder", null, null)
 * val container = bundle?.getParcelable<BinderContainer>("binder")
 * val service = IZhiweiService.Stub.asInterface(container?.binder)
 * ```
 *
 * 除了下发 Binder，本 Provider 还兼作「服务发现探测点」：
 * 第三方可以先 `call("getStatus")` 问一句知微在不在、开没开、通道就绪没，
 * 再决定是否弹自己的引导页——避免用户被无意义的申请弹窗轰炸。
 */
class ZhiweiProvider : ContentProvider() {

    companion object {
        const val AUTHORITY = "com.zhiwei.security.provider"
        const val METHOD_GET_BINDER = "getBinder"
        const val METHOD_GET_STATUS = "getStatus"
        const val EXTRA_BINDER = "binder"
        const val EXTRA_ENABLED = "enabled"
        const val EXTRA_READY = "ready"
        const val EXTRA_RUN_MODE = "runMode"
        const val EXTRA_CORE_VERSION = "coreVersion"
        const val EXTRA_PROTOCOL = "protocol"
        const val EXTRA_MESSAGE = "message"
    }

    override fun onCreate(): Boolean {
        val ctx = context ?: return false
        Prefs.init(ctx)
        AuthDb.init(ctx)
        ZhiweiApiServiceHolder.context = ctx.applicationContext
        return true
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        when (method) {
            METHOD_GET_BINDER -> {
                // 对外总开关：关了就不下发 Binder，第三方彻底拿不到服务
                if (!Prefs.builtinPrivilegeEnabled) {
                    return Bundle().apply {
                        putBoolean(EXTRA_ENABLED, false)
                        putString(EXTRA_MESSAGE, "知微内置特权服务未开启")
                    }
                }
                return Bundle().apply {
                    setClassLoader(BinderContainer::class.java.classLoader)
                    putParcelable(EXTRA_BINDER, BinderContainer(ZhiweiApiService.binder))
                    putBoolean(EXTRA_ENABLED, true)
                }
            }
            METHOD_GET_STATUS -> {
                return Bundle().apply {
                    putBoolean(EXTRA_ENABLED, Prefs.builtinPrivilegeEnabled)
                    putBoolean(EXTRA_READY, com.zhiwei.security.core.Privilege.isReady)
                    putString(EXTRA_RUN_MODE, BuiltinPrivilege.runMode)
                    putString(EXTRA_CORE_VERSION, BuiltinPrivilege.CORE_VERSION)
                    putInt(EXTRA_PROTOCOL, ZhiweiApiService.VERSION)
                    putString(EXTRA_MESSAGE, BuiltinPrivilege.state().label)
                }
            }
        }
        return null
    }

    /** 用 projection 指定字段也能查状态（部分第三方懒得解 Bundle） */
    override fun query(
        uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?
    ): Cursor {
        val cols = arrayOf(
            EXTRA_ENABLED, EXTRA_READY, EXTRA_RUN_MODE,
            EXTRA_CORE_VERSION, EXTRA_PROTOCOL
        )
        val c = MatrixCursor(cols)
        c.addRow(
            arrayOf(
                if (Prefs.builtinPrivilegeEnabled) 1 else 0,
                if (com.zhiwei.security.core.Privilege.isReady) 1 else 0,
                BuiltinPrivilege.runMode,
                BuiltinPrivilege.CORE_VERSION,
                ZhiweiApiService.VERSION
            )
        )
        return c
    }

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(
        uri: Uri, values: ContentValues?, selection: String?,
        selectionArgs: Array<out String>?
    ): Int = 0
}
