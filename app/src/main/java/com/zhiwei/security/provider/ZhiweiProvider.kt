package com.zhiwei.security.provider

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import com.zhiwei.security.api.BinderContainer
import com.zhiwei.security.core.AuthDb
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.service.ZhiweiApiService
import com.zhiwei.security.service.ZhiweiApiServiceHolder

/**
 * 知微特权服务发现入口（Shizuku 式 Provider 机制）
 *
 * 第三方应用用法：
 * ```kotlin
 * val bundle = contentResolver.call(
 *     Uri.parse("content://com.zhiwei.security.provider"), "getBinder", null, null)
 * val container = bundle?.getParcelable<BinderContainer>("binder")
 * val service = IZhiweiService.Stub.asInterface(container?.binder)
 * ```
 */
class ZhiweiProvider : ContentProvider() {

    companion object {
        const val AUTHORITY = "com.zhiwei.security.provider"
        const val METHOD_GET_BINDER = "getBinder"
        const val EXTRA_BINDER = "binder"
    }

    override fun onCreate(): Boolean {
        val ctx = context ?: return false
        Prefs.init(ctx)
        AuthDb.init(ctx)
        ZhiweiApiServiceHolder.context = ctx.applicationContext
        return true
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method != METHOD_GET_BINDER) return null
        val bundle = Bundle()
        bundle.setClassLoader(BinderContainer::class.java.classLoader)
        bundle.putParcelable(EXTRA_BINDER, BinderContainer(ZhiweiApiService.binder))
        return bundle
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?,
                       selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?,
                        selectionArgs: Array<out String>?): Int = 0
}