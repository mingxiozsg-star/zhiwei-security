package com.zhiwei.security.dhizuku

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import com.rosan.dhizuku.shared.DhizukuVariables
import com.zhiwei.security.core.AuthDb
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.service.ZhiweiApiServiceHolder

/**
 * Dhizuku 协议服务端 Provider（官方同款发现机制）
 * authority = 包名 + ".dhizuku_server.provider"（与 DhizukuVariables.getProviderAuthorityName 一致）
 *
 * 客户端（任何使用 Dhizuku-API 的应用）流程：
 *   找到设备所有者组件(我们) → 拼出本 provider → call("client", EXTRA_CLIENT)
 *   → 拿回 PARAM_DHIZUKU_BINDER → IDhizuku.Stub.asInterface(...)
 */
class ZhiweiDhizukuProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        val ctx = context ?: return false
        Prefs.init(ctx)
        AuthDb.init(ctx)
        DhizukuServer.context = ctx.applicationContext
        ZhiweiApiServiceHolder.context = ctx.applicationContext
        return true
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method != DhizukuVariables.PROVIDER_METHOD_CLIENT) return null
        // 客户端 binder（IDhizukuClient）校验存在即可，版本协商可后续扩展
        val clientBinder = extras?.getBinder(DhizukuVariables.EXTRA_CLIENT)
            ?: return null
        if (!clientBinder.pingBinder()) return null
        val out = Bundle()
        out.putBinder(DhizukuVariables.PARAM_DHIZUKU_BINDER, DhizukuServer.binder)
        return out
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?,
                       selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?,
                        selectionArgs: Array<out String>?): Int = 0
}