package com.zhiwei.security.api

import android.os.IBinder
import android.os.Parcel
import android.os.Parcelable

/**
 * Binder 容器：第三方应用通过 ZhiweiProvider.call("getBinder")
 * 拿到装着服务 Binder 的本对象（与 Shizuku 的 BinderContainer 同思路）
 */
class BinderContainer(val binder: IBinder) : Parcelable {

    override fun describeContents(): Int = 0

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeStrongBinder(binder)
    }

    companion object CREATOR : Parcelable.Creator<BinderContainer> {
        override fun createFromParcel(source: Parcel): BinderContainer {
            return BinderContainer(source.readStrongBinder())
        }
        override fun newArray(size: Int): Array<BinderContainer?> = arrayOfNulls(size)
    }
}