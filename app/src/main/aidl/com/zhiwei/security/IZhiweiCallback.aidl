package com.zhiwei.security;

/** 知微特权服务回调 */
interface IZhiweiCallback {
    /** 授权请求结果 */
    void onResult(boolean granted);
}
