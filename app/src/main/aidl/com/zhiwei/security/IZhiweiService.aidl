package com.zhiwei.security;

import com.zhiwei.security.IZhiweiCallback;

/**
 * 知微特权服务（Shizuku 式授权架构）
 * 第三方应用通过 ZhiweiProvider 拿到本 Binder，
 * 先 requestPermission 申请授权，授权后可 execCommand 走知微提权通道执行命令。
 */
interface IZhiweiService {
    /** 协议版本 */
    int getVersion();

    /** 0=未授权 1=已授权（按调用方 uid 判定） */
    int checkPermission();

    /** 异步请求授权，结果经 callback 返回 */
    void requestPermission(IZhiweiCallback callback);

    /**
     * 执行特权命令（需已授权）。
     * 危险命令会弹窗让用户确认（允许一次/拒绝/加入白名单）。
     * 返回 "code\noutput" 格式；第一行为 exitCode。
     */
    String execCommand(String cmd);

    /** 知微侧是否已有可用提权通道 */
    boolean isPrivilegeReady();
}
