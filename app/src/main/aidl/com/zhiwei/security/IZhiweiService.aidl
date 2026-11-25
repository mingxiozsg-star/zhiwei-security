package com.zhiwei.security;

import com.zhiwei.security.IZhiweiCallback;

/**
 * 知微内置特权服务（对第三方应用开放，Shizuku 式授权架构）
 *
 * 第三方应用接入方式：
 *   ContentResolver.call(Uri.parse("content://com.zhiwei.security.provider"), "getBinder", ...)
 *   → 拿到 IBinder → IZhiweiService.Stub.asInterface(...)
 *   → requestPermission(reason, callback) 申请授权
 *   → execCommand(cmd) 执行特权命令
 *   → execCommandAs ∝ 返回 "exitCode\noutput"
 *
 * 协议版本：2（v1 仅有 requestPermission(callback)，v2 追加带理由重载与运行时信息）
 */
interface IZhiweiService {
    /** 协议版本（1=初版 2=带理由申请 + 运行时信息） */
    int getVersion();

    /** 0=未授权 1=已授权（按调用方 uid 判定，不信任自报包名） */
    int checkPermission();

    /** 异步请求授权，结果经 callback 返回 */
    void requestPermission(IZhiweiCallback callback);

    /**
     * 带申请理由的授权请求（v2）。
     * reason 会展示在知微的授权弹窗上，让用户知道对方要什么；为空等同无理由。
     */
    void requestPermissionWithReason(String reason, IZhiweiCallback callback);

    /** 主动放弃授权（第三方可在退出时调用，用户端列表中标记为「已退出」） */
    void releasePermission();

    /**
     * 执行特权命令（需已授权）。
     * 危险命令会弹窗让用户确认（允许一次/拒绝/加入白名单）。
     * 返回 "code\noutput" 格式；第一行为 exitCode。
     */
    String execCommand(String cmd);

    /** 知微侧是否已有可用提权通道 */
    boolean isPrivilegeReady();

    /** 内核版本号（如 1.9.0），第三方可据此做兼容判断 */
    String getCoreVersion();

    /** 当前运行方式：Root / System / ADB / Shizuku / 待通道 / — */
    String getRunMode();

    /** 已授权第三方应用数量（只给数字，不泄露其他应用包名） */
    int getGrantedCount();
}
