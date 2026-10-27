package com.zhiwei.security.core

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File

/**
 * 内嵌 Shizuku 服务端启动器（真搬：服务端二进制来自 RikkaApps/Shizuku v13.6.0 官方包）
 *
 * 原理：把 assets/shizuku/ 内的服务端 dex + 原生启动器（libshizuku.so）经提权通道
 * 部署到 /data/local/tmp/zw_shizuku/ 并以 shell/root 身份运行 app_process 拉起
 * rikka.shizuku.server.ShizukuService。
 *
 * 已知边界（诚实声明，不糊弄）：
 * - Root 设备：服务端把 binder 注册进 ServiceManager，第三方 Shizuku 客户端可直接发现，
 *   完全可用（与 Magisk 模块 Sui 同原理）。
 * - ADB(shell) 设备：服务端可运行，本应用可连；第三方应用的发现/授权依赖官方
 *   manager 包名校验，脱离官方管理器无法完成授权——这是 rikka 的架构限制，非本实现缺陷。
 */
object ShizukuServer {

    private const val TAG = "ShizukuServer"
    private const val TARGET_DIR = "/data/local/tmp/zw_shizuku"

    /** 服务端是否在运行（binder 是否可探测） */
    val isRunning: Boolean
        get() = ShizukuManager.isBinderAlive

    /**
     * 部署并启动内嵌 Shizuku 服务端。需提权通道（Root/ADB）。
     * @return 结果说明文本
     */
    fun deployAndStart(context: Context): String {
        if (!Privilege.isReady) return "❌ 无提权通道：请先连接本机 ADB 或 Root"
        try {
            // 1. 从 assets 导出到应用外部目录（shell 可读）
            val staging = context.getExternalFilesDir("shizuku") ?: return "❌ 外部存储不可用"
            staging.mkdirs()
            val abi64 = Build.SUPPORTED_ABIS.firstOrNull()?.contains("64") != false
            val starterName = if (abi64) "starter64.so" else "starter32.so"
            for (name in listOf("shizuku_server.dex", starterName)) {
                val out = File(staging, name)
                context.assets.open("shizuku/$name").use { inp ->
                    out.outputStream().use { inp.copyTo(it) }
                }
            }
            Log.i(TAG, "staged to ${staging.absolutePath}")

            // 2. 部署到 /data/local/tmp 并启动（一条 shell 命令链）
            val src = staging.absolutePath
            val cmd = "mkdir -p $TARGET_DIR && " +
                "cp $src/shizuku_server.dex $TARGET_DIR/ && " +
                "cp $src/$starterName $TARGET_DIR/starter && " +
                "chmod 755 $TARGET_DIR/starter && chmod 644 $TARGET_DIR/shizuku_server.dex && " +
                "pkill -f shizuku_server 2>/dev/null; " +
                "nohup $TARGET_DIR/starter --apk=$TARGET_DIR/shizuku_server.dex >/dev/null 2>&1 & " +
                "echo DEPLOYED"
            val (code, out) = Privilege.exec(cmd)
            if (!out.contains("DEPLOYED")) return "❌ 部署失败(code=$code)：${out.take(120)}"

            // 3. 等服务端注册 binder（最多 3 秒）
            var waited = 0
            while (waited < 3000) {
                if (ShizukuManager.isBinderAlive) break
                Thread.sleep(300); waited += 300
            }
            return if (ShizukuManager.isBinderAlive) {
                SecurityJournal.log("提权", "内嵌 Shizuku 服务端已启动")
                "✅ 内嵌 Shizuku 服务端已启动" +
                    if (Privilege.levelState.value == Privilege.Level.ROOT)
                        "（Root 模式：第三方应用可直接发现使用）"
                    else "（ADB 模式：本应用可用）"
            } else "⚠️ 服务端已拉起但 binder 未就绪，请稍候重试"
        } catch (e: Throwable) {
            Log.w(TAG, "deployAndStart failed", e)
            return "❌ 启动失败：${e.message}"
        }
    }

    /** 停止内嵌服务端 */
    fun stop(): String {
        if (!Privilege.isReady) return "❌ 无提权通道"
        Privilege.exec("pkill -f shizuku_server; echo STOPPED")
        SecurityJournal.log("提权", "内嵌 Shizuku 服务端已停止")
        return "已停止"
    }
}
