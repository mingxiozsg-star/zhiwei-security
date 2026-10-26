package com.zhiwei.security.core

import android.content.Context
import android.content.pm.PackageInfo
import java.util.concurrent.CopyOnWriteArrayList

/**
 * 病毒扫描引擎抽象层
 *
 * 设计目的：本地特征库之外的引擎即插即用。
 * 任何第三方/商业引擎（如安天 AVL SDK、ClamAV 特征库）只要实现 [ScanEngine]
 * 并注册进 [ScanEngineHub]，全量扫描与新装应用监控会自动叠加其判定结果。
 *
 * 判定合并策略：多引擎结果取最高威胁等级，命中理由注明来源引擎。
 */
interface ScanEngine {

    /** 引擎唯一标识（结果溯源用） */
    val id: String

    /** 展示名（命中理由中标注） */
    val displayName: String

    /** 引擎当前是否可用（授权缺失/库未加载时返回 false） */
    fun isAvailable(context: Context): Boolean

    /**
     * 扫描单个应用。
     * @return 命中威胁返回结果（reasons 建议注明引擎名）；安全返回 null；异常必须内部吞掉返回 null
     */
    fun scanPackage(context: Context, pkg: PackageInfo): VirusDb.ScanResult?
}

object ScanEngineHub {

    private val engines = CopyOnWriteArrayList<ScanEngine>()

    /** 注册引擎（重复 id 自动去重） */
    fun register(engine: ScanEngine) {
        if (engines.none { it.id == engine.id }) engines.add(engine)
    }

    fun unregister(id: String) = engines.removeAll { it.id == id }

    /** 当前可用引擎列表（UI 展示用） */
    fun activeEngines(context: Context): List<ScanEngine> =
        engines.filter { runCatching { it.isAvailable(context) }.getOrDefault(false) }

    fun registeredEngines(): List<ScanEngine> = engines.toList()

    /**
     * 外部引擎联合扫描：取最高威胁等级的结果。
     * 引擎异常只跳过该引擎，不影响整体扫描。
     */
    fun scanWithExternalEngines(context: Context, pkg: PackageInfo): VirusDb.ScanResult? {
        var best: VirusDb.ScanResult? = null
        for (engine in engines) {
            val r = try {
                if (!engine.isAvailable(context)) continue
                engine.scanPackage(context, pkg) ?: continue
            } catch (e: Throwable) { continue }
            if (best == null || r.level.ordinal > best!!.level.ordinal ||
                (r.level == best!!.level && r.score > best!!.score)) {
                best = r
            }
        }
        return best
    }

    /** 合并本地结果与外部引擎结果（取更严重者） */
    fun merge(local: VirusDb.ScanResult?, external: VirusDb.ScanResult?): VirusDb.ScanResult? {
        if (local == null) return external
        if (external == null) return local
        return if (external.level.ordinal > local.level.ordinal ||
            (external.level == local.level && external.score > local.score)) external else local
    }
}

/**
 * 安天 AVL 引擎占位实现
 *
 * 安天实验室 AVL SDK 为商业闭源产品，需企业授权获取 aar 与 license。
 * 拿到授权后：把 SDK 的初始化/扫描调用填入下方标记处即可接入，
 * 无需改动扫描主流程——扫描器经 [ScanEngineHub] 自动叠加本引擎结果。
 */
class AvlSdkEngine : ScanEngine {
    override val id = "avl"
    override val displayName = "安天 AVL"

    override fun isAvailable(context: Context): Boolean {
        // TODO(商业授权后接入)：检查 AVL SDK 类是否存在 + license 校验
        return runCatching {
            Class.forName("com.avl.engine.AvlEngine")
            false // license 校验通过后改 true
        }.getOrDefault(false)
    }

    override fun scanPackage(context: Context, pkg: PackageInfo): VirusDb.ScanResult? {
        // TODO(商业授权后接入)：调用 AVL SDK 对 pkg.applicationInfo.sourceDir 扫描
        return null
    }
}
