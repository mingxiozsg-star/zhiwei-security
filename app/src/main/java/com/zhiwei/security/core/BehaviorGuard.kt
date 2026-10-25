package com.zhiwei.security.core

import android.content.Context
import android.content.pm.PackageManager
import android.util.Log

/**
 * 越权行为检测（系统完整性守护）
 *
 * 场景：第三方应用通过 Shizuku/Dhizuku/其他提权通道执行危险操作：
 *  - 冻结/隐藏系统应用（pm disable / setApplicationHidden）
 *  - 删除系统应用（pm uninstall 系统组件）
 *  - 删除系统文件导致组件缺失
 *
 * 策略：周期性核对核心系统组件的「存在 + 启用」状态，
 * 一旦发现缺失/禁用，立即尝试恢复（pm enable / install-existing），
 * 并把当时的前台应用列为嫌疑对象告警。
 */
object BehaviorGuard {

    private const val TAG = "BehaviorGuard"

    /** 核心系统组件（被禁用/删除会直接破坏系统功能） */
    val criticalSystemPkgs = listOf(
        "android",
        "com.android.systemui",
        "com.android.settings",
        "com.android.phone",
        "com.android.providers.settings",
        "com.android.providers.contacts",
        "com.android.packageinstaller",
        "com.android.permissioncontroller",
        "com.android.shell",
        "com.android.launcher3",
        "com.android.vending"          // Play 商店（无则不报）
    )

    /** 即便缺失也不视为越权的（很多设备本就没有） */
    private val optionalPkgs = setOf(
        "com.android.vending",
        "com.android.launcher3"
    )

    data class Violation(
        val pkg: String,
        val type: Type,
        val restored: Boolean
    ) {
        enum class Type(val label: String) { MISSING("被卸载/删除"), DISABLED("被冻结/禁用") }
    }

    // 上一轮已存在的违规，用于检测"新增"违规
    @Volatile private var knownViolations: Set<String> = emptySet()
    @Volatile private var baselineReady = false

    /**
     * 执行一次完整性检查。
     * @param foregroundPkg 当前前台应用（嫌疑定位用）
     * @param onNewViolation 新增违规回调（违规信息, 嫌疑应用）
     */
    fun check(
        context: Context,
        foregroundPkg: String?,
        onNewViolation: (Violation, suspect: String?) -> Unit
    ) {
        val pm = context.packageManager
        val current = mutableSetOf<String>()

        for (pkg in criticalSystemPkgs) {
            val violation = try {
                val ai = pm.getApplicationInfo(pkg, 0)
                when (ai.enabled) {
                    true -> null
                    else -> Violation(pkg, Violation.Type.DISABLED, restore(context, pkg, Violation.Type.DISABLED))
                }
            } catch (e: PackageManager.NameNotFoundException) {
                // 可选包（vending/launcher3）很多设备本就没有，缺失永远不算越权
                if (pkg in optionalPkgs) null
                else Violation(pkg, Violation.Type.MISSING, restore(context, pkg, Violation.Type.MISSING))
            } catch (e: Exception) { null }

            if (violation != null) {
                current.add(pkg)
                // 只报告"新增"的违规（基线之后的）
                if (baselineReady && pkg !in knownViolations) {
                    val suspect = foregroundPkg?.takeIf {
                        it != context.packageName &&
                        it !in Prefs.whitelist &&
                        it != pkg &&
                        !PanicKill.isSystemApp(context, it)
                    }
                    Log.w(TAG, "越权行为: ${violation.type.label} $pkg, 嫌疑: $suspect")
                    onNewViolation(violation, suspect)
                }
            }
        }

        knownViolations = current
        baselineReady = true
    }

    /** 尝试恢复被破坏的系统组件 */
    private fun restore(context: Context, pkg: String, type: Violation.Type): Boolean {
        if (!Privilege.isReady) return false
        return when (type) {
            Violation.Type.DISABLED ->
                Privilege.exec("pm enable $pkg").first == 0
            Violation.Type.MISSING ->
                // 系统应用卸载（--user 0 方式）可用 install-existing 恢复
                Privilege.exec("pm install-existing $pkg").second.contains("Success", true) ||
                Privilege.exec("cmd package install-existing $pkg").second.contains("Success", true)
        }
    }

    /** 重置基线（设置里可以手动重新校准） */
    fun resetBaseline() {
        knownViolations = emptySet()
        baselineReady = false
    }
}