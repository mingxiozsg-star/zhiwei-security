package com.zhiwei.security.core

/**
 * 危险命令识别：只有命中危险模式的命令才弹窗拦截，
 * 普通命令（ls/id/getprop 等只读操作）直接放行不打扰用户
 */
object DangerousCommands {

    data class Danger(val category: String, val description: String)

    /** 危险模式：正则 → (类别, 说明) */
    private val patterns: List<Pair<Regex, Danger>> = listOf(
        Regex("""\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)?/""") to Danger("删文件", "删除系统/数据文件，可能变砖或丢数据"),
        Regex("""\brm\s+-[a-zA-Z]*r""") to Danger("删文件", "递归删除目录"),
        Regex("""\bdd\s+.*\bof=/dev/""") to Danger("写磁盘", "直接覆写磁盘分区，可致变砖"),
        Regex("""\bmkfs|\bformat\b.*partition""") to Danger("格式化", "格式化分区，数据全毁"),
        Regex("""\breboot\b|\bshutdown\b|\bsvc\s+power\s+(shutdown|reboot)""") to Danger("重启关机", "强制重启/关机"),
        Regex("""\bpm\s+uninstall\b""") to Danger("卸载应用", "卸载应用（含系统应用）"),
        Regex("""\bpm\s+(disable|hide|suspend|clear)\b""") to Danger("停用清除", "停用/隐藏/清空应用数据"),
        Regex("""\bam\s+(force-stop|kill)\b""") to Danger("强杀应用", "强制停止其他应用"),
        Regex("""\bsettings\s+put\s+secure\s+enabled_accessibility_services""") to Danger("改无障碍", "改写系统无障碍服务列表"),
        Regex("""\bsettings\s+put\s+(secure|system|global)\b""") to Danger("改系统设置", "改写系统设置"),
        Regex("""\bpm\s+(grant|revoke)\b""") to Danger("改权限", "授予/撤销其他应用权限"),
        Regex("""\bappops\s+set\b""") to Danger("改权限", "改写应用ops权限"),
        Regex("""\bdevice_policy|\bdpm\s+""") to Danger("设备管理", "操作设备管理器（锁机常用手法）"),
        Regex("""\bchattr\s+\+?i""") to Danger("文件锁", "锁定文件防删除（锁机病毒常驻手法）"),
        Regex("""\bmount\s+(-o\s+)?remount""") to Danger("重挂载", "重挂载系统分区为可写"),
        Regex("""\bchmod\s+777|\bchown\s+""") to Danger("改文件权限", "篡改文件属主/权限"),
        Regex("""\bsetprop\s+""") to Danger("改属性", "改写系统属性"),
        Regex("""\bstop\b;|\bstop\s+zygote|\bkill\s+-9\s+1\b""") to Danger("杀系统", "杀死系统核心进程，直接死机"),
        Regex("""\bcontent\s+(delete|update)\b""") to Danger("改数据", "删除/篡改系统数据库"),
        Regex("""\binput\s+(keyevent|tap|swipe|text)\b""") to Danger("模拟操作", "模拟用户按键/触摸操作"),
        Regex("""\bwm\s+size|\bwm\s+density""") to Danger("改显示", "篡改屏幕分辨率/密度（锁屏手法）"),
        Regex("""\blocksettings\b|\bcmd\s+lock_settings""") to Danger("改锁屏密码", "篡改锁屏密码（锁机勒索核心手法）")
    )

    /** 命中危险模式返回说明，否则 null（安全命令直接放行） */
    fun match(cmd: String): Danger? {
        val c = cmd.trim()
        for ((re, danger) in patterns) {
            if (re.containsMatchIn(c)) return danger
        }
        return null
    }
}