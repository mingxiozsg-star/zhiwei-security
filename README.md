# 知微安全 (Zhiwei Security)

一款专注于**安全防护**的 Android 应用，参考游龙安全护盾重新实现，只做安全功能，无任何花活。

当前版本 **v1.8.0**（versionCode 19）

## 核心功能

- 🔍 **病毒扫描**：本地病毒特征库（恶意包名 / 恶意前缀 / 恶意落地文件名 / 签名特征 / 高危权限组合），支持外部引擎与云端哈希复核叠加
- 🧬 **误杀熔断**：内置 280+ 主流应用与大型游戏可信包名库，命中即豁免扫描、评分、隔离、权限收回与霸屏检测；纯权限评分最高只到「高风险」，永不单独判定病毒
- 🛡️ **三按钮确认处置**：检测到确认病毒时只做可逆的冻结隔离，并强制弹出确认窗，由用户选择「卸载」/「本次忽略」/「加入白名单」——任何情况下都不会自动卸载
- 📱 **应用管理**：黑/白名单管理，支持搜索与筛选
- 🌐 **网络拦截**：VPN 层 DNS 域名过滤，内置广告联盟与统计 SDK 规则库
- 🛡️ **防锁机守护**：前台服务实时监控，屏幕状态监听 + 新装应用检测 + 定期扫描
- 👁️ **双进程互守**：主防护服务 + 独立 `:guard` 守护进程，互相拉起防止被杀
- 🚀 **开机自启 + 定时保活**：BOOT_COMPLETED 广播 + AlarmManager 定时唤醒
- ⚠️ **威胁警告**：发现风险时锁屏上也可显示的全屏警告，三按钮交互，返回键等价于「本次忽略」

## 技术栈

- Kotlin 100%
- Jetpack Compose + Material Design 3
- Navigation Compose
- Shizuku / Root 提权通道（可选，无权限时自动降级）

## 构建

```bash
./gradlew assembleDebug
```

正式版由 GitHub Actions CI 构建（`.github/workflows/build-release.yml`），推送 tag 即发布 Release，产出 `normal`（普通版）与 `system`（系统版）双渠道 APK。

## 项目结构

```
app/src/main/java/com/zhiwei/security/
├── ZhiweiApp.kt              # Application，通知渠道
├── MainActivity.kt           # 单 Activity + Compose 导航
├── core/
│   ├── Prefs.kt              # 配置持久化
│   ├── VirusDb.kt            # 病毒特征库
│   ├── AppScanner.kt         # 扫描引擎
│   ├── KnownSafeApps.kt      # 内置可信应用/游戏白名单
│   ├── ThreatResponder.kt    # 威胁统一处置中心（唯一出口）
│   ├── LocalAvScannerManager.kt  # 本地 AV 特征库引擎
│   ├── CloudHashVerifier.kt  # 云端哈希复核
│   ├── ScanEngineHub.kt      # 外部引擎抽象与结果合并
│   └── RiskAnalyzer.kt       # 权限风险分析
├── service/
│   ├── ProtectService.kt     # 防锁机前台服务
│   ├── NetGuardService.kt    # VPN 域名过滤
│   ├── ZhiweiAccessibilityService.kt  # 音量键管控 / 霸屏检测
│   ├── GuardService.kt       # :guard 守护进程
│   ├── BootReceiver.kt       # 开机自启
│   └── KeepAliveReceiver.kt  # 定时保活
└── ui/
    ├── HomeScreen.kt         # 主页
    ├── ScanScreen.kt         # 病毒扫描
    ├── AppListScreen.kt      # 应用管理
    ├── ProtectScreen.kt      # 防护设置
    ├── SettingsScreen.kt     # 设置
    └── ShieldWarnActivity.kt # 三按钮威胁确认窗
```

## 许可证

MIT
