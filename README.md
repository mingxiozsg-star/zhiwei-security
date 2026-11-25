# 知微安全 (Zhiwei Security)

一款专注于**安全防护**的 Android 应用，参考游龙安全护盾重新实现，只做安全功能，无任何花活。

当前版本 **v1.9.0**（versionCode 21）

Current version **v1.9.0** (versionCode 21)

## 核心功能

- 🔍 **病毒扫描**：本地病毒特征库（恶意包名 / 恶意前缀 / 恶意落地文件名 / 签名特征 / 高危权限组合），支持外部引擎与云端哈希复核叠加
- 🧬 **误杀熔断**：内置 **434 个**主流应用与大型游戏可信包名库，命中即豁免扫描、评分、隔离、权限收回与霸屏检测；纯权限评分最高只到「高风险」，永不单独判定病毒
- 🔒 **设备管理员反制**：枚举全机已激活的设备管理员，自动区分「知微自身 / 可信应用 / 未知第三方」；对可疑管理员一键撤销身份（`dpm remove-active-admin`），彻底斩断锁机勒索「改密码 + 锁死界面 + 阻止卸载」链条。撤销为可逆操作，**不卸载应用、不删数据**
- ⚡ **内置特权（对外授权宿主）**：知微不只是自己提权，还能作为特权宿主向其他应用开放权限——第三方 App 通过 `content://com.zhiwei.security.provider` 发现服务、提交带理由的授权申请，用户逐条确认；危险命令 22 类强制拦截；每一次授权与调用写入审计日志。协议 `IZhiweiService` v2，服务与授权可随时一键关停，关闸后 Provider 直接停止下发 Binder
- 🛡️ **三按钮确认处置**：检测到确认病毒时只做可逆的冻结隔离，并强制弹出确认窗，由用户选择「卸载」/「本次忽略」/「加入白名单」——任何情况下都不会自动卸载
- 📱 **应用管理**：黑/白名单管理，支持搜索与筛选
- 🌐 **网络拦截**：VPN 层 DNS 域名过滤，内置 **277+ 条**规则（国内广告联盟 / 海外广告聚合平台 / 统计 SDK / 钓鱼与隧道回连域名），支持直接导入 **AdGuard / ABP / hosts** 三种格式的规则包
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
│   ├── RiskAnalyzer.kt       # 权限风险分析
│   ├── DeviceAdminCounter.kt # 设备管理员反制（锁机勒索拆弹）
│   ├── BuiltinPrivilege.kt   # 内置特权服务层（Stellar 对标层）
│   ├── AuthDb.kt             # 第三方授权库 + 调用审计
│   ├── AdbShell.kt           # 本机 ADB 提权通道
│   └── AdbPairing.kt         # 无线调试 mDNS 自动发现配对
├── service/
│   ├── ProtectService.kt     # 防锁机前台服务
│   ├── NetGuardService.kt    # VPN 域名过滤
│   ├── ZhiweiAccessibilityService.kt  # 音量键管控 / 霸屏检测
│   ├── GuardService.kt       # :guard 守护进程
│   ├── BootReceiver.kt       # 开机自启
│   ├── KeepAliveReceiver.kt  # 定时保活
│   └── ZhiweiApiService.kt   # 对外特权服务 Binder（IZhiweiService v2）
└── ui/
    ├── HomeScreen.kt         # 主页
    ├── ScanScreen.kt         # 病毒扫描
    ├── AppListScreen.kt      # 应用管理
    ├── ProtectScreen.kt      # 防护设置
    ├── SettingsScreen.kt     # 设置
    ├── ShieldWarnActivity.kt # 三按钮威胁确认窗
    ├── BuiltinPrivilegeScreen.kt # 内置特权控制台
    ├── AuthManageScreen.kt   # 授权管理（授予/撤销/白名单）
    ├── AuthGrantActivity.kt  # 第三方授权申请弹窗
    ├── DeviceAdminScreen.kt  # 设备管理员反制页
    └── CommandConfirmActivity.kt # 危险命令拦截弹窗
```

## 许可证

MIT
