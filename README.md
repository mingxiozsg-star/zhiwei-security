# 知微安全 (Zhiwei Security)

一款专注于**安全防护**的 Android 应用，参考游龙安全护盾重新实现，只做安全功能，无任何花活。

## 核心功能

- 🔍 **病毒扫描**：本地病毒特征库（恶意包名 / 危险权限评分 / 高危权限组合 / 签名特征）
- 📱 **应用管理**：黑/白名单管理，支持搜索与筛选
- 🛡️ **防锁机守护**：前台服务实时监控，屏幕状态监听 + 新装应用检测 + 定期扫描
- 👁️ **双进程互守**：主防护服务 + 独立 `:guard` 守护进程，互相拉起防止被杀
- 🚀 **开机自启 + 定时保活**：BOOT_COMPLETED 广播 + AlarmManager 定时唤醒
- ⚠️ **威胁警告**：发现风险时锁屏上也可显示的全屏警告，支持一键加入黑名单/白名单

## 技术栈

- Kotlin 100%
- Jetpack Compose + Material Design 3
- Navigation Compose
- Shizuku API（预留）

## 构建

```bash
./gradlew assembleDebug
```

正式版由 GitHub Actions CI 构建（`.github/workflows/build-release.yml`），推送 tag 即发布 Release。

## 项目结构

```
app/src/main/java/com/zhiwei/security/
├── ZhiweiApp.kt          # Application，通知渠道
├── MainActivity.kt       # 单 Activity + Compose 导航
├── core/
│   ├── Prefs.kt          # 配置持久化
│   ├── VirusDb.kt        # 病毒特征库
│   ├── AppScanner.kt     # 扫描引擎
│   └── RiskAnalyzer.kt   # 权限风险分析
├── service/
│   ├── ProtectService.kt     # 防锁机前台服务
│   ├── GuardService.kt       # :guard 守护进程
│   ├── BootReceiver.kt       # 开机自启
│   └── KeepAliveReceiver.kt  # 定时保活
└── ui/
    ├── HomeScreen.kt         # 主页
    ├── ScanScreen.kt         # 病毒扫描
    ├── AppListScreen.kt      # 应用管理
    ├── ProtectScreen.kt      # 防护设置
    ├── SettingsScreen.kt     # 设置
    └── ShieldWarnActivity.kt # 威胁警告
```

## 许可证

MIT
