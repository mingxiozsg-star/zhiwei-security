# 更新日志

## v1.4.2（2026-10-26）

### 静默安装监控 + 病毒自动清除
- 监听新装应用（PACKAGE_ADDED），读取安装来源：应用商店/ADB 侧载/未知来源全部弹通知
- installer 为空或 com.android.shell 判定为静默安装，高优先级告警提示确认是否本人操作
- 命中病毒库的应用：提权通道就绪时直接 `pm uninstall` 自动删除并通知；无提权时通知点击一键跳卸载

### 操作结果通知化
- 新增 NotifHelper 通知中心（独立「安全操作结果」渠道）
- 紧急斩杀完成、扫描完成（威胁数/最高危项）、病毒清除全部发通知，不再只依赖 Toast

### 斩杀加固
- 无障碍斩杀通道触发时增加 400ms 震动反馈，确认斩杀已执行
- 斩杀结果通知区分「全杀光」与「仅清后台」

### 软件更新弹窗
- 检查更新发现新版本后先弹窗：显示新版本号、当前版本、完整更新说明
- 用户确认「立即更新」才下载，不再自动下载

### 提权中心全机型指南
- 新增「全机型激活指南」卡：小米/华为/OPPO/vivo/三星等厂商账号移除路径 + 无线调试配对指引
- Shizuku 授权按钮 + Dhizuku 一键激活 + 外部 Dhizuku 兼容，任一通道就绪即可强杀

### UI 全面统一
- 病毒扫描/应用管理/防护设置三屏统一深色品牌主题（0F0F1A 底 + 1A1A2E 卡片 + 粉色主按钮）
- 全部六屏视觉风格一致

## v1.4.1（2026-10-26）

### 紧急斩杀修复（重要）
- 修复「斩杀把自己杀了」：自身包名双重豁免（列表过滤 + 逐包执行时再校验），绝不自毁
- 修复「杀不干净」：提权就绪时逐包 force-stop（前台+后台进程全部杀光），不再一批命令失败即整体放弃；结果 Toast 明确区分「全部杀光」和「仅清理后台（需先激活提权通道）」

### 授权管理独立页
- 新增「授权管理」页：全部第三方应用列表（图标+应用名+包名），开关即授予/撤销知微特权；支持搜索、「只看已授权」过滤
- 页面内含危险命令拦截总开关 + 命令白名单管理（删除）
- 主页宫格和设置页均可进入

### 关于页修复
- 修复点击「关于我们」闪退：品牌图标改用矢量前景+品牌色圆底（adaptive-icon XML 不能被 painterResource 解析）
- 致谢链接改为点击复制（不再直接唤起浏览器）

### UI 改版
- 主页全面重设计：深色品牌底 + 粉×冰蓝渐变状态环 + 胶囊防护开关 + 2x3 功能宫格（病毒扫描/应用管理/防护设置/授权管理/提权中心/关于我们）

## v1.4.0（2026-10-26）

### 内置 Dhizuku 服务端（完整官方协议）
- 新增 `dhizuku/` 包：`DhizukuServer`（官方 IDhizuku 协议完整实现：remote binder 转发、remoteProcess 全双工进程、bindUserService 反射加载客户端类、delegatedScopes、LockTaskMode 事件转发，SERVER_VERSION_CODE=8）
- `ZhiweiDhizukuProvider`（authority=com.zhiwei.security.dhizuku_server.provider，官方发现机制，任何 Dhizuku-API 应用自动识别）
- `DhizukuGrantActivity`（官方授权申请页，允许/拒绝回调 IDhizukuRequestPermissionListener）
- `ZhiweiDAReceiver` 设备所有者锚点 + zhiwei_device_admin.xml（9 项策略）
- 与 v1.3.0 知微特权服务共用同一授权库 AuthDb

### 音量键斩杀兜底通道
- ProtectService 新增音量监听（300ms 轮询媒体音量，2 秒内变化 3 次以上触发斩杀），不依赖无障碍，任何 ROM 生效
- 与无障碍通道（狂按 3 次）双通道并存

### 关于我们 + 软件更新
- 新增「关于我们」页（ROAM 风格：品牌头部 + 软件更新胶囊按钮 + 版本信息卡 + 开源致谢）
- 软件更新走 GitHub Releases API，应用内流式下载 + FileProvider 调起安装

### 提权中心独立页
- uid.system / 本机 ADB 一键配对 / Dhizuku 服务端一键激活（dpm set-device-owner）/ Shizuku / Dhizuku 外部兼容，一页管完
- 设置页「提权通道」改为入口跳转；新增「关于我们」入口

## v1.3.0（2026-10-25）

### 知微特权服务（Shizuku 式完整授权架构）
- 新增对外特权服务：`ZhiweiProvider`（content://com.zhiwei.security.provider，Shizuku 式 Provider 发现机制）+ `ZhiweiApiService`（Binder 服务）
- 第三方应用可申请授权：弹「授权申请」窗口（允许/拒绝），已授权应用通过知微提权通道（Root/系统 uid/ADB/Shizuku）执行命令
- 设置页新增「授权管理」：查看/撤销已授权应用、管理命令白名单

### 危险命令拦截
- 已授权应用执行危险命令时弹「命令拦截」窗口：**允许一次 / 不允许 / 加入白名单**
- 只拦危险命令（22 类：删文件、写磁盘、格式化、重启关机、卸载/停用应用、强杀、改无障碍、改系统设置、改权限、设备管理器、chattr 文件锁、重挂载、改锁屏密码、模拟触摸等），普通只读命令直接放行不打扰
- 白名单按「应用+命令前缀」粒度存储，加入后同类命令不再拦截；撤销授权自动清空其白名单
- 设置内提供「危险命令拦截」总开关

### 音量键修复
- 修复紧急斩杀触发逻辑：改为**狂按音量键 3 次以上**（音量上/下皆可，2 秒窗口内，其他按键打断计数）

## v1.2.0（2026-10-25）

### ADB 提权内置一键激活
- 新增 mDNS 自动发现（Shizuku 同款方案）：App 自动搜索 `_adb-tls-pairing`/`_adb-tls-connect` 服务，IP 和端口不用手抄
- 激活流程简化为：开无线调试 → 打开配对弹窗 → 回 App 填 6 位配对码 → 点「一键激活」
- 保留手动模式兜底（自动发现失败时可手填 IP/端口）

### 病毒库（第三批：实采样本解包入库）
- 恶意包名 +4：`com.bangbangtang.lock`（无权限锁机）、`com.xielunyan.xlynb`（腾龙十层锁机生成器）、`jamesxu.biuedittext`（初凉锁机生成器）、`com.automsg.qqxqg`（自动扣字）
- 风险名单 +3：`io.shencha.gj`、`com.Tong.nb`、`com.Mixo.XiaoBao`（同壳多马甲灰色工具，判高风险不误杀）
- 名称关键词 +6：格机 / 短信轰炸 / 电话轰炸 / 短信测压 / 自动扣字 / 轰炸神器
- 非 APK 威胁（压缩炸弹、PC 端脚本）已甄别，不入移动端病毒库

## v1.1.0（2026-10-25）

### 病毒库
- 新增社区实采恶意样本 18 条（包名完整显示才收录，宁缺毋滥）：
  - 锁机类：`com.com.xiaoshannb.lock`、`com.com.TSLtrHFJNAkxw`、`com.com.wuyu.lock`、`com.lxh.com`、`com.n.v.m`、`com.9178`（龙卷锁机生成器/Runaway）
  - 伪装系统类：`com.com.system.update`、`com.system.update`、`com.com.system.service`、`com.com.servers.ozzbzk`
  - 其他高危：`com.C000000`（黑屏+杀安全软件）、`com.uxklwljtx.xsoldp.sjjid`「谷」浏览器病毒、`com.klshijie.cs`（广告木马）、`com.com.sssp`（陌阳外挂）、`com.com.synb666`（寻光公益容器）、`com.agssjaajahsjsjj`（一键root）、`com.ghrsak`（AK注入器）、`com.kskbl`（黑客开户）
- 新增落地文件名特征：`My horror Android 13-1.0-1.apk`、`My horror Android 000.apk`

### 品牌
- 应用名称：知微安全
- 全新品牌图标：深色底 + 樱粉盾牌 + 冰蓝安全勾 + 呆毛点缀

### 构建
- 正式版签名（release.keystore，normal 渠道）
- CI 从 assembleDebug 切换为 assembleRelease
- versionCode 2 / versionName 1.1.0
