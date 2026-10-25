# 更新日志

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
