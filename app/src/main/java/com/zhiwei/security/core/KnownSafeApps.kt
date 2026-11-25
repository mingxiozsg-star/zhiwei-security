package com.zhiwei.security.core

/**
 * 内置「知名应用 / 大型游戏」可信包名库（防误杀底座）
 *
 * 定位：这不是杀毒特征库，而是误报熔断器。
 * - 命中本库的应用 **不参与权限评分、不参与本地特征规则判定**，永久不进斩杀队列
 * - 仍然会做精确黑名单（VirusDb.maliciousPackages）校验：明确列入黑名单的真样本
 *   依旧会被判 VIRUS，但只走三按钮弹窗，绝不静默卸载
 * - 用户可在设置页关闭「内置知名应用白名单」，关闭后一切按原规则评分
 *
 * 为什么需要：主流游戏与社交应用本身会申请悬浮窗、录音、通讯录、无障碍等
 * 高危权限；应用名里也可能出现「外挂」「刷」「免流」等字样（如攻略/助手类）。
 * 纯特征与权限评分在大型包里误报率不可控，必须用白名单先行短路。
 */
object KnownSafeApps {

    /** 精确可信包名（国内主流 + 大型游戏 + 国际常用 + 系统厂商） */
    val trustedPackages: Set<String> = setOf(
        // ===== 腾讯 =====
        "com.tencent.mm",                       // 微信
        "com.tencent.mobileqq",                 // QQ
        "com.tencent.tim",                      // TIM
        "com.tencent.wework",                   // 企业微信
        "com.tencent.mtt",                      // QQ 浏览器
        "com.tencent.qqlive",                   // 腾讯视频
        "com.tencent.qqmusic",                  // QQ 音乐
        "com.tencent.karaoke",                  // 全民K歌
        "com.tencent.weishi",                   // 微视
        "com.tencent.weread",                   // 微信读书
        "com.tencent.android.qqdownloader",     // 应用宝
        "com.tencent.gamehelper.smoba",         // 王者营地
        "com.tencent.djcity.gamequery",         // 腾讯游戏社区
        "com.tencent.tmgp.sgame",               // 王者荣耀
        "com.tencent.tmgp.sgamece",             // 王者荣耀(体验服)
        "com.tencent.tmgp.pubgmhd",             // 和平精英
        "com.tencent.tmgp.pubgm",               // 和平精英(国际)
        "com.tencent.ig",                       // PUBG MOBILE
        "com.rekoo.pubgm",                      // PUBG MOBILE(部分渠道)
        "com.tencent.tmgp.cf",                  // 穿越火线：枪战王者
        "com.tencent.tmgp.cfmb",                // 穿越火线手游
        "com.tencent.tmgp.speedmobile",         // QQ飞车
        "com.tencent.lolm",                     // 英雄联盟手游
        "com.tencent.jkchess",                  // 金铲铲之战
        "com.tencent.tmgp.dfm",                 // 三角洲行动
        "com.tencent.tmgp.dnf",                 // 地下城与勇士
        "com.tencent.tmgp.wuxia",               // 天涯明月刀
        "com.tencent.tmgp.ylm",                 // 英雄杀
        "com.tencent.tmgp.mrfz",                // 明日方舟(腾讯渠道)
        "com.tencent.tmgp.gnyx",                // 火影忍者
        "com.tencent.tmgp.ko3",                 // 拳皇命运
        "com.tencent.tmgp.zzs",                 // 忍者必须死
        "com.tencent.tmgp.qjnn",                // 全民奇迹
        "com.tencent.tmgp.supercell.clashofclans", // 部落冲突(腾讯渠道)
        "com.tencent.tmgp.supercell.brawlstars",   // 荒野乱斗(腾讯渠道)
        "com.tencent.tmgp.roblox",              // Roblox(腾讯渠道)
        "com.tencent.tmgp.arknights",           // 明日方舟(腾讯渠道兼容)
        "com.tencent.tmgp.hok",                 // 王者荣耀国际(AoV)
        "com.tencent.tmgp.lol",                 // LoL Wild Rift
        "com.tencent.tmgp.ff",                  // 使命召唤手游

        // ===== 网易 =====
        "com.netease.cloudmusic",               // 网易云音乐
        "com.netease.newsreader.activity",      // 网易新闻
        "com.netease.mail",                     // 网易邮箱大师
        "com.netease.nsh",                      // 网易大神
        "com.netease.cc",                       // 网易CC直播
        "com.netease.uu",                       // 网易UU加速器
        "com.netease.mkey",                     // 网易安全中心(将军令)
        "com.netease.my",                       // 梦幻西游手游
        "com.netease.onmyoji",                  // 阴阳师
        "com.netease.g67",                      // 第五人格
        "com.netease.party",                    // 蛋仔派对
        "com.netease.dwrg",                     // 明日之后
        "com.netease.yysls",                    // 逆水寒手游
        "com.netease.yjwujian",                 // 永劫无间手游
        "com.netease.l10",                      // 率土之滨
        "com.netease.pfmp",                     // 梦幻西游网页版
        "com.netease.g78na",                    // 决战！平安京
        "com.netease.zzbg",                     // 暗黑破坏神：不朽
        "com.netease.mrfz",                     // 明日方舟(网易渠道兼容)
        "com.netease.lagrange",                 // 无尽的拉格朗日
        "com.netease.race",                     // 网易竞速

        // ===== 米哈游 =====
        "com.miHoYo.Yuanshen",                  // 原神
        "com.miHoYo.ys.mi",                     // 原神(小米渠道)
        "com.miHoYo.ys.bilibili",               // 原神(B服)
        "com.miHoYo.hkrpg",                     // 崩坏：星穹铁道
        "com.miHoYo.hkrpg.bilibili",            // 星穹铁道(B服)
        "com.miHoYo.bh3",                       // 崩坏3
        "com.miHoYo.bh3.bilibili",              // 崩坏3(B服)
        "com.miHoYo.enterprise.NGHSoD",         // 未定事件簿
        "com.miHoYo.cloudgames.ys",             // 云·原神
        "com.miHoYo.Nap",                       // 绝区零
        "com.miHoYo.Nap.bilibili",              // 绝区零(B服)

        // ===== 鹰角 / 库洛 / 深蓝 / 其他二次元大厂 =====
        "com.hypergryph.arknights",             // 明日方舟
        "com.hypergryph.arknights.bilibili",    // 明日方舟(B服)
        "com.hypergryph.exastris",              // 来自星尘
        "com.hypergryph.endfield",              // 明日方舟：终末地
        "com.kurogame.mingchao",                // 鸣潮
        "com.kurogame.pgr",                     // 战双帕弥什
        "com.Sunborn.SnqxExilium",              // 少女前线2：追放
        "com.sunborn.girlsfrontline.cn",        // 少女前线
        "com.bilibili.fatego",                  // FGO(B服)
        "com.bluepoch.mnszs",                   // 重返未来：1999
        "com.papegames.nn4",                    // 无限暖暖
        "com.papegames.lysk.cn",                // 恋与深空
        "com.hermes.games.pcr",                 // 公主连结ReDive
        "com.megagames.pcr",                    // 公主连结(B服)
        "com.tgc.sky.netease",                  // 光·遇
        "com.cygames.umamusume",                // 赛马娘
        "com.xd.rpg",                           // 铃兰之剑
        "com.xd.box",                           // 元气骑士系列工具
        "com.chillyroom.soulknight",            // 元气骑士
        "com.chillyroom.soulknightprequel",     // 元气骑士前传
        "com.ZombieWorldGame.zombieTown",       // 生存类独立游戏

        // ===== 字节跳动 =====
        "com.ss.android.ugc.aweme",             // 抖音
        "com.ss.android.ugc.aweme.lite",        // 抖音极速版
        "com.ss.android.ugc.live",              // 抖音火山版
        "com.ss.android.article.news",          // 今日头条
        "com.ss.android.article.video",         // 西瓜视频
        "com.larus.nova",                       // 剪映
        "com.phoenix.read",                     // 番茄小说
        "com.ss.android.auto",                  // 懂车帝
        "com.bytedance.news.toutiao",           // 头条(旧包名)

        // ===== 阿里 / 蚂蚁 =====
        "com.taobao.taobao",                    // 淘宝
        "com.tmall.wireless",                   // 天猫
        "com.taobao.idlefish",                  // 闲鱼
        "com.taobao.taobao.lite",               // 淘宝特价
        "com.alibaba.android.rimet",            // 钉钉
        "com.eg.android.AlipayGphone",          // 支付宝
        "com.alipay.mobile.client",             // 支付宝(历史)
        "com.youku.phone",                      // 优酷
        "com.autonavi.minimap",                 // 高德地图
        "com.taobao.trip",                      // 飞猪
        "cn.damai",                             // 大麦
        "com.xunmeng.pinduoduo",                // 拼多多
        "com.taobao.mobile.dipei",              // 饿了么(阿里)

        // ===== 百度 / 京东 / 美团 / 其他互联网 =====
        "com.baidu.searchbox",                  // 百度
        "com.baidu.searchbox.lite",             // 百度极速版
        "com.baidu.BaiduMap",                   // 百度地图
        "com.baidu.netdisk",                    // 百度网盘
        "com.jingdong.app.mall",                // 京东
        "com.jd.jrapp",                         // 京东金融
        "com.sankuai.meituan",                  // 美团
        "com.sankuai.meituan.takeoutnew",       // 美团外卖
        "com.dianping.v1",                      // 大众点评
        "com.sdu.didi.psnger",                  // 滴滴出行
        "com.xingin.xhs",                       // 小红书
        "com.immomo.momo",                      // 陌陌
        "com.p1.mobile.putong",                 // 探探
        "com.zhihu.android",                    // 知乎
        "com.douban.frodo",                     // 豆瓣
        "com.kuaishou.nebula",                  // 快手极速版
        "com.smile.gifmaker",                   // 快手
        "com.achievo.vipshop",                  // 唯品会
        "com.sina.weibo",                       // 微博
        "com.tencent.weibo",                    // 腾讯微博
        "com.qzone",                            // QQ空间
        "com.sohu.sohuvideo",                   // 搜狐视频
        "com.hunantv.imgo.activity",            // 芒果TV
        "tv.danmaku.bili",                      // 哔哩哔哩
        "com.bilibili.app.in",                  // 哔哩哔哩(旧)
        "com.qiyi.video",                       // 爱奇艺
        "com.qiyi.video.lite",                  // 爱奇艺极速版
        "com.google.android.youtube",           // YouTube

        // ===== 工具 / 办公 / 输入法 =====
        "cn.wps.moffice_eng",                   // WPS Office
        "com.microsoft.office.word",
        "com.microsoft.office.excel",
        "com.microsoft.office.powerpoint",
        "com.microsoft.office.outlook",
        "com.microsoft.teams",
        "com.slack",
        "com.evernote",
        "com.tencent.weworklocal",              // 企业微信(本地)
        "com.sohu.inputmethod.sogou",           // 搜狗输入法
        "com.iflytek.inputmethod",              // 讯飞输入法
        "com.baidu.input",                      // 百度输入法
        "com.tencent.wetype",                   // 微信键盘
        "com.google.android.inputmethod.latin", // Gboard
        "com.termux",                           // Termux
        "com.ghostsq.commander",                // Ghost Commander
        "ru.zdevs.zarchiver",                   // ZArchiver
        "ru.zdevs.zarchiver.pro",               // ZArchiver Pro
        "bin.mt.plus",                          // MT 管理器
        "com.estrongs.android.pop",             // ES 文件浏览器
        "com.alphainventor.filemanager",        // File Manager+
        "org.mozilla.firefox",                  // Firefox
        "org.mozilla.firefox_beta",
        "com.opera.browser",                    // Opera
        "com.microsoft.emmx",                   // Edge
        "com.android.chrome",                   // Chrome
        "com.qihoo360.mobilesafe",              // 360 手机卫士
        "com.tencent.qqpimsecure",              // 腾讯手机管家
        "com.lbe.security.miui",                // 小米安全中心
        "com.antiy.avl",                        // 安天引擎测试壳

        // ===== 国际常用 =====
        "com.whatsapp",
        "com.facebook.katana",
        "com.facebook.orca",
        "com.instagram.android",
        "com.google.android.gm",
        "com.google.android.apps.maps",
        "com.google.android.apps.photos",
        "com.spotify.music",
        "com.discord",
        "com.telegram.messenger",
        "org.telegram.messenger",
        "org.telegram.plus",
        "com.twitter.android",
        "com.snapchat.android",
        "com.netflix.mediaclient",
        "com.amazon.mShop.android.shopping",
        "com.linkedin.android",
        "com.zhiliaoapp.musically",             // TikTok
        "com.openai.chatgpt",                   // ChatGPT
        "com.anthropic.claude",                 // Claude

        // ===== 国际游戏 =====
        "com.mojang.minecraftpe",               // Minecraft PE
        "com.mojang.minecraftedu",              // Minecraft 教育版
        "com.roblox.client",                    // Roblox
        "com.supercell.clashofclans",           // 部落冲突
        "com.supercell.brawlstars",             // 荒野乱斗
        "com.supercell.clashroyale",            // 皇室战争
        "com.supercell.hayday",                 // 卡通农场
        "com.riotgames.league.wildrift",        // 英雄联盟手游(国际)
        "com.riotgames.league.teamfighttactics",// 云顶之弈(国际)
        "com.epicgames.fortnite",               // 堡垒之夜
        "com.garena.game.kgtw",                 // 传说对决
        "com.garena.game.codm",                 // 使命召唤手游
        "com.activision.callofduty.shooter",    // CODM
        "com.ea.game.pvz2_row",                 // 植物大战僵尸2
        "com.ea.games.r3_row",                  // 极品飞车
        "com.gameloft.android.ANMP.GloftA8HM",  // 狂野飙车
        "com.matteljv.uno",                     // UNO
        "com.innersloth.spacemafia",            // Among Us
        "com.pikpok.dr2.main",                  // 死亡触发
        "com.ubisoft.dancinglion.rc",           // 刺客信条
        "com.bandainamcoent.opbrww",            // 海贼王赏金
        "com.bandainamcoent.gb_en",             // 龙珠
        "jp.gungho.pad",                        // 智龙迷城
        "jp.co.cygames.umamusume",              // 赛马娘(日)
        "com.kakaogames.gdts",                  // 蔚蓝档案(韩)
        "com.YoStarJP.Arknights",               // 明日方舟(日)
        "com.YoStarEN.Arknights",               // 明日方舟(英)
        "com.YoStarKR.Arknights",               // 明日方舟(韩)
        "com.HoYoverse.Yuanshen",               // 原神(国际)
        "com.HoYoverse.hkrpgoversea",           // 星穹铁道(国际)
        "com.HoYoverse.Nap",                    // 绝区零(国际)
        "com.cognosphere.zenless",              // 绝区零(海外)

        // ===== 系统厂商 / 必备组件 =====
        "com.android.settings",
        "com.android.vending",                  // Google Play
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.miui.packageinstaller",
        "com.miui.securitycenter",
        "com.miui.home",
        "com.miui.notes",
        "com.xiaomi.market",
        "com.huawei.appmarket",
        "com.huawei.hwid",
        "com.vivo.appstore",
        "com.oppo.market",
        "com.heytap.market",
        "com.samsung.android.galaxyapps"
    )

    /**
     * 可信包名前缀：覆盖同厂大量子应用/渠道包，避免逐个列举遗漏
     * 只放「厂商自有命名空间」，不放通用词前缀（否则会被恶意包蹭用）
     */
    val trustedPrefixes: List<String> = listOf(
        "com.tencent.tmgp.",     // 腾讯游戏全渠道包
        "com.miHoYo.",           // 米哈游
        "com.HoYoverse.",        // 米哈游海外
        "com.hypergryph.",       // 鹰角
        "com.kurogame.",         // 库洛
        "com.papegames.",        // 叠纸
        "com.chillyroom.",       // 凉屋
        "cn.MeteorWeaver.",      // 模拟器/独立游戏常用
        // 注意：故意 **不** 收录 "com.android." 这类通用命名空间前缀。
        // 恶意包最爱伪装 com.android.xxx（黑名单里的 com.android.system.v5 /
        // com.android.security.update 就是实例），系统应用本身已由
        // ApplicationInfo.FLAG_SYSTEM 判定，无需靠包名前缀。
        "com.google.android.",   // GMS 系
        "com.miui.",             // MIUI 系统组件
        "com.xiaomi.",           // 小米生态
        "com.huawei.",           // 华为生态
        "com.hihonor.",          // 荣耀
        "com.vivo.",             // vivo 生态
        "com.oppo.",             // OPPO 生态
        "com.heytap.",           // 欧加系
        "com.coloros.",          // ColorOS
        "com.samsung.android."   // 三星生态
    )

    /** 纯匹配（不含开关） */
    fun matches(pkg: String): Boolean {
        if (pkg.isEmpty()) return false
        if (pkg in trustedPackages) return true
        return trustedPrefixes.any { pkg.startsWith(it) }
    }

    /**
     * 是否享受内置白名单保护。
     * 关闭开关后返回 false，回归纯特征/评分判定。
     */
    fun isTrusted(pkg: String): Boolean {
        val enabled = try { Prefs.builtinWhitelistEnabled } catch (e: Throwable) { true }
        return enabled && matches(pkg)
    }

    /** UI：内置库规模 */
    fun size(): Int = trustedPackages.size
}
