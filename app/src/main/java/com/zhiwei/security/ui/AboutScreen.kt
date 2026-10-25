package com.zhiwei.security.ui

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.zhiwei.security.R
import com.zhiwei.security.core.UpdateChecker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 关于我们（ROAM 风格：品牌头部 + 软件更新按钮 + 信息卡片）
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AboutScreen(navController: NavController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val versionName = remember {
        try { context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "?" }
        catch (e: Exception) { "?" }
    }
    val versionCode = remember {
        try {
            if (android.os.Build.VERSION.SDK_INT >= 28)
                context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode
            else @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(context.packageName, 0).versionCode.toLong()
        } catch (e: Exception) { 0L }
    }

    var updateState by remember { mutableStateOf("点击检查更新") }
    var checking by remember { mutableStateOf(false) }
    var downloadProgress by remember { mutableStateOf(-1) }
    var pendingInstall by remember { mutableStateOf<java.io.File?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("关于", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF0F0F1A), titleContentColor = Color.White
                )
            )
        },
        containerColor = Color(0xFF0F0F1A)
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(Modifier.height(36.dp))

            // 品牌图标（用矢量前景+品牌色圆底，避免 adaptive-icon 解析崩溃）
            Box(
                modifier = Modifier
                    .size(84.dp)
                    .clip(CircleShape)
                    .background(Color(0xFFFF6B9D)),
                contentAlignment = Alignment.Center
            ) {
                Image(
                    painter = painterResource(R.drawable.ic_launcher_foreground),
                    contentDescription = null,
                    modifier = Modifier.size(72.dp)
                )
            }
            Spacer(Modifier.height(16.dp))

            // 品牌英文名（ROAM 风格大字）
            Text(
                "zhiwei security",
                color = Color.White,
                fontSize = 26.sp,
                fontWeight = FontWeight.Bold
            )
            Spacer(Modifier.height(6.dp))
            Text(
                "v$versionName（$versionCode）",
                color = Color(0xFF9090A0),
                fontSize = 14.sp
            )
            Spacer(Modifier.height(14.dp))

            // 软件更新按钮（胶囊）
            Button(
                onClick = {
                    if (checking) return@Button
                    checking = true
                    updateState = "正在检查…"
                    scope.launch {
                        val info = withContext(Dispatchers.IO) { UpdateChecker.check() }
                        if (info == null) {
                            updateState = "检查失败：网络不可用"
                            checking = false
                            return@launch
                        }
                        if (!UpdateChecker.isNewer(info.tag, versionName)) {
                            updateState = "已是最新版本"
                            checking = false
                            return@launch
                        }
                        // 有新版本 → 应用内下载
                        updateState = "发现新版本 ${info.tag}，正在下载…"
                        val url = info.apkUrl
                        if (url == null) {
                            updateState = "发现新版本 ${info.tag}，但无下载地址"
                            checking = false
                            return@launch
                        }
                        val file = withContext(Dispatchers.IO) {
                            UpdateChecker.download(context, url) { p -> downloadProgress = p }
                        }
                        downloadProgress = -1
                        checking = false
                        if (file != null) {
                            pendingInstall = file
                            updateState = "${info.tag} 下载完成，点击安装"
                        } else {
                            updateState = "下载失败，请稍后重试"
                        }
                    }
                },
                shape = RoundedCornerShape(50),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2A2A3E))
            ) {
                Text("软件更新", color = Color.White, fontSize = 14.sp)
            }
            if (downloadProgress >= 0) {
                Spacer(Modifier.height(10.dp))
                LinearProgressIndicator(
                    progress = { downloadProgress / 100f },
                    modifier = Modifier.fillMaxWidth(0.6f),
                    color = Color(0xFFFF6B9D)
                )
            }
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = {
                val f = pendingInstall
                if (f != null) UpdateChecker.install(context, f)
            }) {
                Text(updateState, color = Color(0xFF7EC8E3), fontSize = 13.sp)
            }

            Spacer(Modifier.height(24.dp))

            // 软件与版本信息卡片（ROAM 风格分组行）
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(horizontal = 18.dp, vertical = 6.dp)) {
                    AboutRow("软件名称", "知微安全")
                    AboutDivider()
                    AboutRow("版本", "v$versionName（$versionCode）")
                    AboutDivider()
                    AboutRow("编译渠道", "GitHub Actions · 正式签名")
                    AboutDivider()
                    AboutRow("软件作者", "青宇创想 · 知微")
                    AboutDivider()
                    AboutRow("联系作者", "QQ 资源分享群 1131325287")
                    AboutDivider()
                    AboutRow("项目地址", "github.com/mingxiozsg-star/zhiwei-security")
                }
            }

            Spacer(Modifier.height(16.dp))

            // 能力说明
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Text("核心能力", color = Color.White, fontSize = 15.sp, fontWeight = FontWeight.Medium)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "本地病毒特征库扫描 · 前台恶意应用拦截 · 防锁机守护\n" +
                        "音量狂按紧急斩杀 · 无障碍霸占检测 · 三进程互守\n" +
                        "Root / uid.system / ADB / Shizuku 四级提权\n" +
                        "内置 Dhizuku 服务端 · Shizuku 式授权架构 · 危险命令拦截",
                        color = Color(0xFF9090A0), fontSize = 13.sp, lineHeight = 20.sp
                    )
                }
            }

            Spacer(Modifier.height(16.dp))

            // 开源仓库链接
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
            ) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Text("致谢开源项目", color = Color.White, fontSize = 15.sp, fontWeight = FontWeight.Medium)
                    Spacer(Modifier.height(8.dp))
                    LinkRow("Shizuku（RikkaApps）", "https://github.com/RikkaApps/Shizuku")
                    LinkRow("Dhizuku（iamr0s）", "https://github.com/iamr0s/Dhizuku")
                    LinkRow("LADB（tytydraco）", "https://github.com/tytydraco/LADB")
                }
            }

            Spacer(Modifier.height(40.dp))
        }
    }
}

@Composable
private fun AboutRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = Color(0xFF9090A0), fontSize = 14.sp, modifier = Modifier.weight(1f))
        Text(value, color = Color.White, fontSize = 14.sp)
    }
}

@Composable
private fun AboutDivider() {
    HorizontalDivider(color = Color(0xFF2A2A3E), thickness = 0.5.dp)
}

@Composable
private fun LinkRow(name: String, url: String) {
    val context = LocalContext.current
    TextButton(onClick = {
        val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        cm.setPrimaryClip(android.content.ClipData.newPlainText(name, url))
        android.widget.Toast.makeText(context, "链接已复制：$url", android.widget.Toast.LENGTH_SHORT).show()
    }) {
        Text("$name →", color = Color(0xFF7EC8E3), fontSize = 13.sp)
    }
}