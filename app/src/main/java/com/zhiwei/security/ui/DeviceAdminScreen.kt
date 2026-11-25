package com.zhiwei.security.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.zhiwei.security.core.DeviceAdminCounter
import com.zhiwei.security.core.Privilege
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 设备管理员反制页（v1.8.1）
 *
 * 解决的是锁机勒索：恶意软件诱导用户激活设备管理器后，
 * 可改锁屏密码、锁死前台、阻止卸载，用户被彻底锁死。
 * 本页把全机已激活的设备管理员摊开，标注「自己 / 可信 / 未知第三方」，
 * 并允许对未知第三方一键撤销管理员身份（可逆操作，不卸载应用）。
 */
private val BgDark = Color(0xFF0F0F1A)
private val CardDark = Color(0xFF1A1A2E)
private val Pink = Color(0xFFFF6B9D)
private val Ice = Color(0xFF7EC8E3)
private val TextGray = Color(0xFF9090A0)
private val Green = Color(0xFF9CCC65)
private val Red = Color(0xFFEF5350)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceAdminScreen(navController: NavController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var admins by remember { mutableStateOf<List<DeviceAdminCounter.AdminEntry>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var busy by remember { mutableStateOf("") }
    var msg by remember { mutableStateOf("") }
    var refresh by remember { mutableStateOf(0) }
    var confirmTarget by remember { mutableStateOf<DeviceAdminCounter.AdminEntry?>(null) }
    var confirmAll by remember { mutableStateOf(false) }

    LaunchedEffect(refresh) {
        loading = true
        admins = withContext(Dispatchers.IO) {
            DeviceAdminCounter.invalidateCache()
            try { DeviceAdminCounter.listActiveAdmins(context) } catch (e: Throwable) { emptyList() }
        }
        loading = false
    }

    // 单个反制确认弹窗
    confirmTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { confirmTarget = null },
            containerColor = CardDark,
            title = { Text("撤销管理员身份", color = Color.White, fontWeight = FontWeight.Bold) },
            text = {
                Text(
                    "「${target.appName}」当前持有设备管理器权限，可修改锁屏密码、锁死屏幕、阻止卸载。\n\n" +
                        "撤销后该应用仍会保留在手机上（数据不丢），仅失去上述高危能力。",
                    color = TextGray, fontSize = 13.sp, lineHeight = 19.sp
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmTarget = null
                    busy = target.component
                    scope.launch {
                        val ok = withContext(Dispatchers.IO) { DeviceAdminCounter.counter(target) }
                        msg = if (ok) "✅ 已撤销「${target.appName}」的设备管理员身份"
                        else "❌ 撤销失败：该应用可能是设备所有者，需先在系统设置中解除"
                        busy = ""
                        refresh++
                    }
                }) { Text("撤销", color = Pink, fontWeight = FontWeight.Bold) }
            },
            dismissButton = {
                TextButton(onClick = { confirmTarget = null }) { Text("取消", color = TextGray) }
            }
        )
    }

    // 批量反制确认弹窗
    if (confirmAll) {
        AlertDialog(
            onDismissRequest = { confirmAll = false },
            containerColor = CardDark,
            title = { Text("撤销全部可疑管理员", color = Color.White, fontWeight = FontWeight.Bold) },
            text = {
                Text(
                    "将逐个撤销所有「未知第三方」应用的设备管理器权限。\n" +
                        "知微自身与可信应用白名单（434 个）内的应用不受影响。\n\n" +
                        "此操作可逆，不会卸载任何应用。",
                    color = TextGray, fontSize = 13.sp, lineHeight = 19.sp
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmAll = false
                    busy = "ALL"
                    scope.launch {
                        val n = withContext(Dispatchers.IO) {
                            try { DeviceAdminCounter.counterAllHostile(context) } catch (e: Throwable) { 0 }
                        }
                        msg = if (n > 0) "✅ 已撤销 $n 个可疑应用的管理员身份" else "未撤销任何应用（可能全部失败或已被移除）"
                        busy = ""
                        refresh++
                    }
                }) { Text("全部撤销", color = Red, fontWeight = FontWeight.Bold) }
            },
            dismissButton = {
                TextButton(onClick = { confirmAll = false }) { Text("取消", color = TextGray) }
            }
        )
    }

    Scaffold(
        containerColor = BgDark,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("设备管理员", fontWeight = FontWeight.Bold, color = Color.White)
                        Text("锁机勒索反制", fontSize = 11.sp, color = Pink)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "返回", tint = Color.White)
                    }
                },
                actions = {
                    TextButton(onClick = { refresh++ }, enabled = busy.isEmpty()) {
                        Text(if (loading) "…" else "刷新", color = Ice, fontSize = 13.sp)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = BgDark)
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Spacer(modifier = Modifier.height(4.dp))

            // 说明卡
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = CardDark)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("为什么这项重要", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color.White)
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        "锁机木马最常见的套路：诱导你点「激活设备管理器」，随后偷偷改掉锁屏密码、" +
                            "把恶意界面锁死在最前台，让你既进不了系统也卸载不掉。\n\n" +
                            "撤销设备管理员身份即可斩断这条链，且应用本身不会被删除。",
                        fontSize = 12.sp, color = TextGray, lineHeight = 18.sp
                    )
                }
            }

            // 提权未就绪提示
            if (!Privilege.isReady) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF3A2028))
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text("⚠️ 提权未就绪，只能查看不能反制", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Red)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            "枚举与撤销设备管理员需要 shell 权限。请到提权中心连接本机 ADB / Root / Shizuku。",
                            fontSize = 11.sp, color = TextGray, lineHeight = 16.sp
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = { navController.navigate("privilege") },
                            shape = RoundedCornerShape(20.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Pink),
                            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 6.dp)
                        ) { Text("去提权中心", fontSize = 12.sp, color = Color.White) }
                    }
                }
            }

            if (msg.isNotEmpty()) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF23233D))
                ) {
                    Text(msg, modifier = Modifier.padding(12.dp), fontSize = 12.sp, color = Ice, lineHeight = 17.sp)
                }
            }

            if (loading) {
                Box(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 40.dp),
                    contentAlignment = Alignment.Center
                ) { CircularProgressIndicator(color = Pink, modifier = Modifier.size(28.dp)) }
            } else if (admins.isEmpty()) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = CardDark)
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(28.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text("🛡️", fontSize = 32.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            if (Privilege.isReady) "全机没有已激活的设备管理员" else "无法读取（提权未就绪）",
                            fontSize = 13.sp, color = TextGray
                        )
                    }
                }
            } else {
                val hostile = admins.filter { it.isHostile }

                // 概览行
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    StatBox("已激活", admins.size.toString(), Color.White, Modifier.weight(1f))
                    StatBox("可疑", hostile.size.toString(), if (hostile.isEmpty()) Green else Red, Modifier.weight(1f))
                }

                if (hostile.isNotEmpty()) {
                    Button(
                        onClick = { confirmAll = true },
                        enabled = busy.isEmpty() && Privilege.isReady,
                        modifier = Modifier.fillMaxWidth().height(46.dp),
                        shape = RoundedCornerShape(23.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Red.copy(alpha = 0.85f),
                            contentColor = Color.White,
                            disabledContainerColor = Color(0xFF3A3A55)
                        )
                    ) {
                        Text(
                            if (busy == "ALL") "正在撤销…" else "一键撤销全部可疑管理员（${hostile.size}）",
                            fontSize = 14.sp, fontWeight = FontWeight.Bold
                        )
                    }
                }

                admins.forEach { entry ->
                    AdminRow(
                        entry = entry,
                        busy = busy == entry.component,
                        canAct = busy.isEmpty() && Privilege.isReady,
                        onCounter = { confirmTarget = entry }
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
            Text(
                "反制策略：只撤销管理员身份，绝不卸载应用。知微自身与 434 个可信应用白名单永久豁免。",
                fontSize = 10.sp, color = Color(0xFF606070), lineHeight = 15.sp
            )
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
private fun StatBox(label: String, value: String, valueColor: Color, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = CardDark)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(value, fontSize = 22.sp, fontWeight = FontWeight.Bold, color = valueColor)
            Text(label, fontSize = 11.sp, color = TextGray)
        }
    }
}

@Composable
private fun AdminRow(
    entry: DeviceAdminCounter.AdminEntry,
    busy: Boolean,
    canAct: Boolean,
    onCounter: () -> Unit
) {
    val tag: String
    val tagColor: Color
    when {
        entry.isSelf -> { tag = "知微自身"; tagColor = Ice }
        entry.isTrusted -> { tag = "可信应用"; tagColor = Green }
        else -> { tag = "可疑"; tagColor = Red }
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (entry.isHostile) Color(0xFF2A1A22) else CardDark
        )
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    entry.appName,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium,
                    color = Color.White,
                    modifier = Modifier.weight(1f)
                )
                Box(
                    modifier = Modifier
                        .padding(start = 8.dp)
                ) {
                    Text(tag, fontSize = 10.sp, color = tagColor, fontWeight = FontWeight.Bold)
                }
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(entry.pkg, fontSize = 11.sp, color = TextGray)
            Text(entry.receiverClass, fontSize = 10.sp, color = Color(0xFF606070))

            if (entry.isHostile) {
                Spacer(modifier = Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onCounter,
                        enabled = canAct,
                        shape = RoundedCornerShape(18.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Red.copy(alpha = 0.85f),
                            contentColor = Color.White,
                            disabledContainerColor = Color(0xFF3A3A55)
                        ),
                        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 6.dp)
                    ) {
                        Text(if (busy) "处理中…" else "撤销管理员", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                    OutlinedButton(
                        onClick = { },
                        enabled = false,
                        shape = RoundedCornerShape(18.dp),
                        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp)
                    ) {
                        Text("可改密码·锁屏", fontSize = 11.sp, color = Red)
                    }
                }
            }
        }
    }
}
