package com.zhiwei.security.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.core.Privilege
import com.zhiwei.security.core.ThreatResponder
import com.zhiwei.security.ui.theme.ZhiweiSecurityTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 威胁确认弹窗（全屏可锁屏显示）
 *
 * 交互铁律（v1.8.0）：
 * - 本界面自身绝不擅自处置，只做用户决策
 * - 三个按钮：
 *   ①「卸载」→ 用户明确同意后才执行 pm uninstall（无提权则跳系统卸载页）
 *   ②「本次忽略」→ 解除冻结隔离，放行本次，不写白名单，下次仍会提示
 *   ③「加入白名单」→ 写入 whitelist，此后豁免扫描/告警/隔离
 * - 返回键/触摸外部 = 本次忽略（不卸载）
 */
class ShieldWarnActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pkg = intent.getStringExtra("pkg") ?: "unknown"
        val appName = intent.getStringExtra("app_name") ?: pkg
        val reason = intent.getStringExtra("reason") ?: "检测到安全风险"
        val isVirus = intent.getBooleanExtra("is_virus", true)
        Prefs.init(this)

        setContent {
            ZhiweiSecurityTheme {
                val scope = rememberCoroutineScope()
                var processing by remember { mutableStateOf(false) }
                var statusMsg by remember { mutableStateOf<String?>(null) }
                val privReady = remember { Privilege.isReady }

                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = Color(0xE6000000)
                ) {
                    Box(
                        modifier = Modifier.fillMaxSize().padding(22.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Card(
                            shape = RoundedCornerShape(24.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier = Modifier.padding(22.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Text(if (isVirus) "☠️" else "⚠️", fontSize = 48.sp)
                                Spacer(Modifier.height(10.dp))
                                Text(
                                    if (isVirus) "检测到病毒威胁" else "检测到高风险应用",
                                    fontSize = 19.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (isVirus) Color(0xFFF44336) else Color(0xFFFF9800)
                                )
                                Spacer(Modifier.height(12.dp))

                                Text(
                                    appName,
                                    fontSize = 17.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = Color.White,
                                    textAlign = TextAlign.Center
                                )
                                Text(pkg, fontSize = 11.sp, color = Color(0xFF707070))
                                Spacer(Modifier.height(10.dp))

                                Surface(
                                    shape = RoundedCornerShape(12.dp),
                                    color = Color(0xFF252540),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text(
                                        reason,
                                        fontSize = 13.sp,
                                        lineHeight = 19.sp,
                                        color = Color(0xFFB0B0B0),
                                        modifier = Modifier.padding(12.dp)
                                    )
                                }

                                Spacer(Modifier.height(10.dp))
                                Text(
                                    "已做冻结隔离，未删除任何数据。请选择处置方式：",
                                    fontSize = 12.sp,
                                    color = Color(0xFF7EC8E3),
                                    textAlign = TextAlign.Center
                                )

                                statusMsg?.let {
                                    Spacer(Modifier.height(10.dp))
                                    Text(it, fontSize = 13.sp, color = Color(0xFFFFD54F), textAlign = TextAlign.Center)
                                }

                                if (processing) {
                                    Spacer(Modifier.height(12.dp))
                                    CircularProgressIndicator(
                                        color = Color(0xFFF44336),
                                        modifier = Modifier.size(24.dp),
                                        strokeWidth = 3.dp
                                    )
                                }

                                Spacer(Modifier.height(18.dp))

                                // ① 卸载（唯一会删除应用的按钮）
                                Button(
                                    onClick = {
                                        scope.launch {
                                            processing = true
                                            statusMsg = null
                                            if (!Privilege.isReady) {
                                                processing = false
                                                jumpToSystemUninstall(pkg)
                                                return@launch
                                            }
                                            // 先撤销设备管理器（否则 pm uninstall 会失败）
                                            withContext(Dispatchers.IO) {
                                                val adminsOut = Privilege.exec(
                                                    "dpm list-active-admins 2>/dev/null | grep '$pkg/'"
                                                ).second
                                                adminsOut.lines()
                                                    .filter { it.contains("$pkg/") }
                                                    .forEach { line ->
                                                        val rel = line.trim()
                                                            .substringAfter("$pkg/")
                                                            .substringBefore(":")
                                                        if (rel.isNotEmpty()) {
                                                            Privilege.exec("dpm remove-active-admin '$pkg/$rel'")
                                                        }
                                                    }
                                            }
                                            val ok = withContext(Dispatchers.IO) {
                                                ThreatResponder.confirmUninstall(
                                                    this@ShieldWarnActivity, pkg, appName
                                                )
                                            }
                                            processing = false
                                            if (ok) {
                                                Toast.makeText(
                                                    this@ShieldWarnActivity,
                                                    "已卸载 $appName",
                                                    Toast.LENGTH_SHORT
                                                ).show()
                                                finish()
                                            } else {
                                                statusMsg = "自动卸载失败，已跳系统页面"
                                                jumpToSystemUninstall(pkg)
                                            }
                                        }
                                    },
                                    enabled = !processing,
                                    modifier = Modifier.fillMaxWidth().height(50.dp),
                                    shape = RoundedCornerShape(25.dp),
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF44336))
                                ) {
                                    Text(
                                        if (privReady) "卸载该应用" else "卸载（跳系统页面）",
                                        fontSize = 15.sp, fontWeight = FontWeight.Bold
                                    )
                                }

                                Spacer(Modifier.height(10.dp))

                                // ② 本次忽略
                                OutlinedButton(
                                    onClick = {
                                        ThreatResponder.release(pkg)
                                        Toast.makeText(
                                            this@ShieldWarnActivity,
                                            "已放行本次，应用保持原样",
                                            Toast.LENGTH_SHORT
                                        ).show()
                                        finish()
                                    },
                                    enabled = !processing,
                                    modifier = Modifier.fillMaxWidth().height(50.dp),
                                    shape = RoundedCornerShape(25.dp),
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFFF9800))
                                ) {
                                    Text("本次忽略", fontSize = 15.sp)
                                }

                                Spacer(Modifier.height(10.dp))

                                // ③ 加入白名单
                                OutlinedButton(
                                    onClick = {
                                        Prefs.addToWhitelist(pkg)
                                        Prefs.removeFromBlacklist(pkg)
                                        Prefs.addToPermWhitelist(pkg)
                                        ThreatResponder.release(pkg)
                                        Toast.makeText(
                                            this@ShieldWarnActivity,
                                            "已加入白名单，今后不再提示",
                                            Toast.LENGTH_SHORT
                                        ).show()
                                        finish()
                                    },
                                    enabled = !processing,
                                    modifier = Modifier.fillMaxWidth().height(50.dp),
                                    shape = RoundedCornerShape(25.dp),
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFF4CAF50))
                                ) {
                                    Text("加入白名单（永久信任）", fontSize = 15.sp)
                                }

                                Spacer(Modifier.height(8.dp))

                                Text(
                                    "误报请选「加入白名单」，切勿直接卸载",
                                    fontSize = 11.sp,
                                    color = Color(0xFF616161),
                                    textAlign = TextAlign.Center
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    private fun jumpToSystemUninstall(pkg: String) {
        ThreatResponder.onAlertClosed()
        try {
            startActivity(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                    data = Uri.parse("package:$pkg")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            )
        } catch (e: Throwable) { }
        finish()
    }

    override fun onDestroy() {
        // 任何方式离开（按钮/返回键/被系统杀死）都释放弹窗串行锁
        ThreatResponder.onAlertClosed()
        super.onDestroy()
    }
}