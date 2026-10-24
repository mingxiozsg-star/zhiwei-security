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
import com.zhiwei.security.core.ShizukuManager
import com.zhiwei.security.ui.theme.ZhiweiSecurityTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 全屏威胁警告（锁屏上也可显示）
 * 真实处置动作：
 * - 强制停止（Shizuku am force-stop）
 * - 卸载（Shizuku pm uninstall，兜底跳系统卸载）
 * - 加入黑名单 / 白名单
 */
class ShieldWarnActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pkg = intent.getStringExtra("pkg") ?: "unknown"
        val appName = intent.getStringExtra("app_name") ?: pkg
        val reason = intent.getStringExtra("reason") ?: "检测到安全风险"
        Prefs.init(this)

        setContent {
            ZhiweiSecurityTheme {
                val scope = rememberCoroutineScope()
                var processing by remember { mutableStateOf(false) }
                var statusMsg by remember { mutableStateOf<String?>(null) }
                val shizukuReady = remember { ShizukuManager.isReady }

                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = Color(0xFF1A1A2E)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(32.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text("⚠️", fontSize = 72.sp)
                        Spacer(modifier = Modifier.height(24.dp))
                        Text(
                            "安全警告",
                            fontSize = 28.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFFF44336)
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(appName, fontSize = 20.sp, fontWeight = FontWeight.Medium, color = Color.White)
                        Text(pkg, fontSize = 12.sp, color = Color(0xFF707070))
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            reason,
                            fontSize = 15.sp,
                            color = Color(0xFFB0B0B0),
                            textAlign = TextAlign.Center
                        )

                        statusMsg?.let {
                            Spacer(modifier = Modifier.height(12.dp))
                            Text(it, fontSize = 14.sp, color = Color(0xFF7EC8E3), textAlign = TextAlign.Center)
                        }

                        Spacer(modifier = Modifier.height(32.dp))

                        if (processing) {
                            CircularProgressIndicator(color = Color(0xFFF44336))
                            Spacer(modifier = Modifier.height(16.dp))
                        }

                        // 主按钮：强杀 + 卸载
                        Button(
                            onClick = {
                                scope.launch {
                                    processing = true
                                    Prefs.addToBlacklist(pkg)

                                    if (ShizukuManager.isReady) {
                                        // 1. 先撤销设备管理员（否则卸载会失败）
                                        val admins = withContext(Dispatchers.IO) {
                                            ShizukuManager.listActiveAdmins(pkg)
                                        }
                                        admins.forEach { comp ->
                                            val rel = comp.removePrefix("$pkg/").removePrefix("$pkg/")
                                            withContext(Dispatchers.IO) {
                                                ShizukuManager.removeDeviceAdmin(pkg, rel)
                                            }
                                        }
                                        // 2. 强杀
                                        withContext(Dispatchers.IO) { ShizukuManager.forceStop(pkg) }
                                        // 3. 卸载
                                        val ok = withContext(Dispatchers.IO) { ShizukuManager.uninstall(pkg) }
                                        if (ok) {
                                            statusMsg = "已强制停止并卸载"
                                            Toast.makeText(this@ShieldWarnActivity, "威胁已清除", Toast.LENGTH_SHORT).show()
                                            processing = false
                                            finish()
                                            return@launch
                                        } else {
                                            statusMsg = "自动卸载失败，请手动卸载"
                                        }
                                    } else {
                                        statusMsg = "Shizuku 未连接，跳转手动卸载"
                                    }
                                    processing = false
                                    // 兜底：跳系统应用详情页
                                    startActivity(
                                        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                            data = Uri.parse("package:$pkg")
                                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                        }
                                    )
                                }
                            },
                            enabled = !processing,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(52.dp),
                            shape = RoundedCornerShape(26.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF44336))
                        ) {
                            Text(
                                if (shizukuReady) "强制停止并卸载" else "加入黑名单并手动卸载",
                                fontSize = 16.sp, fontWeight = FontWeight.Bold
                            )
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        // 仅强杀
                        if (shizukuReady) {
                            OutlinedButton(
                                onClick = {
                                    scope.launch {
                                        processing = true
                                        Prefs.addToBlacklist(pkg)
                                        val ok = withContext(Dispatchers.IO) { ShizukuManager.forceStop(pkg) }
                                        statusMsg = if (ok) "已强制停止（已加入黑名单，再次启动会被拦截）" else "强杀失败"
                                        processing = false
                                    }
                                },
                                enabled = !processing,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(52.dp),
                                shape = RoundedCornerShape(26.dp),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFFF9800))
                            ) {
                                Text("仅强制停止", fontSize = 16.sp)
                            }
                            Spacer(modifier = Modifier.height(12.dp))
                        }

                        OutlinedButton(
                            onClick = {
                                Prefs.addToWhitelist(pkg)
                                finish()
                            },
                            enabled = !processing,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(52.dp),
                            shape = RoundedCornerShape(26.dp),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White)
                        ) {
                            Text("加入白名单（信任）", fontSize = 16.sp)
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        TextButton(
                            onClick = { finish() },
                            enabled = !processing,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("忽略本次", color = Color(0xFF9E9E9E), fontSize = 15.sp)
                        }
                    }
                }
            }
        }
    }
}