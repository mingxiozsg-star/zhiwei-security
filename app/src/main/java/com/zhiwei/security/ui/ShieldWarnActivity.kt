package com.zhiwei.security.ui

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
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
import com.zhiwei.security.ui.theme.ZhiweiSecurityTheme

class ShieldWarnActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pkg = intent.getStringExtra("pkg") ?: "unknown"
        val appName = intent.getStringExtra("app_name") ?: pkg
        val reason = intent.getStringExtra("reason") ?: "检测到安全风险"

        setContent {
            ZhiweiSecurityTheme {
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
                        Text(
                            appName,
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color.White
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            reason,
                            fontSize = 15.sp,
                            color = Color(0xFFB0B0B0),
                            textAlign = TextAlign.Center
                        )
                        Spacer(modifier = Modifier.height(40.dp))

                        // 操作按钮
                        Button(
                            onClick = {
                                // 加入黑名单
                                Prefs.init(this@ShieldWarnActivity)
                                Prefs.addToBlacklist(pkg)
                                // 跳转到应用详情页卸载
                                val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                    data = Uri.parse("package:$pkg")
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                }
                                startActivity(intent)
                                finish()
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(52.dp),
                            shape = RoundedCornerShape(26.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF44336))
                        ) {
                            Text("加入黑名单并卸载", fontSize = 16.sp, fontWeight = FontWeight.Bold)
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        OutlinedButton(
                            onClick = {
                                Prefs.init(this@ShieldWarnActivity)
                                Prefs.addToWhitelist(pkg)
                                finish()
                            },
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