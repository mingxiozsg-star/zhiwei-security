package com.zhiwei.security.ui

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zhiwei.security.core.DangerousCommands
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * 命令拦截弹窗：已授权应用执行危险命令时弹出
 * 三个选择：允许一次 / 不允许 / 加入白名单（该应用同类命令以后不再拦）
 */
class CommandConfirmActivity : ComponentActivity() {

    enum class Decision { ALLOW_ONCE, DENY, WHITELIST, TIMEOUT }

    companion object {
        private var latch: CountDownLatch? = null
        private var decision: Decision = Decision.DENY
        private var pendingInfo: Triple<String, String, DangerousCommands.Danger>? = null
        private var showing = false

        /**
         * 发起拦截确认并同步等待用户决定
         * @return 用户的决定（超时视为 TIMEOUT → 拒绝）
         */
        @Synchronized
        fun requestBlocking(
            context: Context,
            pkg: String,
            cmd: String,
            danger: DangerousCommands.Danger,
            timeoutMs: Long
        ): Decision {
            // 已有拦截框在显示时，不并发弹，直接拒绝后来的（防弹窗轰炸）
            if (showing) return Decision.DENY
            showing = true
            latch = CountDownLatch(1)
            decision = Decision.DENY
            pendingInfo = Triple(pkg, cmd, danger)
            try {
                context.startActivity(
                    Intent(context, CommandConfirmActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                )
                latch?.let { l ->
                    if (!l.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                        // 超时单独标记，调用方可以区分「用户拒绝」与「用户没理」
                        if (decision == Decision.DENY) decision = Decision.TIMEOUT
                    }
                }
                return decision
            } catch (e: Exception) {
                return Decision.DENY
            } finally {
                latch = null
                pendingInfo = null
                showing = false
            }
        }

        @Synchronized
        internal fun resolve(d: Decision) {
            decision = d
            latch?.countDown()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val info = pendingInfo
        if (info == null) { finish(); return }
        val (pkg, cmd, danger) = info
        val appLabel = try {
            packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
        } catch (e: Exception) { pkg }

        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = Color(0xCC0F0F1A)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Card(
                            modifier = Modifier.fillMaxWidth(0.9f),
                            shape = RoundedCornerShape(20.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
                        ) {
                            Column(
                                modifier = Modifier.padding(24.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Text("⛔", fontSize = 40.sp)
                                Spacer(Modifier.height(8.dp))
                                Text(
                                    "命令拦截",
                                    color = Color(0xFFFF6B9D),
                                    fontSize = 20.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Spacer(Modifier.height(12.dp))
                                Text(
                                    "「$appLabel」试图执行危险命令",
                                    color = Color.White,
                                    fontSize = 15.sp
                                )
                                Spacer(Modifier.height(10.dp))
                                // 命令原文（等宽字体）
                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(Color(0xFF0F0F1A), RoundedCornerShape(10.dp))
                                        .padding(12.dp)
                                ) {
                                    Text(
                                        cmd,
                                        color = Color(0xFF7EC8E3),
                                        fontSize = 13.sp,
                                        fontFamily = FontFamily.Monospace
                                    )
                                }
                                Spacer(Modifier.height(10.dp))
                                Text(
                                    "⚠️ ${danger.category}：${danger.description}",
                                    color = Color(0xFFFFB347),
                                    fontSize = 13.sp
                                )
                                Spacer(Modifier.height(20.dp))
                                // 三个选择
                                Button(
                                    onClick = { resolve(Decision.ALLOW_ONCE); finish() },
                                    modifier = Modifier.fillMaxWidth(),
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = Color(0xFF7EC8E3)
                                    )
                                ) { Text("允许一次", color = Color(0xFF0F0F1A)) }
                                Spacer(Modifier.height(8.dp))
                                OutlinedButton(
                                    onClick = { resolve(Decision.WHITELIST); finish() },
                                    modifier = Modifier.fillMaxWidth(),
                                    colors = ButtonDefaults.outlinedButtonColors(
                                        contentColor = Color(0xFF9CCC65)
                                    )
                                ) { Text("加入白名单（不再拦截此类命令）") }
                                Spacer(Modifier.height(8.dp))
                                OutlinedButton(
                                    onClick = { resolve(Decision.DENY); finish() },
                                    modifier = Modifier.fillMaxWidth(),
                                    colors = ButtonDefaults.outlinedButtonColors(
                                        contentColor = Color(0xFFFF6B6B)
                                    )
                                ) { Text("不允许") }
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        // 用户划掉窗口视为拒绝
        resolve(Decision.DENY)
        super.onDestroy()
    }
}