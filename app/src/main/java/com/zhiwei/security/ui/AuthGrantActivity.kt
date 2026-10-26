package com.zhiwei.security.ui

import android.content.Context
import android.content.Intent
import android.os.Bundle
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zhiwei.security.core.AuthDb

/**
 * 授权申请弹窗：第三方应用请求使用知微特权服务时弹出
 * （对应 Shizuku 的「允许/拒绝」授权框）
 */
class AuthGrantActivity : ComponentActivity() {

    companion object {
        private var pending: Pair<String, (Boolean) -> Unit>? = null
        private var showing = false

        @Synchronized
        fun request(context: Context, pkg: String, callback: (Boolean) -> Unit) {
            // 已有一个授权框在显示/排队时，直接拒绝后来的（防轰炸）
            // 注意：showing 必须在入队时就置位，否则弹窗启动前的竞态会吞掉先到的回调
            if (showing) { callback(false); return }
            showing = true
            pending = pkg to callback
            try {
                context.startActivity(
                    Intent(context, AuthGrantActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                )
            } catch (e: Throwable) {
                pending = null
                showing = false
                callback(false)
            }
        }

        @Synchronized
        internal fun takePending(): Pair<String, (Boolean) -> Unit>? {
            val p = pending
            return p
        }

        @Synchronized
        internal fun resolve(granted: Boolean) {
            val p = pending
            pending = null
            showing = false
            p?.second?.invoke(granted)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AuthDb.init(this)
        val p = takePending()
        if (p == null) { finish(); return }
        showing = true
        val pkg = p.first
        val appLabel = try {
            packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
        } catch (e: Exception) { pkg }

        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = Color(0xAA0F0F1A)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Card(
                            modifier = Modifier.fillMaxWidth(0.88f),
                            shape = RoundedCornerShape(20.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E))
                        ) {
                            Column(
                                modifier = Modifier.padding(24.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Text("🔑", fontSize = 40.sp)
                                Spacer(Modifier.height(12.dp))
                                Text(
                                    "授权申请",
                                    color = Color(0xFFFF6B9D),
                                    fontSize = 20.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Spacer(Modifier.height(12.dp))
                                Text(
                                    "「$appLabel」\n($pkg)",
                                    color = Color.White,
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Medium
                                )
                                Spacer(Modifier.height(8.dp))
                                Text(
                                    "申请使用知微特权服务\n授权后可通过知微的提权通道执行特权命令\n危险命令仍会逐条弹窗拦截",
                                    color = Color(0xFFAAAAAA),
                                    fontSize = 13.sp
                                )
                                Spacer(Modifier.height(20.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                    OutlinedButton(
                                        onClick = { resolve(false); finish() },
                                        modifier = Modifier.weight(1f),
                                        colors = ButtonDefaults.outlinedButtonColors(
                                            contentColor = Color(0xFFFF6B6B)
                                        )
                                    ) { Text("拒绝") }
                                    Button(
                                        onClick = {
                                            AuthDb.grant(pkg)
                                            resolve(true)
                                            finish()
                                        },
                                        modifier = Modifier.weight(1f),
                                        colors = ButtonDefaults.buttonColors(
                                            containerColor = Color(0xFF7EC8E3)
                                        )
                                    ) { Text("允许", color = Color(0xFF0F0F1A)) }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        // 用户直接划掉/返回，视为拒绝
        if (pending != null) resolve(false)
        super.onDestroy()
    }
}