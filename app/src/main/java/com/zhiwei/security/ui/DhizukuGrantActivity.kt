package com.zhiwei.security.ui

import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rosan.dhizuku.aidl.IDhizukuRequestPermissionListener
import com.rosan.dhizuku.shared.DhizukuVariables
import com.zhiwei.security.core.AuthDb

/**
 * Dhizuku 授权申请页（官方协议 activity）
 * action = 包名 + ".action.REQUEST_DHIZUKU_PERMISSION"
 * 客户端 startActivity 带 uid + request_permission_binder，用户决定后经 listener 回调
 */
class DhizukuGrantActivity : ComponentActivity() {

    private var listener: IDhizukuRequestPermissionListener? = null
    private var callerPkg: String? = null
    private var resolved = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AuthDb.init(this)

        val extras = intent.extras
        val uid = extras?.getInt(DhizukuVariables.PARAM_CLIENT_UID, -1) ?: -1
        val listenerBinder = extras?.getBinder(DhizukuVariables.PARAM_CLIENT_REQUEST_PERMISSION_BINDER)
        if (uid < 0 || listenerBinder == null) { finish(); return }

        listener = IDhizukuRequestPermissionListener.Stub.asInterface(listenerBinder)
        callerPkg = packageManager.getPackagesForUid(uid)?.firstOrNull()
        if (callerPkg == null) { finish(); return }

        // 已授权的直接放行
        if (AuthDb.isGranted(callerPkg!!)) {
            answer(PackageManager.PERMISSION_GRANTED)
            return
        }

        val pkg = callerPkg!!
        val label = try {
            packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
        } catch (e: Exception) { pkg }

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = Color(0xAA0F0F1A)) {
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
                                Text("🛡", fontSize = 40.sp)
                                Spacer(Modifier.height(12.dp))
                                Text("Dhizuku 授权申请", color = Color(0xFFFF6B9D),
                                    fontSize = 20.sp, fontWeight = FontWeight.Bold)
                                Spacer(Modifier.height(12.dp))
                                Text("「$label」\n($pkg)", color = Color.White, fontSize = 15.sp)
                                Spacer(Modifier.height(8.dp))
                                Text(
                                    "申请使用设备所有者特权（Dhizuku 协议）\n授权后可调用系统级设备管理能力",
                                    color = Color(0xFFAAAAAA), fontSize = 13.sp
                                )
                                Spacer(Modifier.height(20.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                    OutlinedButton(
                                        onClick = { answer(PackageManager.PERMISSION_DENIED) },
                                        modifier = Modifier.weight(1f),
                                        colors = ButtonDefaults.outlinedButtonColors(
                                            contentColor = Color(0xFFFF6B6B))
                                    ) { Text("拒绝") }
                                    Button(
                                        onClick = {
                                            AuthDb.grant(pkg)
                                            answer(PackageManager.PERMISSION_GRANTED)
                                        },
                                        modifier = Modifier.weight(1f),
                                        colors = ButtonDefaults.buttonColors(
                                            containerColor = Color(0xFF7EC8E3))
                                    ) { Text("允许", color = Color(0xFF0F0F1A)) }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private fun answer(grantResult: Int) {
        if (!resolved) {
            resolved = true
            try { listener?.onRequestPermission(grantResult) } catch (e: Throwable) { }
        }
        finish()
    }

    override fun onDestroy() {
        if (!resolved) answer(PackageManager.PERMISSION_DENIED)
        super.onDestroy()
    }
}