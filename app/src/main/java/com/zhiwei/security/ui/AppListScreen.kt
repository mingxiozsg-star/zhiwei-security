package com.zhiwei.security.ui

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import androidx.navigation.NavController
import com.zhiwei.security.core.Prefs
import com.zhiwei.security.core.VirusDb
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class AppInfo(
    val packageName: String,
    val appName: String,
    val icon: Drawable?,
    val isSystem: Boolean,
    val isBlacklist: Boolean,
    val isWhitelist: Boolean,
    val riskScore: Int,
    val versionName: String?
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppListScreen(navController: NavController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var apps by remember { mutableStateOf<List<AppInfo>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var searchQuery by remember { mutableStateOf("") }
    var showSystemApps by remember { mutableStateOf(false) }
    var filterMode by remember { mutableStateOf(0) } // 0=全部, 1=黑名单, 2=白名单

    LaunchedEffect(Unit) {
        isLoading = true
        apps = loadInstalledApps(context)
        isLoading = false
    }

    val filteredApps = apps.filter { app ->
        val matchesSearch = searchQuery.isEmpty() ||
                app.appName.contains(searchQuery, true) ||
                app.packageName.contains(searchQuery, true)
        val matchesFilter = when (filterMode) {
            1 -> app.isBlacklist
            2 -> app.isWhitelist
            else -> true
        }
        val matchesSystem = showSystemApps || !app.isSystem
        matchesSearch && matchesFilter && matchesSystem
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("应用管理", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "返回")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
        ) {
            // 搜索栏
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text("搜索应用...") },
                leadingIcon = { Icon(Icons.Default.Search, null) },
                singleLine = true,
                shape = RoundedCornerShape(12.dp)
            )

            Spacer(modifier = Modifier.height(12.dp))

            // 筛选
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilterChip(
                    selected = filterMode == 0,
                    onClick = { filterMode = 0 },
                    label = { Text("全部") }
                )
                FilterChip(
                    selected = filterMode == 1,
                    onClick = { filterMode = 1 },
                    label = { Text("黑名单") }
                )
                FilterChip(
                    selected = filterMode == 2,
                    onClick = { filterMode = 2 },
                    label = { Text("白名单") }
                )
                FilterChip(
                    selected = showSystemApps,
                    onClick = { showSystemApps = !showSystemApps },
                    label = { Text("系统") }
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            if (isLoading) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            } else {
                Text("${filteredApps.size} 个应用", fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(modifier = Modifier.height(8.dp))
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    items(filteredApps, key = { it.packageName }) { app ->
                        AppListItem(
                            app = app,
                            onToggleBlacklist = {
                                scope.launch {
                                    if (app.isBlacklist) {
                                        Prefs.removeFromBlacklist(app.packageName)
                                    } else {
                                        Prefs.addToBlacklist(app.packageName)
                                        Prefs.removeFromWhitelist(app.packageName)
                                    }
                                    apps = loadInstalledApps(context)
                                }
                            },
                            onToggleWhitelist = {
                                scope.launch {
                                    if (app.isWhitelist) {
                                        Prefs.removeFromWhitelist(app.packageName)
                                    } else {
                                        Prefs.addToWhitelist(app.packageName)
                                        Prefs.removeFromBlacklist(app.packageName)
                                    }
                                    apps = loadInstalledApps(context)
                                }
                            },
                            onUninstall = {
                                val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                    data = Uri.parse("package:${app.packageName}")
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                }
                                context.startActivity(intent)
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun AppListItem(
    app: AppInfo,
    onToggleBlacklist: () -> Unit,
    onToggleWhitelist: () -> Unit,
    onUninstall: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(
            containerColor = when {
                app.isBlacklist -> Color(0xFFF44336).copy(alpha = 0.08f)
                app.isWhitelist -> Color(0xFF4CAF50).copy(alpha = 0.08f)
                else -> MaterialTheme.colorScheme.surfaceVariant
            }
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // 应用图标
            app.icon?.let { drawable ->
                val bitmap = remember { drawable.toBitmap(48, 48) }
                Image(
                    bitmap = bitmap.asImageBitmap(),
                    contentDescription = null,
                    modifier = Modifier
                        .size(44.dp)
                        .clip(RoundedCornerShape(10.dp))
                )
            } ?: Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.2f)),
                contentAlignment = Alignment.Center
            ) {
                Text("📱", fontSize = 20.sp)
            }

            Spacer(modifier = Modifier.width(10.dp))

            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(app.appName, fontWeight = FontWeight.Medium, fontSize = 14.sp)
                    if (app.isSystem) {
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("系统", fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Text(app.packageName, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            // 黑名单标记
            IconButton(onClick = onToggleBlacklist, modifier = Modifier.size(36.dp)) {
                Text(
                    if (app.isBlacklist) "🚫" else "⬛",
                    fontSize = 16.sp
                )
            }

            // 白名单标记
            IconButton(onClick = onToggleWhitelist, modifier = Modifier.size(36.dp)) {
                Text(
                    if (app.isWhitelist) "✅" else "⬜",
                    fontSize = 16.sp
                )
            }
        }
    }
}

private suspend fun loadInstalledApps(context: Context): List<AppInfo> = withContext(Dispatchers.IO) {
    val pm = context.packageManager
    Prefs.init(context)

    val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
    } else {
        @Suppress("DEPRECATION")
        pm.getInstalledApplications(0)
    }

    packages.map { appInfo ->
        val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        AppInfo(
            packageName = appInfo.packageName,
            appName = try { appInfo.loadLabel(pm).toString() } catch (e: Exception) { appInfo.packageName },
            icon = try { appInfo.loadIcon(pm) } catch (e: Exception) { null },
            isSystem = isSystem,
            isBlacklist = appInfo.packageName in Prefs.blacklist,
            isWhitelist = appInfo.packageName in Prefs.whitelist,
            riskScore = 0,
            versionName = try {
                pm.getPackageInfo(appInfo.packageName, 0).versionName
            } catch (e: Exception) { null }
        )
    }.sortedWith(compareBy({ !it.isBlacklist }, { it.appName }))
}
