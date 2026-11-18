package com.cxywh.safefile

import android.content.Context
import android.os.Build
import android.os.storage.StorageManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * 两条通道：
 * - `safefile/background`：前台服务保活与通知文案，任务本身在 Rust 线程里跑。
 * - `safefile/storage`：向系统要存储卷列表。
 *
 * 卷列表必须问 StorageManager，不能自己扫 `/storage`：该目录权限是 `drwx--x--- root:media_rw`，
 * 应用进程列不出内容，于是 U 盘永远发现不了。
 */
class MainActivity : FlutterActivity() {
    private val backgroundChannel = "safefile/background"
    private val storageChannel = "safefile/storage"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, backgroundChannel)
            .setMethodCallHandler { call: MethodCall, result: MethodChannel.Result ->
                try {
                    when (call.method) {
                        "start", "update" -> {
                            val title = call.argument<String>("title") ?: "正在处理"
                            val text = call.argument<String>("text") ?: ""
                            BatchService.start(this, title, text)
                            result.success(true)
                        }
                        "stop" -> {
                            BatchService.stop(this)
                            result.success(true)
                        }
                        else -> result.notImplemented()
                    }
                } catch (e: Exception) {
                    // 通知权限被收回时 startForegroundService 可能抛异常，降级为「无通知继续跑」。
                    result.error("background_failed", e.message, null)
                }
            }

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, storageChannel)
            .setMethodCallHandler { call: MethodCall, result: MethodChannel.Result ->
                when (call.method) {
                    "volumes" -> result.success(storageVolumes())
                    else -> result.notImplemented()
                }
            }
    }

    /** 内部共享存储 + 所有可移动卷（OTG U 盘、SD 卡）的真实挂载路径。 */
    private fun storageVolumes(): List<Map<String, Any>> {
        val list = mutableListOf<Map<String, Any>>()
        val sm = getSystemService(Context.STORAGE_SERVICE) as StorageManager
        for (volume in sm.storageVolumes) {
            val dir = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) volume.directory else null
            if (dir == null || !dir.exists()) continue
            val path = dir.absolutePath
            val primary = volume.isPrimary
            val label = if (primary) "内部存储" else "U 盘 · ${path.substringAfterLast('/')}"
            list.add(
                mapOf(
                    "path" to path,
                    "label" to label,
                    "removable" to volume.isRemovable,
                    "primary" to primary,
                )
            )
        }
        // 主存储排在最前，其余按路径排序，保证下拉顺序稳定。
        return list.sortedWith(compareByDescending<Map<String, Any>> { it["primary"] == true }
            .thenBy { it["path"] as String })
    }
}
