package com.cxywh.safefile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * 批量加解密的前台服务。
 *
 * 作用只有一个：任务进行期间把进程钉在前台，让用户切出应用后系统不回收进程，
 * 并给出一条不可滑掉的进度通知。真正的加解密仍在 Rust 线程里跑，这里不碰文件。
 */
class BatchService : Service() {
    companion object {
        private const val CHANNEL_ID = "safefile-batch-v2"
        private const val NOTIFICATION_ID = 4201
        const val EXTRA_TITLE = "title"
        const val EXTRA_TEXT = "text"

        /** 启动或更新通知；重复调用只会更新文案。 */
        fun start(context: Context, title: String, text: String) {
            val intent = Intent(context, BatchService::class.java).apply {
                putExtra(EXTRA_TITLE, title)
                putExtra(EXTRA_TEXT, text)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, BatchService::class.java))
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val title = intent?.getStringExtra(EXTRA_TITLE) ?: "正在处理"
        val text = intent?.getStringExtra(EXTRA_TEXT) ?: ""
        ensureChannel()
        val notification = buildNotification(title, text)
        // Android 10+ 必须带服务类型，否则系统记「FGS stop call ... has no types」并可能提前回收。
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        // 任务由 Flutter 侧驱动：进程被杀不需要自动重启，避免留下空转的通知。
        return START_NOT_STICKY
    }

    private fun buildNotification(title: String, text: String): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setCategory(Notification.CATEGORY_PROGRESS)
            .setProgress(0, 0, true)
            .setShowWhen(false)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(open)
            .build()
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(CHANNEL_ID, "加解密任务", NotificationManager.IMPORTANCE_DEFAULT)
        channel.description = "任务进行中的常驻通知，点按可回到应用查看进度"
        channel.setShowBadge(false)
        channel.enableVibration(false)
        channel.setSound(null, null)
        manager.createNotificationChannel(channel)
    }
}
