import 'dart:io';

import 'package:flutter/services.dart';
import 'package:permission_handler/permission_handler.dart';

/// 批量任务的后台保活通道。
///
/// Android：拉起前台服务（dataSync 类型）+ 常驻进度通知，切出应用后进程不被回收。
/// 其它平台：空实现——桌面端最小化后本来就在继续跑，关闭窗口才会结束。
class BackgroundTask {
  static const MethodChannel _channel = MethodChannel('safefile/background');
  static bool _running = false;

  static bool get supported => Platform.isAndroid;
  static bool get running => _running;

  /// Android 13+ 通知需要运行时授权；没有通知服务仍可运行，只是看不见进度。
  static Future<void> ensureNotificationPermission() async {
    if (!Platform.isAndroid) return;
    final status = await Permission.notification.status;
    if (!status.isGranted) {
      await Permission.notification.request();
    }
  }

  static Future<void> start({required String title, required String text}) async {
    if (!Platform.isAndroid) return;
    await ensureNotificationPermission();
    try {
      await _channel.invokeMethod<bool>('start', {'title': title, 'text': text});
      _running = true;
    } on PlatformException {
      _running = false;
    } on MissingPluginException {
      _running = false;
    }
  }

  static Future<void> update({required String title, required String text}) async {
    if (!Platform.isAndroid || !_running) return;
    try {
      await _channel.invokeMethod<bool>('update', {'title': title, 'text': text});
    } on PlatformException {
      // 通知更新失败不影响任务本身。
    } on MissingPluginException {
      _running = false;
    }
  }

  static Future<void> stop() async {
    if (!Platform.isAndroid || !_running) return;
    _running = false;
    try {
      await _channel.invokeMethod<bool>('stop');
    } on PlatformException {
      // 停止失败时服务会随进程结束自行清理。
    } on MissingPluginException {
      // 通道不存在（如桌面端调试）时忽略。
    }
  }
}
