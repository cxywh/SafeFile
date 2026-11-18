import 'dart:io';

import 'package:permission_handler/permission_handler.dart';

/// Android 存储访问。
///
/// 背景：Android 11 起，应用只能用 SAF 拿到的缓存副本或自己的私有目录；
/// 直接 open(`/storage/emulated/0/...`) 会被内核拒绝，表现为 `EPERM (os error 1)`。
/// 文件夹加密、公开输出目录都需要真实路径，因此统一走「所有文件访问权限」
/// (`MANAGE_EXTERNAL_STORAGE`)：授予后普通 `File` API 对用户可见目录完全可用。
///
/// 未授予时不静默降级成私有目录，而是让调用方把权限状态显式呈现给用户——
/// 否则用户会看到「加密成功」却在自己的文件管理器里找不到产物。
class AndroidStorage {
  const AndroidStorage._();

  /// 公开输出目录（所有文件访问权限可用时）。
  static const String publicRoot = '/storage/emulated/0/SafeFile';

  static Future<bool> hasAllFilesAccess() async {
    if (!Platform.isAndroid) return true;
    return Permission.manageExternalStorage.isGranted;
  }

  /// 拉起系统授权页。返回拉起后是否已获得权限（用户可能在系统页里点了允许）。
  static Future<bool> requestAllFilesAccess() async {
    if (!Platform.isAndroid) return true;
    final status = await Permission.manageExternalStorage.request();
    return status.isGranted;
  }

  /// 已授权时返回公开输出目录（必要时创建），否则返回 null。
  ///
  /// 返回前会做一次真实写入探测：部分机型/ROM 上「所有文件访问权限」显示已授予，
  /// 但 `/storage/emulated/0` 仍不可写（或目录被同名的文件占住）。探测失败一律返回
  /// null，让调用方把「不可用」如实显示出来，而不是给出一个写不进去的路径。
  static Future<String?> publicOutputDir() async {
    if (!await hasAllFilesAccess()) return null;
    try {
      final dir = Directory(publicRoot);
      if (!dir.existsSync()) dir.createSync(recursive: true);
      final probe = File('${dir.path}${Platform.pathSeparator}.safefile_probe');
      probe.writeAsStringSync('ok', flush: true);
      probe.deleteSync();
      return dir.path;
    } catch (_) {
      return null;
    }
  }

  /// 诊断用：说明公开目录当前为什么不可用（授权缺失 / 创建或写入失败）。
  static Future<String> unavailableReason() async {
    if (!await hasAllFilesAccess()) return '尚未授予「所有文件访问权限」';
    try {
      final dir = Directory(publicRoot);
      if (!dir.existsSync()) dir.createSync(recursive: true);
      final probe = File('${dir.path}${Platform.pathSeparator}.safefile_probe');
      probe.writeAsStringSync('ok', flush: true);
      probe.deleteSync();
      return '';
    } on FileSystemException catch (e) {
      return '${e.message}（errno ${e.osError?.errorCode}）';
    } catch (e) {
      return '$e';
    }
  }
}
