import 'dart:io';

import 'package:path_provider/path_provider.dart';

import 'android_storage.dart';

/// 平台默认输出目录。
///
/// Windows / 桌面：返回空字符串，表示"与源文件同目录"（引擎按容器元数据还原文件名）。
/// Android：只要拿到了「所有文件访问权限」，一律使用公开目录 `/storage/emulated/0/SafeFile`；
/// 尚未授权（或该目录建不出来 / 写不进去）时返回空字符串，由界面显式提示「未授权」。
///
/// 这里**不再回退到应用私有目录**：`getApplicationDocumentsDirectory()` 在 Android 上位于
/// `Android/data/<pkg>/…`，Android 11 起文件管理器默认看不到该目录，用户会以为「产物不存在」；
/// 早期版本正是这样：首次启动显示一个私有路径，授权后才切到公开目录，前后不一致。
Future<String> defaultOutputDir() async {
  if (!Platform.isAndroid) return '';
  return await AndroidStorage.publicOutputDir() ?? '';
}

/// 局域网接收的默认保存目录。
///
/// Android 走 [defaultOutputDir]（公开目录 `/storage/emulated/0/SafeFile`；未授权时为空串，
/// 界面据此提示授权，而不是把文件收进用户看不见的私有目录）。
/// 桌面用系统下载目录，取不到时退到 `~/Downloads`，再退到当前工作目录——
/// 不会把手机路径 `/storage/emulated/0/...` 带到 Windows 上。
Future<String> defaultSaveDir() async {
  if (Platform.isAndroid) return defaultOutputDir();
  try {
    final downloads = await getDownloadsDirectory();
    if (downloads != null && downloads.path.isNotEmpty) {
      final dir = Directory(downloads.path);
      if (dir.existsSync() || _ensureDir(dir)) return dir.path;
    }
  } catch (_) {
    // 某些桌面环境没有 Downloads 概念，继续兜底。
  }
  final home = Platform.environment['USERPROFILE'] ?? Platform.environment['HOME'];
  if (home != null && home.isNotEmpty) {
    final dir = Directory('$home${Platform.pathSeparator}Downloads');
    if (dir.existsSync() || _ensureDir(dir)) return dir.path;
  }
  return Directory.current.path;
}

/// 预检输出目录是否真的可写。
///
/// 引擎报错只有 `IO 错误：拒绝访问。(os error 5)` 这种底层文案，用户看不出该做什么；
/// 这里在启动批量任务前先真实写一个探针文件再删掉，把「不可写」提前变成可操作的中文提示。
/// 成功返回 `null`，失败返回给用户看的说明。Android 走 SAF/权限体系，这里不预检。
Future<String?> checkWritableDir(String dir) async {
  if (Platform.isAndroid) return null;
  final sep = Platform.pathSeparator;
  final path = dir.endsWith(sep) ? dir.substring(0, dir.length - 1) : dir;
  if (path.isEmpty) return '输出目录为空：请点「更改」选择一个目录';
  try {
    final d = Directory(path);
    if (!d.existsSync()) d.createSync(recursive: true);
    final probe = File('$path$sep.safefile-probe-${DateTime.now().microsecondsSinceEpoch}');
    probe.writeAsStringSync('probe', flush: true);
    if (probe.existsSync()) probe.deleteSync();
    return null;
  } on FileSystemException catch (e) {
    final reason = e.osError?.message ?? e.message;
    return '输出目录不可写：$path（$reason）。可能是权限不足、目录只读，或被安全软件拦截；'
        '请点「更改」换一个目录，或把文件复制到可写位置后重试';
  } catch (e) {
    return '输出目录不可写：$path（$e）。请点「更改」换一个目录后重试';
  }
}

/// 尽力创建目录；失败时返回 false，让调用方继续用下一个候选。
bool _ensureDir(Directory dir) {
  try {
    dir.createSync(recursive: true);
    return true;
  } catch (_) {
    return false;
  }
}
