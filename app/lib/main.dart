import 'package:flutter/material.dart';

import 'core/app_state.dart';
import 'core/share_core.dart';
import 'ui/shell.dart';
import 'ui/theme.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const SafeFileApp());
}

class SafeFileApp extends StatefulWidget {
  const SafeFileApp({super.key});

  @override
  State<SafeFileApp> createState() => _SafeFileAppState();
}

class _SafeFileAppState extends State<SafeFileApp> with WidgetsBindingObserver {
  final AppState _state = AppState();
  bool _ready = false;
  bool _dark = false;

  @override
  void initState() {
    super.initState();
    // 用户可能去系统设置页授权后返回，回到前台时要重读一次存储权限。
    WidgetsBinding.instance.addObserver(this);
    // 只在「主题是否变化」时重建 MaterialApp。
    // 轮询期间 AppState 每 250ms 通知一次，若在此处整棵重建 MaterialApp，
    // 会把导航器和所有页面反复重建，既浪费又容易让状态看起来错乱。
    _state.addListener(_onThemeMayChange);
    // 局域网节点独立启动：读取偏好（或等待系统权限）不该拖住设备发现，
    // 这样 App 一打开、甚至还停在启动画面时，同网段的设备就能看到本机。
    _bootLan();
    _state.load().then((_) async {
      if (mounted) setState(() => _ready = true);
    });
  }

  /// 启动局域网节点（幂等）。没有动态库时静默跳过，不影响加密功能。
  ///
  /// 配置目录由 [initLanAuto] 按候选链挑选（环境变量 → 应用支持目录 →
  /// 可执行文件旁 → 系统临时目录），失败原因记在 [lanLastError]。
  Future<void> _bootLan() async {
    final status = await initLanAuto();
    if (status != null) {
      debugPrint('[lan] boot name=${status.name} port=${status.port} '
          'discovery=${status.discoveryOk}');
    } else {
      debugPrint('[lan] boot failed: $lanLastError');
    }
  }

  void _onThemeMayChange() {
    if (_state.darkMode != _dark && mounted) {
      setState(() => _dark = _state.darkMode);
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _state.refreshStorageAccess();
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _state.removeListener(_onThemeMayChange);
    _state.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SafeFile',
      debugShowCheckedModeBanner: false,
      theme: buildTheme(Brightness.light),
      darkTheme: buildTheme(Brightness.dark),
      themeMode: _dark ? ThemeMode.dark : ThemeMode.light,
      home: _ready ? Shell(state: _state) : const Scaffold(body: Center(child: CircularProgressIndicator())),
    );
  }
}
