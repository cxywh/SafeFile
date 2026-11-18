import 'package:flutter/material.dart';

import '../core/app_state.dart';
import 'pages_crypto.dart';
import 'pages_main.dart';
import 'pages_settings.dart';
import 'pages_share.dart';
import 'theme.dart';

/// 应用主框架：桌面用左侧导航，窄屏用底部导航。
class Shell extends StatefulWidget {
  const Shell({super.key, required this.state});

  final AppState state;

  @override
  State<Shell> createState() => _ShellState();
}

class _ShellState extends State<Shell> {
  int _index = 0;

  static const _items = [
    (icon: Icons.home_outlined, selected: Icons.home, label: '首页'),
    (icon: Icons.lock_outline, selected: Icons.lock, label: '文件加密'),
    (icon: Icons.lock_open_outlined, selected: Icons.lock_open, label: '文件解密'),
    (icon: Icons.visibility_outlined, selected: Icons.visibility, label: '文件预览'),
    (icon: Icons.task_outlined, selected: Icons.task, label: '任务中心'),
    (icon: Icons.history_outlined, selected: Icons.history, label: '最近文件'),
    (icon: Icons.wifi_tethering_outlined, selected: Icons.wifi_tethering, label: '局域网传输'),
    (icon: Icons.settings_outlined, selected: Icons.settings, label: '设置'),
  ];

  /// 手机底部导航：5 个高频入口。Material 3 的 NavigationBar 超过 5 项，
  /// 在 360~430dp 手机上文字会被压缩或省略；「文件预览」「最近文件」改为从首页进入。
  static const _mobileTabs = [
    (page: 0, icon: Icons.home_outlined, selected: Icons.home, label: '首页'),
    (page: 1, icon: Icons.lock_outline, selected: Icons.lock, label: '加密'),
    (page: 2, icon: Icons.lock_open_outlined, selected: Icons.lock_open, label: '解密'),
    (page: 4, icon: Icons.task_outlined, selected: Icons.task, label: '任务'),
    (page: 6, icon: Icons.wifi_tethering_outlined, selected: Icons.wifi_tethering, label: '传输'),
    (page: 7, icon: Icons.settings_outlined, selected: Icons.settings, label: '设置'),
  ];

  void _select(int index) => setState(() => _index = index);

  /// 页面用「构造函数」而不是「常驻实例」缓存。
  /// `IndexedStack` 会保留子树的 State（输入框内容、已选文件、校验结果不丢），
  /// 但常驻实例会被 Flutter 判定为「同一个 widget」而跳过重建——
  /// 结果就是任务跑完了按钮仍停在「任务进行中」。每次重建生成新 widget 才能拿到最新状态。
  late final List<Widget Function()> _pageBuilders = <Widget Function()>[
    () => HomePage(state: widget.state, onNavigate: _select),
    () => EncryptPage(state: widget.state, onNavigate: _select),
    () => DecryptPage(state: widget.state, onNavigate: _select),
    () => PreviewPage(state: widget.state, onNavigate: _select),
    () => TasksPage(state: widget.state),
    () => RecentPage(state: widget.state),
    () => SharePage(state: widget.state),
    () => SettingsPage(state: widget.state),
  ];

  @override
  Widget build(BuildContext context) {
    final wide = MediaQuery.sizeOf(context).width >= Tokens.compactWidth;
    // 监听只下移到内容区：轮询驱动的重建不再牵动 MaterialApp/Navigator。
    final body = ShellController(
      select: _select,
      current: _index,
      child: AnimatedBuilder(
        animation: widget.state,
        builder: (context, _) => IndexedStack(
          index: _index,
          children: [for (final build in _pageBuilders) build()],
        ),
      ),
    );

    // 「文件预览」「最近文件」只从首页进入，此时底部导航让「首页」保持选中。
    final tabIndex = _mobileTabs.indexWhere((t) => t.page == _index);
    final selectedTab = tabIndex < 0 ? 0 : tabIndex;

    return Scaffold(
      body: SafeArea(
        bottom: false,
        child: wide
            ? Row(
                children: [
                  _Sidebar(index: _index, onSelect: _select, items: _items),
                  const VerticalDivider(width: 1),
                  Expanded(child: body),
                ],
              )
            : body,
      ),
      bottomNavigationBar: wide
          ? null
          : NavigationBar(
              height: 68,
              selectedIndex: selectedTab,
              labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
              onDestinationSelected: (i) => _select(_mobileTabs[i].page),
              destinations: [
                for (final tab in _mobileTabs)
                  NavigationDestination(
                    icon: Icon(tab.icon, size: 24),
                    selectedIcon: Icon(tab.selected, size: 24),
                    label: tab.label,
                  ),
              ],
            ),
    );
  }
}

class _Sidebar extends StatelessWidget {
  const _Sidebar({required this.index, required this.onSelect, required this.items});

  final int index;
  final ValueChanged<int> onSelect;
  final List<({IconData icon, IconData selected, String label})> items;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    return Container(
      width: Tokens.sidebarWidth,
      color: isDark ? const Color(0xFF12151A) : Colors.white,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 24, 20, 18),
            child: Row(
              children: [
                ClipRRect(
                  borderRadius: BorderRadius.circular(9),
                  child: Image.asset(
                    'assets/logo.png',
                    width: 32,
                    height: 32,
                    filterQuality: FilterQuality.high,
                    semanticLabel: 'SafeFile',
                  ),
                ),
                const SizedBox(width: 10),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('SafeFile', style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w700)),
                    Text(
                      '本地加密工作台',
                      style: theme.textTheme.labelSmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                    ),
                  ],
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          const SizedBox(height: 10),
          Expanded(
            child: ListView(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              children: [
                for (var i = 0; i < items.length; i++)
                  _SidebarItem(
                    icon: items[i].icon,
                    selectedIcon: items[i].selected,
                    label: items[i].label,
                    selected: i == index,
                    onTap: () => onSelect(i),
                  ),
              ],
            ),
          ),
          const Divider(height: 1),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Text(
              '离线运行 · 数据不出本机',
              style: theme.textTheme.labelSmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
            ),
          ),
        ],
      ),
    );
  }
}

class _SidebarItem extends StatelessWidget {
  const _SidebarItem({
    required this.icon,
    required this.selectedIcon,
    required this.label,
    required this.selected,
    required this.onTap,
  });

  final IconData icon;
  final IconData selectedIcon;
  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Material(
        color: selected ? theme.colorScheme.primary.withValues(alpha: 0.10) : Colors.transparent,
        borderRadius: BorderRadius.circular(Tokens.radiusSm),
        child: InkWell(
          borderRadius: BorderRadius.circular(Tokens.radiusSm),
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 11),
            child: Row(
              children: [
                Icon(
                  selected ? selectedIcon : icon,
                  size: 19,
                  color: selected ? theme.colorScheme.primary : theme.colorScheme.onSurfaceVariant,
                ),
                const SizedBox(width: 11),
                Text(
                  label,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    fontWeight: selected ? FontWeight.w600 : FontWeight.w500,
                    color: selected ? theme.colorScheme.primary : theme.colorScheme.onSurface,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
