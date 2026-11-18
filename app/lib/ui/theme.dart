import 'package:flutter/material.dart';

/// 设计 Token：统一圆角、间距、字重。界面禁止装饰性渐变与堆砌卡片。
class Tokens {
  static const double radius = 14;
  static const double radiusSm = 10;
  static const double gap = 12;
  static const double gapLg = 20;
  static const double pagePadding = 28;
  static const double sidebarWidth = 236;

  /// 手机端统一内边距：16dp 是触屏上"不贴边、又不浪费横向空间"的平衡点。
  static const double pagePaddingMobile = 16;

  /// 手机端列表底部留白：内容滚到底时不要贴着导航栏。
  static const double bottomSafe = 24;

  /// 窄屏判定阈值（dp）。低于此值走单列 + 底部导航。
  static const double compactWidth = 720;

  static bool isCompact(BuildContext context) => MediaQuery.sizeOf(context).width < compactWidth;

  static EdgeInsets pageInsets(BuildContext context) => isCompact(context)
      ? const EdgeInsets.fromLTRB(pagePaddingMobile, 8, pagePaddingMobile, bottomSafe)
      : const EdgeInsets.all(pagePadding);
}

ThemeData buildTheme(Brightness brightness) {
  const seed = Color(0xFF2F6FED);
  final scheme = ColorScheme.fromSeed(seedColor: seed, brightness: brightness);
  final isDark = brightness == Brightness.dark;
  final base = ThemeData(
    colorScheme: scheme,
    useMaterial3: true,
    brightness: brightness,
    visualDensity: VisualDensity.standard,
  );

  return base.copyWith(
    scaffoldBackgroundColor: isDark ? const Color(0xFF0F1115) : const Color(0xFFF7F8FA),
    dividerTheme: DividerThemeData(
      color: isDark ? const Color(0xFF262A31) : const Color(0xFFE4E7EC),
      thickness: 1,
      space: 1,
    ),
    cardTheme: CardThemeData(
      elevation: 0,
      color: isDark ? const Color(0xFF171A20) : Colors.white,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Tokens.radius),
        side: BorderSide(color: isDark ? const Color(0xFF262A31) : const Color(0xFFE4E7EC)),
      ),
      margin: EdgeInsets.zero,
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: isDark ? const Color(0xFF12151A) : const Color(0xFFF2F4F7),
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(Tokens.radiusSm),
        borderSide: BorderSide(color: isDark ? const Color(0xFF2B3038) : const Color(0xFFDDE1E7)),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(Tokens.radiusSm),
        borderSide: BorderSide(color: isDark ? const Color(0xFF2B3038) : const Color(0xFFDDE1E7)),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(Tokens.radiusSm),
        borderSide: BorderSide(color: scheme.primary, width: 1.6),
      ),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(Tokens.radiusSm)),
        textStyle: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 15),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(Tokens.radiusSm)),
        side: BorderSide(color: isDark ? const Color(0xFF2B3038) : const Color(0xFFDDE1E7)),
        textStyle: const TextStyle(fontWeight: FontWeight.w500, fontSize: 14),
      ),
    ),
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(Tokens.radiusSm)),
        textStyle: const TextStyle(fontWeight: FontWeight.w500),
      ),
    ),
    snackBarTheme: SnackBarThemeData(
      behavior: SnackBarBehavior.floating,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(Tokens.radiusSm)),
    ),
    tooltipTheme: const TooltipThemeData(waitDuration: Duration(milliseconds: 400)),
    navigationBarTheme: NavigationBarThemeData(
      height: 68,
      backgroundColor: isDark ? const Color(0xFF12151A) : Colors.white,
      indicatorColor: scheme.primary.withValues(alpha: 0.14),
      labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
    ),
    textTheme: base.textTheme.apply(fontSizeFactor: 1.0),
  );
}

/// 页面标题区：标题 + 说明 + 右侧操作。
class PageHeader extends StatelessWidget {
  const PageHeader({super.key, required this.title, required this.subtitle, this.actions = const []});

  final String title;
  final String subtitle;
  final List<Widget> actions;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final titleBlock = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: theme.textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w700),
        ),
        const SizedBox(height: 6),
        Text(
          subtitle,
          style: theme.textTheme.bodyMedium?.copyWith(color: theme.colorScheme.onSurfaceVariant),
        ),
      ],
    );

    // 窄屏：把操作按钮挪到标题下方并允许换行，避免右侧按钮把标题挤成一条竖线。
    if (Tokens.isCompact(context)) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          titleBlock,
          if (actions.isNotEmpty) ...[
            const SizedBox(height: Tokens.gap),
            Wrap(spacing: 8, runSpacing: 8, children: actions),
          ],
        ],
      );
    }

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(child: titleBlock),
        if (actions.isNotEmpty) ...[const SizedBox(width: Tokens.gap), ...actions],
      ],
    );
  }
}
