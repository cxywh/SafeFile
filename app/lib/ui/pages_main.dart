import 'dart:io';
import 'dart:isolate';

import 'package:flutter/material.dart';

import '../core/app_state.dart';
import 'theme.dart';
import 'widgets.dart';

/// 在独立 isolate 中执行可能阻塞的 FFI 调用，保持界面流畅。
Future<T> runOff<T>(T Function() action) => Isolate.run(action);

class AppNav {
  static Future<void> go(BuildContext context, int index) async {
    // 由 Shell 注入的回调：通过 InheritedWidget 简化，这里使用全局 navigator key 方案
    ShellController.of(context).select(index);
  }
}

class ShellController extends InheritedWidget {
  const ShellController({super.key, required this.select, required this.current, required super.child});

  final void Function(int) select;
  final int current;

  static ShellController of(BuildContext context) {
    final c = context.dependOnInheritedWidgetOfExactType<ShellController>();
    assert(c != null, 'ShellController 缺失');
    return c!;
  }

  @override
  bool updateShouldNotify(ShellController oldWidget) => oldWidget.current != current;
}

// ---------------------------------------------------------------- 首页

class HomePage extends StatelessWidget {
  const HomePage({super.key, required this.state, required this.onNavigate});

  final AppState state;
  final ValueChanged<int> onNavigate;

  @override
  Widget build(BuildContext context) => Tokens.isCompact(context)
      ? _HomeMobile(state: state, onNavigate: onNavigate)
      : _HomeDesktop(state: state, onNavigate: onNavigate);
}

/// 手机端首页：单列、拇指可达，两个主操作保证在首屏内可见。
class _HomeMobile extends StatelessWidget {
  const _HomeMobile({required this.state, required this.onNavigate});

  final AppState state;
  final ValueChanged<int> onNavigate;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final batch = state.batch;
    return ListView(
      padding: Tokens.pageInsets(context),
      children: [
        Row(
          children: [
            ClipRRect(
              borderRadius: BorderRadius.circular(11),
              child: Image.asset(
                'assets/logo.png',
                width: 38,
                height: 38,
                filterQuality: FilterQuality.high,
                semanticLabel: 'SafeFile',
              ),
            ),
            const SizedBox(width: 11),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('SafeFile', style: theme.textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w700)),
                  Text(
                    '本地加密工作台',
                    style: theme.textTheme.labelSmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                  ),
                ],
              ),
            ),
          ],
        ),
        const SizedBox(height: 18),
        if (!state.storageGranted) ...[
          PermissionNotice(
            title: '需要「所有文件访问权限」',
            message: 'Android 11 起，应用不能直接读写存储目录。授予后即可加密整个文件夹、'
                '并把结果保存到手机里可见的 SafeFile 目录。',
            actionLabel: '去授权',
            onAction: () async {
              final ok = await state.ensureStorageAccess();
              if (!context.mounted) return;
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text(ok ? '已获得存储访问权限' : '未获得权限，文件夹加密不可用')),
              );
            },
          ),
          const SizedBox(height: 12),
        ],
        Row(
          children: [
            Expanded(
              child: _MobileAction(
                icon: Icons.lock,
                title: '加密文件',
                subtitle: '保存为加密文件',
                filled: true,
                onTap: () => onNavigate(1),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _MobileAction(
                icon: Icons.lock_open,
                title: '解密文件',
                subtitle: '还原原始文件',
                tonal: true,
                onTap: () => onNavigate(2),
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        _MobileRowAction(
          icon: Icons.visibility_outlined,
          title: '安全预览',
          subtitle: '无需解密出原文件即可查看',
          onTap: () => onNavigate(3),
        ),
        if (state.recent.isEmpty && batch == null) ...[
          const SizedBox(height: 12),
          const SectionCard(
            title: '三步开始',
            child: Column(
              children: [
                _StepRow(index: 1, text: '选择文件，或整个文件夹'),
                _StepRow(index: 2, text: '设置密码，并记住它'),
                _StepRow(index: 3, text: '生成 .safefile，对方用同一密码还原'),
              ],
            ),
          ),
        ],
        const SizedBox(height: 20),
        if (batch != null) ...[
          SectionCard(
            title: batch.decrypt ? '解密任务' : '加密任务',
            subtitle: '${batch.finishedItems}/${batch.totalItems} 个文件 · ${formatSpeed(batch.speedBps)}',
            trailing: TextButton(onPressed: () => onNavigate(4), child: const Text('查看')),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                ClipRRect(
                  borderRadius: BorderRadius.circular(4),
                  child: LinearProgressIndicator(value: batch.progress, minHeight: 6),
                ),
                const SizedBox(height: 12),
                Text(
                  batch.isDone ? '已完成' : (batch.isPaused ? '已暂停' : '正在处理'),
                  style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                ),
                if (batch.note != null) ...[
                  const SizedBox(height: 6),
                  Text(
                    batch.note!,
                    style: theme.textTheme.labelSmall?.copyWith(color: theme.colorScheme.error),
                  ),
                ],
              ],
            ),
          ),
          const SizedBox(height: 12),
        ],
        SectionCard(
          title: '最近处理',
          subtitle: state.recent.isEmpty ? null : '仅记录路径与结果，不含密码',
          trailing: state.recent.isEmpty
              ? null
              : TextButton(onPressed: () => onNavigate(5), child: const Text('全部')),
          child: state.recent.isEmpty
              ? Padding(
                  padding: const EdgeInsets.symmetric(vertical: 6),
                  child: Row(
                    children: [
                      Icon(Icons.history, size: 18, color: theme.colorScheme.onSurfaceVariant),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          '还没有处理记录，完成一次加密或解密后会显示在这里',
                          style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                        ),
                      ),
                    ],
                  ),
                )
              : Column(
                  children: [
                    for (final entry in state.recent.take(4))
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 8),
                        child: Row(
                          children: [
                            Icon(
                              entry.action == 'encrypt' ? Icons.lock_outline : Icons.lock_open_outlined,
                              size: 18,
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 10),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    fileNameOf(entry.path),
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                    style: theme.textTheme.bodyMedium,
                                  ),
                                  Text(
                                    formatTime(entry.timeMs),
                                    style: theme.textTheme.labelSmall?.copyWith(
                                      color: theme.colorScheme.onSurfaceVariant,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                            StatusPill(status: entry.status),
                          ],
                        ),
                      ),
                  ],
                ),
        ),
        const SizedBox(height: 4),
        Text(
          '文件加解密全程在本机完成，不上传文件，无需账号。',
          textAlign: TextAlign.center,
          style: theme.textTheme.labelSmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
        ),
      ],
    );
  }
}

/// 手机首页主操作块（大触控区，高度 ≥ 92dp）。
class _StepRow extends StatelessWidget {
  const _StepRow({required this.index, required this.text});

  final int index;
  final String text;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 22,
            height: 22,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: theme.colorScheme.primary.withValues(alpha: 0.10),
              shape: BoxShape.circle,
            ),
            child: Text(
              '$index',
              style: theme.textTheme.labelSmall?.copyWith(
                color: theme.colorScheme.primary,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              text,
              style: theme.textTheme.bodySmall?.copyWith(height: 1.45),
            ),
          ),
        ],
      ),
    );
  }
}

class _MobileAction extends StatelessWidget {
  const _MobileAction({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
    this.filled = false,
    this.tonal = false,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;
  final bool filled;
  final bool tonal;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final bg = filled
        ? theme.colorScheme.primary
        : (tonal ? theme.colorScheme.primary.withValues(alpha: 0.08) : theme.cardColor);
    final fg = filled
        ? Colors.white
        : (tonal ? theme.colorScheme.primary : theme.colorScheme.onSurface);
    final sub = filled ? Colors.white.withValues(alpha: 0.82) : theme.colorScheme.onSurfaceVariant;
    return Material(
      color: bg,
      borderRadius: BorderRadius.circular(Tokens.radius),
      child: InkWell(
        borderRadius: BorderRadius.circular(Tokens.radius),
        onTap: onTap,
        child: Container(
          height: 104,
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(Tokens.radius),
            border: filled
                ? null
                : Border.all(
                    color: tonal
                        ? theme.colorScheme.primary.withValues(alpha: 0.24)
                        : theme.dividerColor,
                  ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Icon(icon, size: 24, color: fg),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: theme.textTheme.titleMedium?.copyWith(color: fg, fontWeight: FontWeight.w600)),
                  const SizedBox(height: 2),
                  Text(subtitle, style: theme.textTheme.labelSmall?.copyWith(color: sub)),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// 手机首页整行操作（次要入口）。
class _MobileRowAction extends StatelessWidget {
  const _MobileRowAction({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Material(
      color: theme.cardColor,
      borderRadius: BorderRadius.circular(Tokens.radius),
      child: InkWell(
        borderRadius: BorderRadius.circular(Tokens.radius),
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(Tokens.radius),
            border: Border.all(color: theme.dividerColor),
          ),
          child: Row(
            children: [
              Icon(icon, size: 20, color: theme.colorScheme.primary),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(title, style: theme.textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600)),
                    const SizedBox(height: 2),
                    Text(
                      subtitle,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.labelSmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                    ),
                  ],
                ),
              ),
              Icon(Icons.chevron_right, size: 20, color: theme.colorScheme.onSurfaceVariant),
            ],
          ),
        ),
      ),
    );
  }
}

class _HomeDesktop extends StatelessWidget {
  const _HomeDesktop({required this.state, required this.onNavigate});

  final AppState state;
  final ValueChanged<int> onNavigate;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final batch = state.batch;
    final core = state.coreInfo;
    return ListView(
      padding: Tokens.pageInsets(context),
      children: [
        PageHeader(
          title: 'SafeFile',
          subtitle: '本地文件加密、解密与预览 · Windows 与 Android 互通',
          actions: [
            OutlinedButton.icon(
              onPressed: () => onNavigate(5),
              icon: const Icon(Icons.history, size: 18),
              label: const Text('最近处理'),
            ),
          ],
        ),
        const SizedBox(height: Tokens.gapLg),
        LayoutBuilder(
          builder: (context, constraints) {
            final wide = constraints.maxWidth > 860;
            final cards = [
              _QuickAction(
                icon: Icons.lock_outline,
                title: '加密文件',
                description: '把文件或整个文件夹封装为 .safefile',
                onTap: () => onNavigate(1),
              ),
              _QuickAction(
                icon: Icons.lock_open_outlined,
                title: '解密文件',
                description: '输入密码还原原始文件，保留目录结构',
                onTap: () => onNavigate(2),
              ),
              _QuickAction(
                icon: Icons.image_outlined,
                title: '安全预览',
                description: '明文不落盘即可查看加密文件内容。',
                onTap: () => onNavigate(3),
              ),
            ];
            if (!wide) {
              return Column(
                children: [
                  for (final card in cards) ...[card, const SizedBox(height: Tokens.gap)],
                ],
              );
            }
            return Row(
              children: [
                for (var i = 0; i < cards.length; i++) ...[
                  Expanded(child: cards[i]),
                  if (i < cards.length - 1) const SizedBox(width: Tokens.gap),
                ],
              ],
            );
          },
        ),
        const SizedBox(height: Tokens.gapLg),
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              flex: 3,
              child: SectionCard(
                title: '当前任务',
                subtitle: batch == null ? '暂无正在运行的任务' : (batch.isDone ? '上一批任务已完成' : '正在处理'),
                trailing: batch == null
                    ? null
                    : TextButton(onPressed: () => onNavigate(4), child: const Text('任务中心')),
                child: batch == null
                    ? const EmptyHint(title: '还没有任务', description: '从「文件加密」或「文件解密」开始一批评处理任务')
                    : Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          ClipRRect(
                            borderRadius: BorderRadius.circular(4),
                            child: LinearProgressIndicator(value: batch.progress, minHeight: 6),
                          ),
                          const SizedBox(height: 14),
                          Wrap(
                            spacing: 32,
                            runSpacing: 14,
                            children: [
                              StatTile(label: '进度', value: '${batch.finishedItems}/${batch.totalItems}'),
                              StatTile(label: '成功', value: '${batch.successItems}'),
                              StatTile(label: '失败', value: '${batch.failedItems}'),
                              StatTile(label: '速度', value: formatSpeed(batch.speedBps)),
                              StatTile(label: '已处理', value: formatBytes(batch.processedBytes)),
                            ],
                          ),
                        ],
                      ),
              ),
            ),
            const SizedBox(width: Tokens.gap),
            Expanded(
              flex: 2,
              child: SectionCard(
                title: '安全状态',
                subtitle: '核心与格式信息',
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _KeyValue(label: '加密核心', value: 'v${core['core'] ?? '-'}'),
                    _KeyValue(label: '容器格式', value: 'v${core['format'] ?? '-'}'),
                    _KeyValue(label: '当前 KDF', value: state.kdfPreset.shortLabel),
                    _KeyValue(label: '性能模式', value: state.perfMode.label),
                    const SizedBox(height: 10),
                    Text(
                      '加解密全程在本机完成，不上传文件，无需账号，不记录密码。',
                      style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: Tokens.gapLg),
        SectionCard(
          title: '最近处理',
          subtitle: '仅记录文件路径与处理结果，不记录密码。',
          trailing: state.recent.isEmpty
              ? null
              : TextButton(onPressed: state.clearRecent, child: const Text('清空')),
          child: state.recent.isEmpty
              ? const EmptyHint(
                  title: '暂无记录',
                  description: '完成一次加密或解密后，这里会显示最近 20 条处理记录',
                  icon: Icons.history,
                )
              : Column(
                  children: [
                    for (final entry in state.recent.take(8))
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 6),
                        child: Row(
                          children: [
                            Icon(
                              entry.action == 'encrypt' ? Icons.lock_outline : Icons.lock_open_outlined,
                              size: 18,
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 10),
                            Expanded(
                              child: Text(
                                entry.path,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: theme.textTheme.bodySmall,
                              ),
                            ),
                            Text(
                              formatTime(entry.timeMs),
                              style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                            ),
                            const SizedBox(width: 10),
                            StatusPill(status: entry.status),
                          ],
                        ),
                      ),
                  ],
                ),
        ),
      ],
    );
  }
}

class _QuickAction extends StatelessWidget {
  const _QuickAction({
    required this.icon,
    required this.title,
    required this.description,
    required this.onTap,
  });

  final IconData icon;
  final String title;
  final String description;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      child: InkWell(
        borderRadius: BorderRadius.circular(Tokens.radius),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                width: 38,
                height: 38,
                decoration: BoxDecoration(
                  color: theme.colorScheme.primary.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(Tokens.radiusSm),
                ),
                child: Icon(icon, size: 20, color: theme.colorScheme.primary),
              ),
              const SizedBox(height: 14),
              Text(title, style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w600)),
              const SizedBox(height: 4),
              Text(
                description,
                style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _KeyValue extends StatelessWidget {
  const _KeyValue({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: Row(
        children: [
          SizedBox(
            width: 86,
            child: Text(
              label,
              style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
            ),
          ),
          Expanded(child: Text(value, style: theme.textTheme.bodySmall)),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------- 任务中心

/// 把引擎的底层 IO 文案翻译成用户能照做的提示。
/// 例如 `IO 错误：拒绝访问。(os error 5)`（目录只读、权限不足或被安全软件拦截），
/// 原样显示时用户只看到「拒绝访问」，不知道该改哪里。
String _jobErrorText(String message, String? code) {
  final denied = message.contains('os error 5') ||
      message.contains('拒绝访问') ||
      message.contains('Access is denied');
  if (code == 'io' && denied) {
    return '$message —— 输出目录不可写：请点「更改」换一个可写目录，或把源文件移到可写位置后重试';
  }
  return message;
}

class TasksPage extends StatelessWidget {
  const TasksPage({super.key, required this.state});

  final AppState state;

  @override
  Widget build(BuildContext context) {
    final batch = state.batch;
    final theme = Theme.of(context);
    return ListView(
      padding: Tokens.pageInsets(context),
      children: [
        PageHeader(
          title: '任务中心',
          subtitle: '实时显示进度，支持暂停与取消；任务结束后密码自内存释放。',
          actions: [
            if (batch != null) ...[
              OutlinedButton.icon(
                onPressed: batch.isDone ? null : (batch.isPaused ? state.resumeBatch : state.pauseBatch),
                icon: Icon(batch.isPaused ? Icons.play_arrow : Icons.pause, size: 18),
                label: Text(batch.isPaused ? '继续' : '暂停'),
              ),
              const SizedBox(width: 8),
              OutlinedButton.icon(
                onPressed: batch.isDone ? null : state.cancelBatch,
                icon: const Icon(Icons.stop_circle_outlined, size: 18),
                label: const Text('取消'),
              ),
              const SizedBox(width: 8),
              TextButton(onPressed: state.clearBatch, child: const Text('清空')),
            ],
          ],
        ),
        const SizedBox(height: Tokens.gapLg),
        if (batch == null)
          const SectionCard(
            child: EmptyHint(
              title: '暂无任务',
              description: '在加密或解密页面选择文件后开始处理，任务会在这里实时显示',
              icon: Icons.task_outlined,
            ),
          )
        else ...[
          SectionCard(
            title: batch.decrypt ? '解密任务' : '加密任务',
            subtitle: '并发 ${batch.concurrency} · 用时 ${formatDuration(batch.elapsedMs)} · ${formatSpeed(batch.speedBps)}',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                ClipRRect(
                  borderRadius: BorderRadius.circular(4),
                  child: LinearProgressIndicator(value: batch.progress, minHeight: 6),
                ),
                const SizedBox(height: 16),
                Wrap(
                  spacing: 32,
                  runSpacing: 14,
                  children: [
                    StatTile(label: '文件总数', value: '${batch.totalItems}'),
                    StatTile(label: '已完成', value: '${batch.finishedItems}'),
                    StatTile(label: '成功', value: '${batch.successItems}'),
                    StatTile(label: '失败', value: '${batch.failedItems}'),
                    StatTile(label: '已取消', value: '${batch.cancelledItems}'),
                    StatTile(label: '数据量', value: formatBytes(batch.processedBytes)),
                  ],
                ),
              ],
            ),
          ),
          if (batch.note != null) ...[
            const SizedBox(height: Tokens.gap),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: theme.colorScheme.error.withValues(alpha: 0.06),
                borderRadius: BorderRadius.circular(Tokens.radiusSm),
                border: Border.all(color: theme.colorScheme.error.withValues(alpha: 0.32)),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(Icons.error_outline, size: 18, color: theme.colorScheme.error),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(batch.note!, style: theme.textTheme.bodySmall?.copyWith(height: 1.45)),
                  ),
                ],
              ),
            ),
          ],
          const SizedBox(height: Tokens.gap),
          SectionCard(
            title: '文件明细',
            subtitle: '失败原因会显示在对应条目下方',
            padding: const EdgeInsets.fromLTRB(20, 20, 20, 8),
            child: Column(
              children: [
                for (final item in batch.items.take(200))
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Expanded(
                              child: Text(
                                item.name,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: theme.textTheme.bodyMedium,
                              ),
                            ),
                            StatusPill(status: item.status),
                            const SizedBox(width: 10),
                            SizedBox(
                              width: 96,
                              child: Text(
                                '${formatBytes(item.processed)} / ${formatBytes(item.size)}',
                                textAlign: TextAlign.right,
                                style: theme.textTheme.bodySmall?.copyWith(
                                  color: theme.colorScheme.onSurfaceVariant,
                                ),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 6),
                        ClipRRect(
                          borderRadius: BorderRadius.circular(3),
                          child: LinearProgressIndicator(value: item.progress, minHeight: 4),
                        ),
                        if (item.deleted) ...[
                          const SizedBox(height: 6),
                          Row(
                            children: [
                              Icon(
                                Icons.delete_outline,
                                size: 14,
                                color: theme.colorScheme.onSurfaceVariant,
                              ),
                              const SizedBox(width: 4),
                              Text(
                                '原文件已删除',
                                style: theme.textTheme.labelSmall?.copyWith(
                                  color: theme.colorScheme.onSurfaceVariant,
                                ),
                              ),
                            ],
                          ),
                        ],
                        if (item.errorMessage != null) ...[
                          const SizedBox(height: 6),
                          Text(
                            '${_jobErrorText(item.errorMessage!, item.errorCode)}（${item.errorCode}）',
                            style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
                          ),
                        ],
                      ],
                    ),
                  ),
                if (batch.items.length > 200)
                  Padding(
                    padding: const EdgeInsets.all(12),
                    child: Text(
                      '仅显示前 200 条，共 ${batch.items.length} 条',
                      style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                    ),
                  ),
              ],
            ),
          ),
        ],
      ],
    );
  }
}

// ---------------------------------------------------------------- 文件解密（含容器信息）

class ContainerInfoCards extends StatelessWidget {
  const ContainerInfoCards({super.key, required this.info});

  final Map<String, dynamic> info;

  @override
  Widget build(BuildContext context) {
    if (info['ok'] != true) {
      return SectionCard(
        child: Text(
          '无法识别：${info['message'] ?? '不是有效的 .safefile 文件'}',
          style: TextStyle(color: Theme.of(context).colorScheme.error),
        ),
      );
    }
    return SectionCard(
      title: '加密文件信息',
      subtitle: '来自文件头的公开参数，无需密码即可读取',
      child: Wrap(
        spacing: 28,
        runSpacing: 16,
        children: [
          StatTile(label: '加密算法', value: '${info['cipher']}'),
          StatTile(label: '密钥派生', value: '${info['kdf']}'),
          StatTile(label: 'KDF 参数', value: '${info['kdf_description']}'),
          StatTile(label: '分块大小', value: formatBytes((info['chunk_size'] as num?)?.toInt() ?? 0)),
          StatTile(label: '容器大小', value: formatBytes((info['container_size'] as num?)?.toInt() ?? 0)),
          StatTile(label: '格式版本', value: 'v${info['version']}'),
        ],
      ),
    );
  }
}

/// 清理旧版本遗留的预览临时目录（>1 小时）。
///
/// 现在预览走纯内存路径（`sf_preview_mem` / `sf_media_open`），不会再产生这类目录；
/// 这里只负责清掉升级前留下的明文缓存。
Future<void> sweepStalePreviewDirs() async {
  try {
    final tmp = Directory.systemTemp;
    if (!await tmp.exists()) return;
    final cutoff = DateTime.now().subtract(const Duration(hours: 1));
    await for (final entity in tmp.list(followLinks: false)) {
      if (entity is! Directory) continue;
      final name = entity.path.split(RegExp(r'[\\/]')).last;
      if (!name.startsWith('safefile-preview-')) continue;
      try {
        if ((await entity.stat()).modified.isBefore(cutoff)) {
          await entity.delete(recursive: true);
        }
      } catch (_) {}
    }
  } catch (_) {}
}