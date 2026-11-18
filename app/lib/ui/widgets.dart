import 'dart:io';

import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'theme.dart';

String formatBytes(int bytes) {
  if (bytes < 1024) return '$bytes B';
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  double value = bytes / 1024;
  var unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return '${value.toStringAsFixed(value >= 100 ? 0 : 1)} ${units[unit]}';
}

String formatSpeed(int bytesPerSecond) => '${formatBytes(bytesPerSecond)}/s';

String formatDuration(int ms) {
  if (ms < 1000) return '${ms}ms';
  final s = ms / 1000;
  if (s < 60) return '${s.toStringAsFixed(1)}s';
  final m = s ~/ 60;
  return '${m}m ${(s % 60).round()}s';
}

String formatTime(int ms) {
  final t = DateTime.fromMillisecondsSinceEpoch(ms);
  String two(int v) => v.toString().padLeft(2, '0');
  return '${t.year}-${two(t.month)}-${two(t.day)} ${two(t.hour)}:${two(t.minute)}';
}

String fileNameOf(String path) => path.split(RegExp(r'[\\/]')).last;

/// 主区 + 侧栏：宽屏并排，窄屏上下堆叠（手机端一律单列）。
class AdaptiveSplit extends StatelessWidget {
  const AdaptiveSplit({
    super.key,
    required this.main,
    required this.side,
    this.sideWidth = 340,
    this.breakpoint = Tokens.compactWidth,
    this.mainFlex = 3,
    this.sideFlex = 2,
    this.gap = Tokens.gap,
  });

  final Widget main;
  final Widget side;
  final double sideWidth;
  final double breakpoint;
  final int mainFlex;
  final int sideFlex;
  final double gap;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < breakpoint) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [main, SizedBox(height: gap + 4), side],
          );
        }
        return Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(flex: mainFlex, child: main),
            SizedBox(width: gap),
            SizedBox(
              width: constraints.maxWidth > 1100 ? sideWidth : (constraints.maxWidth * 0.36).clamp(300.0, sideWidth),
              child: side,
            ),
          ],
        );
      },
    );
  }
}

/// 权限/状态提示卡：用于「需要用户去系统里点一次」的场景。
class PermissionNotice extends StatelessWidget {
  const PermissionNotice({
    super.key,
    required this.title,
    required this.message,
    required this.actionLabel,
    required this.onAction,
    this.icon = Icons.folder_off_outlined,
  });

  final String title;
  final String message;
  final String actionLabel;
  final VoidCallback onAction;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final accent = theme.colorScheme.error;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: accent.withValues(alpha: 0.06),
        borderRadius: BorderRadius.circular(Tokens.radius),
        border: Border.all(color: accent.withValues(alpha: 0.32)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 20, color: accent),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  title,
                  style: theme.textTheme.titleSmall?.copyWith(fontWeight: FontWeight.w600),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            message,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              height: 1.45,
            ),
          ),
          const SizedBox(height: 10),
          Align(
            alignment: Alignment.centerRight,
            child: FilledButton.tonal(onPressed: onAction, child: Text(actionLabel)),
          ),
        ],
      ),
    );
  }
}

/// 通用内容卡片。
class SectionCard extends StatelessWidget {
  const SectionCard({
    super.key,
    required this.child,
    this.title,
    this.subtitle,
    this.trailing,
    this.padding = const EdgeInsets.all(20),
  });

  final Widget child;
  final String? title;
  final String? subtitle;
  final Widget? trailing;
  final EdgeInsets padding;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      child: Padding(
        padding: padding,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (title != null)
              Row(
                children: [
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(title!, style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w600)),
                        if (subtitle != null) ...[
                          const SizedBox(height: 4),
                          Text(
                            subtitle!,
                            style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                          ),
                        ],
                      ],
                    ),
                  ),
                  if (trailing != null) trailing!,
                ],
              ),
            if (title != null) const SizedBox(height: 16),
            child,
          ],
        ),
      ),
    );
  }
}

/// 指标小块：标签在上，值在下。
class StatTile extends StatelessWidget {
  const StatTile({super.key, required this.label, required this.value, this.hint});

  final String label;
  final String value;
  final String? hint;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: theme.textTheme.labelMedium?.copyWith(color: theme.colorScheme.onSurfaceVariant)),
        const SizedBox(height: 4),
        Text(value, style: theme.textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w600)),
        if (hint != null) ...[
          const SizedBox(height: 2),
          Text(hint!, style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant)),
        ],
      ],
    );
  }
}

/// 状态标签：用文字 + 颜色表达，不使用 emoji。
class StatusPill extends StatelessWidget {
  const StatusPill({super.key, required this.status});

  final String status;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final (label, color) = switch (status) {
      'success' => ('已完成', const Color(0xFF1B8A5A)),
      'running' => ('处理中', scheme.primary),
      'failed' => ('失败', scheme.error),
      'cancelled' => ('已取消', scheme.onSurfaceVariant),
      _ => ('等待', scheme.onSurfaceVariant),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(label, style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w600)),
    );
  }
}

/// 密码输入：显示/隐藏、粘贴、强度条、二次确认。
class PasswordFields extends StatefulWidget {
  const PasswordFields({
    super.key,
    required this.controller,
    this.confirmController,
    required this.onStrength,
    this.showStrength = true,
    this.label = '密码',
  });

  final TextEditingController controller;
  final TextEditingController? confirmController;
  final int Function(String) onStrength;
  final bool showStrength;
  final String label;

  @override
  State<PasswordFields> createState() => _PasswordFieldsState();
}

class _PasswordFieldsState extends State<PasswordFields> {
  bool _hidden = true;

  static const _levelLabels = ['很弱', '弱', '一般', '较强', '强'];
  static const _levelColors = [Color(0xFFD1345B), Color(0xFFD97C2B), Color(0xFFC9A227), Color(0xFF2F9E6E), Color(0xFF1B8A5A)];

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final strength = widget.onStrength(widget.controller.text);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        TextField(
          controller: widget.controller,
          obscureText: _hidden,
          autocorrect: false,
          enableSuggestions: false,
          onChanged: (_) => setState(() {}),
          decoration: InputDecoration(
            labelText: widget.label,
            hintText: '至少 8 个字符，建议混合大小写与符号',
            prefixIcon: const Icon(Icons.key_outlined, size: 20),
            suffixIcon: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                IconButton(
                  tooltip: _hidden ? '显示密码' : '隐藏密码',
                  icon: Icon(_hidden ? Icons.visibility_outlined : Icons.visibility_off_outlined, size: 20),
                  onPressed: () => setState(() => _hidden = !_hidden),
                ),
                IconButton(
                  tooltip: '粘贴',
                  icon: const Icon(Icons.content_paste_outlined, size: 20),
                  onPressed: () async {
                    final data = await Clipboard.getData(Clipboard.kTextPlain);
                    if (data?.text != null) {
                      widget.controller.text = data!.text!;
                      setState(() {});
                    }
                  },
                ),
              ],
            ),
          ),
        ),
        if (widget.showStrength) ...[
          const SizedBox(height: 10),
          Row(
            children: [
              for (var i = 0; i < 5; i++) ...[
                Expanded(
                  child: Container(
                    height: 4,
                    decoration: BoxDecoration(
                      color: i < strength ? _levelColors[strength.clamp(0, 4)] : theme.dividerColor,
                      borderRadius: BorderRadius.circular(2),
                    ),
                  ),
                ),
                if (i < 4) const SizedBox(width: 4),
              ],
              const SizedBox(width: 10),
              Text(
                strength == 0 ? '未输入' : _levelLabels[strength.clamp(0, 4)],
                style: theme.textTheme.bodySmall?.copyWith(
                  color: strength == 0 ? theme.colorScheme.onSurfaceVariant : _levelColors[strength.clamp(0, 4)],
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ],
        if (widget.confirmController != null) ...[
          const SizedBox(height: Tokens.gap),
          TextField(
            controller: widget.confirmController,
            obscureText: _hidden,
            autocorrect: false,
            enableSuggestions: false,
            decoration: const InputDecoration(
              labelText: '确认密码',
              prefixIcon: Icon(Icons.lock_outline, size: 20),
            ),
          ),
        ],
      ],
    );
  }
}

/// 已选文件条目。
class PickedFileTile extends StatelessWidget {
  const PickedFileTile({
    super.key,
    required this.name,
    required this.sizeLabel,
    this.subtitle,
    this.onRemove,
  });

  final String name;
  final String sizeLabel;
  final String? subtitle;
  final VoidCallback? onRemove;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Row(
        children: [
          Icon(Icons.insert_drive_file_outlined, size: 20, color: theme.colorScheme.onSurfaceVariant),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(name, maxLines: 1, overflow: TextOverflow.ellipsis, style: theme.textTheme.bodyMedium),
                Text(
                  subtitle ?? sizeLabel,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                ),
              ],
            ),
          ),
          Text(sizeLabel, style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant)),
          if (onRemove != null)
            IconButton(
              tooltip: '移除',
              icon: const Icon(Icons.close, size: 18),
              onPressed: onRemove,
            ),
        ],
      ),
    );
  }
}

/// 空状态提示。
class EmptyHint extends StatelessWidget {
  const EmptyHint({super.key, required this.title, required this.description, this.icon = Icons.inbox_outlined});

  final String title;
  final String description;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 28),
      child: Column(
        children: [
          Icon(icon, size: 30, color: theme.colorScheme.onSurfaceVariant),
          const SizedBox(height: 10),
          Text(title, style: theme.textTheme.titleSmall?.copyWith(fontWeight: FontWeight.w600)),
          const SizedBox(height: 4),
          Text(
            description,
            textAlign: TextAlign.center,
            style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
          ),
        ],
      ),
    );
  }
}

/// 文件选择服务（桌面用 file_selector，保证 Windows 原生对话框）。
class FilePick {
  static Future<List<String>> pickFiles({bool safefileOnly = false}) async {
    if (Platform.isWindows || Platform.isLinux || Platform.isMacOS) {
      final group = safefileOnly
          ? const XTypeGroup(label: 'SafeFile 加密文件', extensions: ['safefile'])
          : const XTypeGroup(label: '所有文件');
      final files = await openFiles(acceptedTypeGroups: [group]);
      return files.map((f) => f.path).toList();
    }
    return const [];
  }
}
