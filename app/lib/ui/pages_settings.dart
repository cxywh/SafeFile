import 'dart:io';

import 'package:flutter/material.dart';

import '../core/android_storage.dart';
import '../core/app_state.dart';
import 'theme.dart';
import 'widgets.dart';

/// 最近文件页。
class RecentPage extends StatelessWidget {
  const RecentPage({super.key, required this.state});

  final AppState state;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ListView(
      padding: Tokens.pageInsets(context),
      children: [
        PageHeader(
          title: '最近文件',
          subtitle: '仅保存路径与结果，不保存文件内容、密码及密钥。',
          actions: [
            if (state.recent.isNotEmpty)
              OutlinedButton.icon(
                onPressed: state.clearRecent,
                icon: const Icon(Icons.delete_outline, size: 18),
                label: const Text('清空记录'),
              ),
          ],
        ),
        const SizedBox(height: Tokens.gapLg),
        SectionCard(
          child: state.recent.isEmpty
              ? const EmptyHint(
                  title: '暂无记录',
                  description: '完成一次加密或解密后，最近 20 条记录会出现在这里',
                  icon: Icons.history,
                )
              : Column(
                  children: [
                    for (final entry in state.recent)
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 8),
                        child: Row(
                          children: [
                            Icon(
                              entry.action == 'encrypt' ? Icons.lock_outline : Icons.lock_open_outlined,
                              size: 18,
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    entry.name,
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                    style: theme.textTheme.bodyMedium,
                                  ),
                                  Text(
                                    entry.path,
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                    style: theme.textTheme.bodySmall?.copyWith(
                                      color: theme.colorScheme.onSurfaceVariant,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                            Text(
                              formatTime(entry.timeMs),
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: theme.colorScheme.onSurfaceVariant,
                              ),
                            ),
                            const SizedBox(width: 12),
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

/// 设置页。
class SettingsPage extends StatelessWidget {
  const SettingsPage({super.key, required this.state});

  final AppState state;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final core = state.coreInfo;
    return ListView(
      padding: Tokens.pageInsets(context),
      children: [
        const PageHeader(title: '设置', subtitle: '加密强度、性能与界面偏好'),
        const SizedBox(height: Tokens.gapLg),
        SectionCard(
          title: '密钥派生强度',
          subtitle: '影响每次加解密的耗时与破解成本；保存在文件头中，解密端自动跟随',
          child: Tokens.isCompact(context)
              ? Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        for (final preset in KdfPreset.values)
                          ChoiceChip(
                            label: Text(preset.shortLabel),
                            selected: state.kdfPreset == preset,
                            onSelected: (_) => state.setKdfPreset(preset),
                          ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    Text(
                      '当前参数：${state.kdfPreset.label}',
                      style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                    ),
                  ],
                )
              : RadioGroup<KdfPreset>(
            groupValue: state.kdfPreset,
            onChanged: (v) => v == null ? null : state.setKdfPreset(v),
            child: Column(
              children: [
                for (final preset in KdfPreset.values)
                  RadioListTile<KdfPreset>(
                    value: preset,
                    title: Text(preset.shortLabel),
                    subtitle: Text(preset == KdfPreset.mobile ? '移动设备推荐默认值' : preset.label),
                    contentPadding: EdgeInsets.zero,
                  ),
              ],
            ),
          ),
        ),
        const SizedBox(height: Tokens.gap),
        SectionCard(
          title: '并发与性能',
          subtitle: '并发过高会与磁盘 I/O 争抢，批量小文件主要在等待密钥派生',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (Tokens.isCompact(context))
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        for (final mode in PerfMode.values)
                          ChoiceChip(
                            label: Text(mode.label),
                            selected: state.perfMode == mode,
                            onSelected: (_) => state.setPerfMode(mode),
                          ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    Text(
                      state.perfMode.description,
                      style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                    ),
                  ],
                )
              else
                RadioGroup<PerfMode>(
                groupValue: state.perfMode,
                onChanged: (v) => v == null ? null : state.setPerfMode(v),
                child: Column(
                  children: [
                    for (final mode in PerfMode.values)
                      RadioListTile<PerfMode>(
                        value: mode,
                        title: Text(mode.label),
                        subtitle: Text(mode.description),
                        contentPadding: EdgeInsets.zero,
                      ),
                  ],
                ),
              ),
              if (state.perfMode == PerfMode.custom)
                Row(
                  children: [
                    Text('并发数 ${state.customConcurrency}', style: theme.textTheme.bodySmall),
                    Expanded(
                      child: Slider(
                        value: state.customConcurrency.toDouble(),
                        min: 1,
                        max: 16,
                        divisions: 15,
                        label: '${state.customConcurrency}',
                        onChanged: (v) => state.setCustomConcurrency(v.round()),
                      ),
                    ),
                  ],
                ),
            ],
          ),
        ),
        const SizedBox(height: Tokens.gap),
        SectionCard(
          title: '存储访问',
          subtitle: Platform.isAndroid
              ? (state.storageGranted
                  ? '已获得「所有文件访问权限」，可直接读写手机存储'
                  : '未授权：无法读写手机存储，加密/解密和接收都会先要求授权')
              : '桌面端直接使用文件系统，无需额外权限',
          trailing: Platform.isAndroid && !state.storageGranted
              ? FilledButton.tonal(
                  onPressed: () async {
                    final ok = await state.ensureStorageAccess();
                    if (!context.mounted) return;
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text(ok ? '已获得存储访问权限' : '未获得权限')),
                    );
                  },
                  child: const Text('去授权'),
                )
              : null,
          child: Text(
            Platform.isAndroid && state.storageGranted
                ? '输出目录：${AndroidStorage.publicRoot}'
                : '未授权：不会退回到用户看不见的应用私有目录，请点「去授权」后使用公开目录。',
            style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
          ),
        ),
        const SizedBox(height: Tokens.gap),
        SectionCard(
          title: '行为偏好',
          child: Column(
            children: [
              SwitchListTile(
                value: state.darkMode,
                onChanged: state.setDarkMode,
                title: const Text('深色模式'),
                subtitle: const Text('跟随界面主题，不影响加密结果'),
                contentPadding: EdgeInsets.zero,
              ),
              SwitchListTile(
                value: state.overwriteOutput,
                onChanged: state.setOverwrite,
                title: const Text('允许覆盖已存在的输出文件'),
                subtitle: const Text('默认关闭；关闭时遇到同名文件会直接失败而不会覆盖'),
                contentPadding: EdgeInsets.zero,
              ),
              SwitchListTile(
                value: state.deleteSource,
                onChanged: state.setDeleteSource,
                title: const Text('成功后删除原文件'),
                subtitle: const Text(
                  '只在输出写完并原子重命名成功后删除；失败、取消、断电一律保留原文件。'
                  '图片与视频会被系统图库收进「最近删除」，由系统到期自动清除',
                ),
                contentPadding: EdgeInsets.zero,
              ),
              SwitchListTile(
                value: state.backgroundRun,
                onChanged: state.setBackgroundRun,
                title: const Text('退到后台时继续处理'),
                subtitle: Text(
                  Platform.isAndroid
                      ? '开启后任务在通知栏常驻，切出应用也不会被系统回收'
                      : '开启后最小化窗口仍继续处理（关闭窗口会终止任务）',
                ),
                contentPadding: EdgeInsets.zero,
              ),
            ],
          ),
        ),
        const SizedBox(height: Tokens.gap),
        SectionCard(
          title: '安全自检',
          subtitle: '在本机跑一次加解密往返、错误密码与明文泄漏检查',
          trailing: FilledButton(
            onPressed: state.runSelftest,
            child: const Text('运行自检'),
          ),
          child: state.selftestResult == null
              ? const EmptyHint(
                  title: '尚未运行',
                  description: '自检过程不访问网络，不读取无关文件，仅使用系统临时目录。',
                  icon: Icons.verified_outlined,
                )
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      state.selftestResult!['all_pass'] == true ? '全部通过' : '存在未通过项',
                      style: theme.textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.w600,
                        color: state.selftestResult!['all_pass'] == true
                            ? const Color(0xFF1B8A5A)
                            : theme.colorScheme.error,
                      ),
                    ),
                    const SizedBox(height: 8),
                    for (final check in (state.selftestResult!['checks'] as List? ?? const []))
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 3),
                        child: Row(
                          children: [
                            Icon(
                              (check as Map)['pass'] == true ? Icons.check_circle_outline : Icons.error_outline,
                              size: 16,
                              color: check['pass'] == true ? const Color(0xFF1B8A5A) : theme.colorScheme.error,
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                '${check['name']} · ${check['detail']}',
                                style: theme.textTheme.bodySmall,
                              ),
                            ),
                          ],
                        ),
                      ),
                    const SizedBox(height: 6),
                    Text(
                      'KDF 耗时 ${state.selftestResult!['kdf_ms']} ms · 核心 v${state.selftestResult!['core_version']} · 格式 v${state.selftestResult!['format_version']}',
                      style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                    ),
                  ],
                ),
        ),
        const SizedBox(height: Tokens.gap),
        SectionCard(
          title: '隐私与安全说明',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _Bullet(text: '文件加解密全程在本机完成，不上传文件，无需账号与登录。'),
              _Bullet(text: '加密算法采用 XChaCha20-Poly1305 流式加密与 Argon2id 密钥派生。'),
              _Bullet(text: '安全预览的解密与解析均在进程内存中完成，不写入磁盘。'),
              _Bullet(text: '局域网传输采用设备身份签名与端到端加密，文件不经第三方服务器中转。'),
              _Bullet(text: '日志与界面不输出密码、密钥及明文内容。'),
              _Bullet(text: '密码遗失后无法恢复，产品不设后门与恢复通道。'),
            ],
          ),
        ),
        const SizedBox(height: Tokens.gap),
        SectionCard(
          title: '关于',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _Bullet(text: 'SafeFile 0.1.0'),
              _Bullet(text: '加密核心 v${core['core']} · 容器格式 v${core['format']}'),
              _Bullet(text: '同一密码与同一容器可在 Windows 与 Android 之间互换。'),
            ],
          ),
        ),
      ],
    );
  }
}

class _Bullet extends StatelessWidget {
  const _Bullet({required this.text});

  final String text;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.only(top: 6, right: 8),
            child: Container(
              width: 4,
              height: 4,
              decoration: BoxDecoration(color: theme.colorScheme.primary, shape: BoxShape.circle),
            ),
          ),
          Expanded(
            child: Text(
              text,
              style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
            ),
          ),
        ],
      ),
    );
  }
}
