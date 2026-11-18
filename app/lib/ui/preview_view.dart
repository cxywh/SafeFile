import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:video_player/video_player.dart';

import '../core/native_core.dart';
import 'widgets.dart';

/// 安全预览（纯内存版）。
///
/// 整个流程都不落盘：
/// - `sf_preview_mem` 在 Rust 里把容器解密到内存，图片重新编码成缩略图，
///   Office / PDF / 文本直接解析成结构化内容；
/// - 图片用 `Image.memory` 显示缩略后的像素；
/// - 视频/音频由 `sf_media_open` 起一个只绑定回环、URL 带 128 位令牌的临时端点，
///   播放器从那里流式读取，关闭预览即销毁。
class SafePreview extends StatefulWidget {
  const SafePreview({super.key, required this.container, required this.password});

  /// 加密容器（`.safefile`）路径。
  final String container;

  /// 容器密码；只在本次预览的生命周期内保留在内存里。
  final String password;

  @override
  State<SafePreview> createState() => _SafePreviewState();
}

class _SafePreviewState extends State<SafePreview> {
  Map<String, dynamic>? _preview;
  String? _error;
  bool _loading = true;
  int _page = 0;

  String _format = 'none';
  String _name = '';
  String? _mediaId;
  String? _mediaUrl;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _closeMedia();
    super.dispose();
  }

  void _closeMedia() {
    final id = _mediaId;
    _mediaId = null;
    _mediaUrl = null;
    if (id != null) NativeCore.instance.mediaClose(id);
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final res = await NativeCore.instance.previewMemOffThread(
        container: widget.container,
        password: widget.password,
      );
      if (!mounted) return;
      if (res['ok'] != true) {
        setState(() {
          _error = '${res['message'] ?? '预览失败'}';
          _loading = false;
        });
        return;
      }
      final preview = Map<String, dynamic>.from(res['preview'] as Map? ?? const {});
      final format = '${preview['format'] ?? 'none'}';
      if (format == 'video' || format == 'audio') {
        final media = await NativeCore.instance.mediaOpenOffThread(
          container: widget.container,
          password: widget.password,
        );
        if (!mounted) {
          if (media['ok'] == true) NativeCore.instance.mediaClose('${media['id']}');
          return;
        }
        if (media['ok'] != true) {
          setState(() {
            _error = '${media['message'] ?? '无法打开媒体'}';
            _loading = false;
          });
          return;
        }
        setState(() {
          _preview = preview;
          _format = format;
          _name = '${preview['name'] ?? ''}';
          _mediaId = '${media['id']}';
          _mediaUrl = '${media['url']}';
          _loading = false;
        });
        return;
      }
      setState(() {
        _preview = preview;
        _format = format;
        _name = '${preview['name'] ?? ''}';
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = '$e';
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Padding(
        padding: EdgeInsets.symmetric(vertical: 48),
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              CircularProgressIndicator(),
              SizedBox(height: 12),
              Text('正在内存里解密与解析…', style: TextStyle(fontSize: 12)),
            ],
          ),
        ),
      );
    }
    if (_error != null) return _errorBox(_error!);
    final preview = _preview;
    if (preview == null) return const SizedBox.shrink();

    if (_format == 'image') return _image(preview['image'] as Map?);
    if (_format == 'video' && _mediaUrl != null) return _VideoView(url: _mediaUrl!);
    if (_format == 'audio' && _mediaUrl != null) {
      return _AudioView(url: _mediaUrl!, title: _name);
    }

    final doc = Map<String, dynamic>.from(preview['doc'] as Map? ?? const {});
    final notes = ((doc['notes'] as List?) ?? const []).map((e) => '$e').toList();
    final truncated = doc['truncated'] == true;

    final children = <Widget>[];
    if (notes.isNotEmpty) children.add(_notes(notes));
    if (truncated) {
      children.add(
        Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: Text(
            '内容较长，仅显示前一部分。',
            style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.outline),
          ),
        ),
      );
    }

    if ((doc['pdf_pages'] as List?)?.isNotEmpty == true) {
      children.add(_pdf(doc['pdf_pages'] as List));
    } else if ((doc['sheets'] as List?)?.isNotEmpty == true) {
      children.add(_sheets(doc['sheets'] as List));
    } else if ((doc['slides'] as List?)?.isNotEmpty == true) {
      children.add(_slides(doc['slides'] as List));
    } else if ((doc['text'] as String?)?.isNotEmpty == true) {
      children.add(_text(doc['text'] as String));
    } else if (notes.isEmpty) {
      children.add(
        SectionCard(
          child: Text(
            '该文件没有可展示的内容（格式：$_format）。',
            style: TextStyle(color: Theme.of(context).colorScheme.outline),
          ),
        ),
      );
    }
    if (children.isEmpty) return const SizedBox.shrink();
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: children);
  }

  Widget _errorBox(String message) => SectionCard(
    child: Row(
      children: [
        Icon(Icons.error_outline, color: Theme.of(context).colorScheme.error),
        const SizedBox(width: 10),
        Expanded(child: SelectableText(message)),
      ],
    ),
  );

  Widget _notes(List<String> notes) => Padding(
    padding: const EdgeInsets.only(bottom: 12),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (final n in notes)
          Padding(
            padding: const EdgeInsets.only(bottom: 4),
            child: Text(n, style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.outline)),
          ),
      ],
    ),
  );

  Widget _image(Map? image) {
    if (image == null) {
      return _errorBox('图片解码失败：没有拿到缩略图。');
    }
    final bytes = base64Decode('${image['data'] ?? ''}');
    final width = image['width'];
    final height = image['height'];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(
          '$width × $height · ${image['mime'] ?? ''} · 像素只在内存里',
          style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.outline),
        ),
        const SizedBox(height: 8),
        ConstrainedBox(
          constraints: const BoxConstraints(maxHeight: 560),
          child: InteractiveViewer(
            maxScale: 6,
            child: Center(
              child: Image.memory(
                bytes,
                gaplessPlayback: true,
                errorBuilder: (_, _, _) => Padding(
                  padding: const EdgeInsets.all(24),
                  child: Text(
                    '该图片格式无法在本机解码，或文件已损坏。',
                    style: TextStyle(color: Theme.of(context).colorScheme.error),
                  ),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _text(String content) => Container(
    constraints: const BoxConstraints(maxHeight: 560),
    child: SingleChildScrollView(
      child: SelectableText(content, style: const TextStyle(fontFamily: 'Consolas', fontSize: 13)),
    ),
  );

  Widget _pdf(List pages) {
    final page = _page.clamp(0, pages.length - 1);
    final text = '${pages[page]}';
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            IconButton(
              onPressed: page > 0 ? () => setState(() => _page = page - 1) : null,
              icon: const Icon(Icons.chevron_left),
              tooltip: '上一页',
            ),
            Text('第 ${page + 1} / ${pages.length} 页（最多显示 30 页）'),
            IconButton(
              onPressed: page + 1 < pages.length ? () => setState(() => _page = page + 1) : null,
              icon: const Icon(Icons.chevron_right),
              tooltip: '下一页',
            ),
          ],
        ),
        Container(
          constraints: const BoxConstraints(maxHeight: 520),
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
            borderRadius: BorderRadius.circular(10),
          ),
          child: text.trim().isEmpty
              ? Text('本页没有可提取的文本（可能是图片或扫描内容）', style: TextStyle(color: Theme.of(context).colorScheme.outline))
              : SingleChildScrollView(
                  child: SelectableText(text, style: const TextStyle(fontSize: 13, height: 1.5)),
                ),
        ),
      ],
    );
  }

  Widget _sheets(List sheets) {
    final list = sheets.whereType<Map>().toList();
    if (list.isEmpty) return const SizedBox.shrink();
    final selected = _page.clamp(0, list.length - 1);
    final sheet = list[selected];
    final rows = ((sheet['rows'] as List?) ?? const []).whereType<List>().toList();
    final maxCols = rows.fold<int>(0, (m, r) => r.length > m ? r.length : m);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (list.length > 1)
          SizedBox(
            height: 36,
            child: ListView(
              scrollDirection: Axis.horizontal,
              children: [
                for (var i = 0; i < list.length; i++)
                  Padding(
                    padding: const EdgeInsets.only(right: 8),
                    child: ChoiceChip(
                      label: Text('${list[i]['name'] ?? 'Sheet ${i + 1}'}'),
                      selected: i == selected,
                      onSelected: (_) => setState(() => _page = i),
                    ),
                  ),
              ],
            ),
          ),
        const SizedBox(height: 8),
        Text(
          '${sheet['name'] ?? ''} · ${rows.length} 行 × $maxCols 列${sheet['truncated'] == true ? '（已截断）' : ''}',
          style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.outline),
        ),
        const SizedBox(height: 8),
        Container(
          constraints: const BoxConstraints(maxHeight: 520),
          decoration: BoxDecoration(
            border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Scrollbar(
            child: SingleChildScrollView(
              child: SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: DataTable(
                  headingRowHeight: 36,
                  dataRowMinHeight: 30,
                  dataRowMaxHeight: 40,
                  columns: [
                    for (var c = 0; c < maxCols; c++) DataColumn(label: Text('${c + 1}', style: const TextStyle(fontSize: 12))),
                  ],
                  rows: [
                    for (final r in rows)
                      DataRow(
                        cells: [
                          for (var c = 0; c < maxCols; c++)
                            DataCell(
                              ConstrainedBox(
                                constraints: const BoxConstraints(maxWidth: 220),
                                child: Text('${c < r.length ? r[c] : ''}', maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(fontSize: 12)),
                              ),
                            ),
                        ],
                      ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _slides(List slides) {
    final list = slides.whereType<Map>().toList();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        for (var i = 0; i < list.length; i++) ...[
          SectionCard(
            title: '第 ${list[i]['index'] ?? i + 1} 页 · ${list[i]['title'] ?? ''}',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                for (final line in ((list[i]['lines'] as List?) ?? const []).skip(1))
                  Padding(
                    padding: const EdgeInsets.only(bottom: 4),
                    child: Text('$line', style: const TextStyle(fontSize: 13, height: 1.45)),
                  ),
              ],
            ),
          ),
          const SizedBox(height: 12),
        ],
      ],
    );
  }
}

/// 视频：从回环令牌端点流式播放，关闭页面即释放播放器与会话。
class _VideoView extends StatefulWidget {
  const _VideoView({required this.url});

  final String url;

  @override
  State<_VideoView> createState() => _VideoViewState();
}

class _VideoViewState extends State<_VideoView> {
  VideoPlayerController? _controller;
  String? _error;

  @override
  void initState() {
    super.initState();
    _open();
  }

  Future<void> _open() async {
    final controller = VideoPlayerController.networkUrl(Uri.parse(widget.url));
    try {
      await controller.initialize();
      if (!mounted) {
        await controller.dispose();
        return;
      }
      setState(() => _controller = controller);
      await controller.play();
    } catch (e) {
      await controller.dispose();
      if (!mounted) return;
      setState(() => _error = '$e');
    }
  }

  @override
  void dispose() {
    _controller?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_error != null) {
      return SectionCard(
        child: Text(
          '该视频无法在本机播放（可能是编码不受支持，或播放器不支持网络数据源）：$_error',
          style: TextStyle(color: Theme.of(context).colorScheme.error),
        ),
      );
    }
    final c = _controller;
    if (c == null) {
      return const Padding(
        padding: EdgeInsets.symmetric(vertical: 48),
        child: Center(child: CircularProgressIndicator()),
      );
    }
    return Column(
      children: [
        ConstrainedBox(
          constraints: const BoxConstraints(maxHeight: 520),
          child: AspectRatio(aspectRatio: c.value.aspectRatio == 0 ? 16 / 9 : c.value.aspectRatio, child: VideoPlayer(c)),
        ),
        VideoProgressIndicator(c, allowScrubbing: true, padding: const EdgeInsets.only(top: 8)),
        Row(
          children: [
            IconButton(
              onPressed: () => setState(() => c.value.isPlaying ? c.pause() : c.play()),
              icon: Icon(c.value.isPlaying ? Icons.pause : Icons.play_arrow),
              tooltip: c.value.isPlaying ? '暂停' : '播放',
            ),
            Text(_clock(c.value.position)),
            const Text(' / '),
            Text(_clock(c.value.duration)),
            const Spacer(),
            Text(
              '${c.value.size.width.toInt()}×${c.value.size.height.toInt()}',
              style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.outline),
            ),
          ],
        ),
      ],
    );
  }

  String _clock(Duration d) {
    final m = d.inMinutes.remainder(60).toString().padLeft(2, '0');
    final s = d.inSeconds.remainder(60).toString().padLeft(2, '0');
    return '$m:$s';
  }
}

/// 音频：只做播放控制，不展示波形（避免为预览引入额外解码库）。
class _AudioView extends StatefulWidget {
  const _AudioView({required this.url, required this.title});

  final String url;
  final String title;

  @override
  State<_AudioView> createState() => _AudioViewState();
}

class _AudioViewState extends State<_AudioView> {
  VideoPlayerController? _controller;
  String? _error;

  @override
  void initState() {
    super.initState();
    _open();
  }

  Future<void> _open() async {
    final controller = VideoPlayerController.networkUrl(Uri.parse(widget.url));
    try {
      await controller.initialize();
      if (!mounted) {
        await controller.dispose();
        return;
      }
      setState(() => _controller = controller);
    } catch (e) {
      await controller.dispose();
      if (!mounted) return;
      setState(() => _error = '$e');
    }
  }

  @override
  void dispose() {
    _controller?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_error != null) {
      return SectionCard(
        child: Text(
          '该音频无法在本机播放（可能是编码不受支持，或播放器不支持网络数据源）：$_error',
          style: TextStyle(color: Theme.of(context).colorScheme.error),
        ),
      );
    }
    final c = _controller;
    if (c == null) {
      return const Padding(
        padding: EdgeInsets.symmetric(vertical: 32),
        child: Center(child: CircularProgressIndicator()),
      );
    }
    return SectionCard(
      child: Row(
        children: [
          IconButton.filled(
            onPressed: () => setState(() => c.value.isPlaying ? c.pause() : c.play()),
            icon: Icon(c.value.isPlaying ? Icons.pause : Icons.play_arrow),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(widget.title, maxLines: 1, overflow: TextOverflow.ellipsis),
                VideoProgressIndicator(c, allowScrubbing: true, padding: const EdgeInsets.symmetric(vertical: 8)),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
