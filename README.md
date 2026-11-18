# SafeFile

SafeFile 是本地文件加密与局域网传输工具，提供 Windows 桌面端与 Android 客户端。文件的加密、解密与预览均在设备本地完成。

## 功能

- **加密容器**：`.safefile` 容器采用 XChaCha20-Poly1305 流式加密，Argon2id 派生密钥，每个文件使用独立随机盐。
- **批量处理**：支持单文件、多文件与目录批量加密、解密，保留目录结构，逐文件 BLAKE3 校验。
- **局域网传输**：固定端口 UDP 广播发现（47777）与 TCP 传输（47778），无需配对码；设备以持久随机名称显示。
- **设备身份**：Ed25519 持久身份、首次使用信任（TOFU）、6 位安全码人工核对。
- **安全预览**：容器在进程内存中解密与解析，支持图片、音视频、PDF、Office 与文本格式，不写入临时明文文件。
- **一致体验**：同一密码与同一容器可在 Windows 与 Android 之间互换。

## 目录结构

```
core/        Rust workspace
  crates/safefile-core    加密、容器格式、传输、预览、设备身份
  crates/safefile-cli     命令行工具
  crates/safefile-ffi     C ABI，供 Flutter 调用
app/         Flutter 客户端（Android、Windows）
tools/       PyNaCl 参考实现与互通校验脚本
vectors/     互通测试向量与报告
scripts/     Android 互通验证脚本
assets/      品牌图源文件
```

## 构建

前置环境：Rust stable 1.85 及以上、Flutter 3.27 及以上、Visual Studio C++ 工具链（Windows）、Android SDK 与 NDK（Android）。

桌面端：

```bash
cd app
flutter pub get
flutter build windows --release
```

Android：

```bash
cargo ndk -t arm64-v8a -t armeabi-v7a \
  -o app/android/app/src/main/jniLibs \
  build --release -p safefile-ffi
cd app
flutter build apk --release
```

命令行工具：

```bash
cargo build --release -p safefile-cli
```

测试：

```bash
cargo test --release -p safefile-core
cd app && flutter test
```

## 运行期配置

| 环境变量 | 用途 |
| --- | --- |
| `SAFEFILE_CONFIG_DIR` | 配置目录（设备身份、信任库、设备名称） |
| `SAFEFILE_DISCOVERY_PORT` | 发现端口，两端需一致 |
| `SAFEFILE_TEST_DIR` | 自动化测试的临时目录 |

默认端口：UDP 47777（发现）、TCP 47778（传输）。

## 协议与格式

- 容器：头部包含公开参数与 Argon2id 盐，随后的数据块以 XChaCha20-Poly1305 认证加密，文件级摘要为 BLAKE3。
- 传输握手：`SFTR2` 开头，双方交换 X25519 临时公钥与 Ed25519 静态身份签名，转录经 BLAKE3 派生出双向独立的会话密钥与 6 位安全码。
- 数据帧：`[kind:1][len:4][ciphertext]`，控制帧为 JSON，数据帧为明文块。
- 接收端仅使用相对文件名落盘，路径片段经收敛处理；文件先写入 `.part`，校验长度与摘要后原子改名。

## 安全属性

- 加密与解密在本机完成，文件不经过网络服务。
- 认证加密覆盖每个数据块；会话密钥由临时密钥协商得出，具备前向保密。
- 设备身份由签名公告保护，公钥变更时连接按安全策略终止。
- 安全预览的解密与解析在进程内存中完成，不写入磁盘；音视频经绑定 `127.0.0.1` 的一次性令牌端点播放。
- 日志与界面不输出密码、密钥及明文内容；密码遗失后不可恢复。

## 已知限制

- 设备发现依赖广播可达性；启用客户端隔离的网络需使用手动地址 `ip:47778`。
- 首次连接未核对 6 位安全码时，存在局域网内主动中间人攻击的理论风险。
- 音视频播放能力取决于系统解码器；不支持的编码会给出提示。
- 预览内存上限：图片、文档与 PDF 为 256 MiB，音视频为 512 MiB。

## 下载

Release 页面提供 Android 安装包与 Windows 免安装压缩包。版本与校验值见 `RELEASES-NOTES.md`。

## 版本

0.1.0
