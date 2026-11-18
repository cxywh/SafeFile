#!/usr/bin/env bash
# Android ↔ Windows 互通验证脚本
#
# 做法：不依赖点界面，直接把同一份 Rust 核心编译成 Android 可执行文件（safefile-cli），
# 推到设备的 /data/local/tmp 里跑，这样验证的是"设备上真实的加密核心"，
# 而不是模拟器与 Windows 之间的文件拷贝。
#
# 前置：模拟器已启动（或真机已连接），adb devices 能看到设备。
set -euo pipefail

CORE="${CORE:-$(cd "$(dirname "$0")/../core" && pwd)}"
WORK="${WORK:-${TMPDIR:-/tmp}/sf-interop}"
PW="${PW:-interop-2024-中文}"          # 测试口令，仅本次进程使用，不落盘
ABI="${ABI:-x86_64}"                    # 模拟器用 x86_64，真机通常是 arm64

ADB="${ADB:-adb}"
case "$ABI" in
  arm64-v8a|arm64) ANDROID_CLI="$CORE/target/aarch64-linux-android/release/safefile" ;;
  x86_64)          ANDROID_CLI="$CORE/target/x86_64-linux-android/release/safefile" ;;
  *) echo "unsupported ABI: $ABI"; exit 2 ;;
esac
WIN_CLI="$CORE/target/release/safefile.exe"

mkdir -p "$WORK"
cd "$WORK"

log() { printf '\n=== %s ===\n' "$1"; }
# adb 是原生 Windows 程序，不认 /d/... 这类 MSYS 路径，push 前统一转换。
w() { cygpath -w "$1" 2>/dev/null || printf '%s' "$1"; }

log "0. 设备状态"
"$ADB" devices -l
"$ADB" shell getprop ro.product.cpu.abi

log "1. 推送 Android 版加密核心"
"$ADB" push "$(w "$ANDROID_CLI")" /data/local/tmp/safefile >/dev/null
"$ADB" shell chmod 755 /data/local/tmp/safefile
"$ADB" shell /data/local/tmp/safefile --version || true

log "2. 造数据：2 MB + 中文文件名"
head -c 2097152 /dev/urandom > "互通 测试.bin"
sha256sum "互通 测试.bin" | awk '{print $1}' > win-plain.sha

log "3. Windows 加密 → Android 解密"
SF_PW="$PW" "$WIN_CLI" enc "互通 测试.bin" -o win.safefile --password-env SF_PW >/dev/null
"$ADB" push "$(w win.safefile)" /data/local/tmp/win.safefile >/dev/null
"$ADB" shell "cd /data/local/tmp && rm -rf out1 && mkdir out1 && SF_PW='$PW' ./safefile dec win.safefile -o out1 --password-env SF_PW"
"$ADB" shell "cd /data/local/tmp/out1 && sha256sum *" | tee android-dec.sha
WANT=$(cat win-plain.sha)
GOT=$(awk '{print $1}' android-dec.sha | head -1)
[[ "$WANT" == "$GOT" ]] && echo "PASS: Windows 加密 → Android 解密（SHA-256 一致）" || { echo "FAIL: 哈希不一致"; exit 1; }

log "4. Android 加密 → Windows 解密"
"$ADB" push "$(w "互通 测试.bin")" /data/local/tmp/src.bin >/dev/null
"$ADB" shell "cd /data/local/tmp && SF_PW='$PW' ./safefile enc src.bin -o and.safefile --password-env SF_PW"
"$ADB" pull /data/local/tmp/and.safefile and.safefile >/dev/null
mkdir -p out2
SF_PW="$PW" "$WIN_CLI" dec and.safefile -o out2 --password-env SF_PW >/dev/null
GOT2=$(sha256sum out2/* | awk '{print $1}' | head -1)
[[ "$WANT" == "$GOT2" ]] && echo "PASS: Android 加密 → Windows 解密（SHA-256 一致）" || { echo "FAIL: 哈希不一致"; exit 1; }

log "5. 错误密码互拒"
set +e
"$ADB" shell "cd /data/local/tmp && rm -rf out3 && mkdir out3 && SF_PW='wrong-password' ./safefile dec win.safefile -o out3 --password-env SF_PW" >/dev/null 2>&1
AND_BAD=$?
SF_PW="wrong-password" "$WIN_CLI" dec and.safefile -o out2 --password-env SF_PW >/dev/null 2>&1
WIN_BAD=$?
set -e
echo "android exit=$AND_BAD / windows exit=$WIN_BAD"
[[ $AND_BAD -ne 0 && $WIN_BAD -ne 0 ]] && echo "PASS: 两端都拒绝错误密码" || { echo "FAIL: 有端接受了错误密码"; exit 1; }

log "6. 失败后 Android 输出目录条目数（应为 0）"
"$ADB" shell "ls -A /data/local/tmp/out3 | wc -l"

log "7. info（公开头，无需密码）"
"$ADB" shell "cd /data/local/tmp && ./safefile info win.safefile"
"$WIN_CLI" info and.safefile

log "全部完成"
