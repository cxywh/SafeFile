#!/usr/bin/env python3
"""SAFEFILE v1 参考实现（独立于 Rust 核心）。

用途：验证 Rust 核心的容器格式与密码学选择能在**另一套独立实现**
（libsodium 绑定 PyNaCl + Argon2 参考实现 argon2-cffi）上互通。
不是产品代码，只用于互操作测试。

用法：
    python safefile_reference.py encrypt <输入> <输出.safefile> --password X [--name 名字] [--m 8192 --t 1 --p 1 --chunk 65536]
    python safefile_reference.py decrypt <容器> <输出> --password X
    python safefile_reference.py inspect <容器>
"""

import argparse
import json
import os
import struct
import sys

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_init_push,
    crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_push,
)
from nacl.bindings.crypto_secretstream import (
    crypto_secretstream_xchacha20poly1305_state,
)

MAGIC = b"SAFEFILE"
VERSION = 1
CIPHER = 1
KDF = 1
PUBLIC_HEADER_LEN = 64
SS_HEADER_LEN = 24
PREFIX_LEN = PUBLIC_HEADER_LEN + SS_HEADER_LEN
META_BLOCK_LEN = 4096
TAG_OVERHEAD = 17

TAG_END, TAG_FILENAME, TAG_SIZE, TAG_MTIME, TAG_NANOS, TAG_MIME, TAG_KIND = range(7)


def derive(password: str, salt: bytes, m: int, t: int, p: int) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=32,
        type=Type.ID,
    )


def encode_meta(name: str, size: int, kind: int = 0) -> bytes:
    out = struct.pack("<H", 1)

    def field(tag, value):
        nonlocal out
        out += struct.pack("<BI", tag, len(value)) + value

    field(TAG_FILENAME, name.encode("utf-8"))
    field(TAG_SIZE, struct.pack("<Q", size))
    field(TAG_KIND, bytes([kind]))
    out += bytes([TAG_END])
    return out


def decode_meta(buf: bytes):
    version = struct.unpack_from("<H", buf, 0)[0]
    if version != 1:
        raise SystemExit("元数据版本不支持")
    idx = 2
    meta = {"filename": None, "size": None, "kind": 0}
    while idx < len(buf):
        tag = buf[idx]
        idx += 1
        if tag == TAG_END:
            break
        (length,) = struct.unpack_from("<I", buf, idx)
        idx += 4
        value = buf[idx : idx + length]
        idx += length
        if tag == TAG_FILENAME:
            meta["filename"] = value.decode("utf-8")
        elif tag == TAG_SIZE:
            meta["size"] = struct.unpack("<Q", value)[0]
        elif tag == TAG_KIND:
            meta["kind"] = value[0]
    if meta["filename"] is None or meta["size"] is None:
        raise SystemExit("元数据缺少必需字段")
    return meta


def read_header(path: str):
    with open(path, "rb") as f:
        prefix = f.read(PREFIX_LEN)
    if len(prefix) < PREFIX_LEN:
        raise SystemExit("文件过短")
    if prefix[:8] != MAGIC:
        raise SystemExit("Magic 不匹配")
    (version,) = struct.unpack_from("<H", prefix, 8)
    if version != VERSION:
        raise SystemExit(f"版本不支持：{version}")
    if prefix[10] != CIPHER or prefix[11] != KDF:
        raise SystemExit("算法标识不支持")
    m, t, p = struct.unpack_from("<III", prefix, 12)
    out_len = prefix[24]
    exp = prefix[25]
    (flags,) = struct.unpack_from("<H", prefix, 26)
    salt = prefix[28:60]
    reserved = prefix[60:64]
    if reserved != b"\x00\x00\x00\x00" or flags != 0:
        raise SystemExit("保留字段非零")
    if out_len != 32:
        raise SystemExit("KDF 输出长度不支持")
    return {
        "m": m,
        "t": t,
        "p": p,
        "salt": salt,
        "chunk": 1024 << exp,
        "ss_header": prefix[PUBLIC_HEADER_LEN:PREFIX_LEN],
        "prefix": prefix,
    }


def frame_plan(total: int, chunk: int):
    """按明文大小推导每个消息的明文字节数（与 Rust 侧 FramePlan 等价）。"""
    if total == 0:
        return [(0, True)]
    count = (total + chunk - 1) // chunk
    rem = total % chunk
    plan = []
    for i in range(count):
        if i < count - 1:
            plan.append((chunk, False))
        elif rem == 0:
            plan.append((chunk, True))
        else:
            plan.append((rem, True))
    return plan


def encrypt(inp: str, out: str, password: str, name: str, m: int, t: int, p: int, chunk: int):
    data = open(inp, "rb").read()
    salt = os.urandom(32)
    exp = (chunk.bit_length() - 1) - 10
    header = bytearray(PUBLIC_HEADER_LEN)
    header[0:8] = MAGIC
    struct.pack_into("<H", header, 8, VERSION)
    header[10] = CIPHER
    header[11] = KDF
    struct.pack_into("<III", header, 12, m, t, p)
    header[24] = 32
    header[25] = exp
    struct.pack_into("<H", header, 26, 0)
    header[28:60] = salt
    key = derive(password, salt, m, t, p)

    state = crypto_secretstream_xchacha20poly1305_state()
    ss_header = crypto_secretstream_xchacha20poly1305_init_push(state, key)
    prefix = bytes(header) + ss_header

    with open(out, "wb") as f:
        f.write(prefix)
        meta = encode_meta(name, len(data))
        block = meta + b"\x00" * (META_BLOCK_LEN - len(meta))
        f.write(
            crypto_secretstream_xchacha20poly1305_push(
                state, block, ad=prefix, tag=crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
            )
        )
        offset = 0
        for plain_len, is_final in frame_plan(len(data), chunk):
            piece = data[offset : offset + plain_len]
            offset += plain_len
            tag = (
                crypto_secretstream_xchacha20poly1305_TAG_FINAL
                if is_final
                else crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
            )
            f.write(crypto_secretstream_xchacha20poly1305_push(state, piece, ad=prefix, tag=tag))


def decrypt(path: str, password: str, out: str) -> dict:
    info = read_header(path)
    key = derive(password, info["salt"], info["m"], info["t"], info["p"])
    prefix = info["prefix"]
    with open(path, "rb") as f:
        f.read(PREFIX_LEN)
        state = crypto_secretstream_xchacha20poly1305_state()
        crypto_secretstream_xchacha20poly1305_init_pull(state, info["ss_header"], key)
        meta_ct = f.read(META_BLOCK_LEN + TAG_OVERHEAD)
        if len(meta_ct) != META_BLOCK_LEN + TAG_OVERHEAD:
            raise SystemExit("元数据块被截断")
        meta_plain, _tag = crypto_secretstream_xchacha20poly1305_pull(state, meta_ct, ad=prefix)
        meta = decode_meta(meta_plain)
        chunks = []
        for plain_len, is_final in frame_plan(meta["size"], info["chunk"]):
            want = plain_len + TAG_OVERHEAD
            piece_ct = f.read(want)
            if len(piece_ct) != want:
                raise SystemExit("缺少结束块或块内截断")
            piece, tag = crypto_secretstream_xchacha20poly1305_pull(state, piece_ct, ad=prefix)
            if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) != is_final:
                raise SystemExit("块标记与声明长度不一致")
            chunks.append(piece)
        if f.read(1):
            raise SystemExit("结束块后存在多余数据")
    data = b"".join(chunks)
    if len(data) != meta["size"]:
        raise SystemExit(f"长度不符：{len(data)} != {meta['size']}")
    with open(out, "wb") as g:
        g.write(data)
    return {
        "metadata": meta,
        "plaintext_size": len(data),
        "kdf": {"m": info["m"], "t": info["t"], "p": info["p"]},
    }


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("encrypt")
    e.add_argument("input")
    e.add_argument("output")
    e.add_argument("--password", required=True)
    e.add_argument("--name")
    e.add_argument("--m", type=int, default=8192)
    e.add_argument("--t", type=int, default=1)
    e.add_argument("--p", type=int, default=1)
    e.add_argument("--chunk", type=int, default=65536)
    d = sub.add_parser("decrypt")
    d.add_argument("input")
    d.add_argument("output")
    d.add_argument("--password", required=True)
    i = sub.add_parser("inspect")
    i.add_argument("input")
    args = ap.parse_args()

    if args.cmd == "encrypt":
        name = args.name or os.path.basename(args.input)
        encrypt(args.input, args.output, args.password, name, args.m, args.t, args.p, args.chunk)
        print(json.dumps({"ok": True, "output": args.output}, ensure_ascii=False))
    elif args.cmd == "decrypt":
        print(json.dumps({"ok": True, **decrypt(args.input, args.password, args.output)}, ensure_ascii=False))
    else:
        info = read_header(args.input)
        info.pop("prefix")
        info.pop("ss_header")
        info["salt"] = info["salt"].hex()
        print(json.dumps({"ok": True, **info}, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
