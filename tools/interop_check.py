#!/usr/bin/env python3
"""跨实现互通验证：Rust 核心 <-> 独立参考实现（PyNaCl + argon2-cffi）。

验证项：
  1. KDF 一致性：Rust 单元测试固化的向量 vs argon2-cffi 计算结果
  2. Rust 加密 -> Python 解密（内容逐字节一致）
  3. Python 加密 -> Rust 解密（内容逐字节一致）
  4. 空文件、Unicode 文件名、跨块大文件
  5. 错误密码在双向实现上都必须失败
输出 JSON 报告，写 vectors/interop-report.json。
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLI = os.path.join(ROOT, "core", "target", "release", "safefile.exe")
REF = os.path.join(HERE, "safefile_reference.py")
PY = sys.executable
VECTORS = os.path.join(ROOT, "vectors")

results = []


def run(cmd, expect_ok=True):
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    ok = (p.returncode == 0) == expect_ok
    return ok, p.stdout.strip(), p.stderr.strip()


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def record(name, ok, detail):
    results.append({"name": name, "pass": bool(ok), "detail": detail})
    print(("PASS  " if ok else "FAIL  ") + name + "  " + detail)


def main():
    if not os.path.exists(CLI):
        print(f"找不到 CLI：{CLI}", file=sys.stderr)
        return 1
    work = tempfile.mkdtemp(prefix="safefile-interop-")
    pw_rust = "interop-密码-7F"

    # ---- 1. KDF 一致性
    from argon2.low_level import Type, hash_secret_raw

    kdf_key = hash_secret_raw(
        secret=b"password", salt=b"\x00" * 32, time_cost=3, memory_cost=65536,
        parallelism=4, hash_len=32, type=Type.ID,
    )
    expected = "592555a93064d6ac4a58d740c0ac9c8eda33b2d4a916b88efd88ea9d6ab65cc2"
    record(
        "kdf_vector_matches_rust",
        kdf_key.hex() == expected,
        f"argon2-cffi={kdf_key.hex()[:16]}… rust={expected[:16]}…",
    )

    cases = [
        ("empty", "空文件.bin", b""),
        ("small", "小文件 ①——テスト.txt", "中文内容 with unicode 🔐".encode("utf-8")),
        ("chunked", "大文件.bin", os.urandom(3 * 1024 * 1024 + 777)),
        ("boundary", "块边界.bin", os.urandom(65536)),
    ]

    for tag, name, data in cases:
        plain = os.path.join(work, f"{tag}-src.bin")
        with open(plain, "wb") as f:
            f.write(data)
        src_sha = hashlib.sha256(data).hexdigest()

        # ---- 2. Rust 加密 -> Python 解密
        ct = os.path.join(work, f"{tag}-rust.safefile")
        ok, out, err = run([CLI, "enc", plain, "-o", ct, "--password-env", "SF_PW", "--overwrite"], expect_ok=True) \
            if False else (None, None, None)
        env = dict(os.environ, SF_PW=pw_rust)
        p = subprocess.run([CLI, "enc", plain, "-o", ct, "--password-env", "SF_PW"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
        if p.returncode != 0:
            record(f"rust_encrypt[{tag}]", False, p.stderr.strip()[:200])
            continue
        dec = os.path.join(work, f"{tag}-py-out.bin")
        p2 = subprocess.run([PY, REF, "decrypt", ct, dec, "--password", pw_rust],
                            capture_output=True, text=True, encoding="utf-8", errors="replace")
        if p2.returncode != 0:
            record(f"rust_to_python[{tag}]", False, p2.stderr.strip()[:200])
        else:
            record(f"rust_to_python[{tag}]", sha(dec) == src_sha, f"sha={src_sha[:16]}…")

        # ---- 3. Python 加密 -> Rust 解密
        ct2 = os.path.join(work, f"{tag}-py.safefile")
        p3 = subprocess.run(
            [PY, REF, "encrypt", plain, ct2, "--password", pw_rust, "--name", name,
             "--m", "8192", "--t", "1", "--p", "1", "--chunk", "65536"],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        if p3.returncode != 0:
            record(f"python_encrypt[{tag}]", False, p3.stderr.strip()[:200])
            continue
        decdir = os.path.join(work, f"{tag}-rust-out")
        os.makedirs(decdir, exist_ok=True)
        p4 = subprocess.run([CLI, "dec", ct2, "-o", decdir, "--password-env", "SF_PW"],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
        restored = os.path.join(decdir, name)
        if p4.returncode != 0 or not os.path.exists(restored):
            record(f"python_to_rust[{tag}]", False, (p4.stderr or p4.stdout).strip()[:200])
        else:
            record(f"python_to_rust[{tag}]", sha(restored) == src_sha, f"文件名还原={os.path.basename(restored)}")

    # ---- 5. 错误密码双向都失败
    plain = os.path.join(work, "pw-src.bin")
    with open(plain, "wb") as f:
        f.write(b"password check")
    ct = os.path.join(work, "pw.safefile")
    env = dict(os.environ, SF_PW="correct")
    subprocess.run([CLI, "enc", plain, "-o", ct, "--password-env", "SF_PW"],
                   capture_output=True, text=True, env=env)
    p = subprocess.run([PY, REF, "decrypt", ct, os.path.join(work, "pw-py.out"), "--password", "wrong"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    record("python_rejects_wrong_password", p.returncode != 0, (p.stderr or p.stdout).strip().splitlines()[-1][:120] if (p.stderr or p.stdout) else "失败(符合预期)")
    env2 = dict(os.environ, SF_PW="wrong")
    p2 = subprocess.run([CLI, "dec", ct, "-o", os.path.join(work, "pw-rust.out"), "--password-env", "SF_PW"],
                        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env2)
    record("rust_rejects_wrong_password", p2.returncode != 0, (p2.stderr or "").strip().splitlines()[-1][:120] if p2.stderr else "失败(符合预期)")

    passed = sum(1 for r in results if r["pass"])
    report = {"total": len(results), "passed": passed, "all_pass": passed == len(results), "checks": results}
    os.makedirs(VECTORS, exist_ok=True)
    with open(os.path.join(VECTORS, "interop-report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n{passed}/{len(results)} 通过，报告：vectors/interop-report.json")
    shutil.rmtree(work, ignore_errors=True)
    return 0 if report["all_pass"] else 2


if __name__ == "__main__":
    sys.exit(main())
