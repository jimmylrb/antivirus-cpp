#!/usr/bin/env python3
# update_database.py — 下载并解析 ClamAV 官方病毒库（CVD 格式）
# 用法: python update_database.py [--daily] [--main] [--dir database]
#
# CVD 结构（新版）:
#   1. 文本头部 "ClamAV-VDB:..." 以 \n 结束
#   2. 剩余部分是 zlib 压缩的 tar 归档
#   3. tar 内含 daily.hdb / daily.ndb / daily.ldb / daily.mdb 等文本签名

import os
import sys
import zlib
import gzip
import tarfile
import io
import urllib.request
import tempfile
import time

MIRRORS = [
    "https://database.clamav.net/",
    "https://db.local.clamav.net/",
]
UA = "clamav/1.4.0 (BlockAV learning project)"


def download(url, dest, timeout=300):
    """下载文件（带进度）"""
    print(f"[下载] {url}")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        done = 0
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if total:
                    pct = done * 100 // total
                    sys.stdout.write(f"\r   {done//1048576}MB/{total//1048576}MB ({pct}%)")
                    sys.stdout.flush()
        print()
    return os.path.getsize(dest)


def parse_cvd(cvd_path):
    """解析 CVD 文件，返回解压出的文件名列表"""
    with open(cvd_path, "rb") as f:
        data = f.read()

    # 1) 头部：文本行 + 空格填充到 512 字节对齐，之后是 gzip 压缩数据
    idx = data.find(b"\x1f\x8b")
    if idx < 0:
        raise ValueError("找不到 gzip 数据")
    header = data[:idx].decode("ascii", errors="replace").strip()
    print(f"[CVD] 头部: {header[:120]}...")
    print(f"[CVD] 数据偏移: {idx} (512 对齐: {idx % 512 == 0})")

    # 2) gzip 解压
    compressed = data[idx:]
    print(f"[CVD] 压缩数据 {len(compressed)//1048576}MB，解压中...")
    t0 = time.time()
    decompressed = gzip.decompress(compressed)
    print(f"[CVD] 解压完成 {len(decompressed)//1048576}MB，用时 {time.time()-t0:.1f}s")

    # 3) tarfile 解析
    tar = tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:")
    extracted = []
    for member in tar.getmembers():
        if not member.isfile():
            continue
        name = member.name
        if name.endswith((".hdb", ".ndb", ".ldb", ".mdb", ".fp", ".ign2", ".cdb", ".wdb", ".pdb")):
            content = tar.extractfile(member).read()
            extracted.append((name, content))
    tar.close()
    return extracted


def split_lines(content):
    """按行分割（处理 \r\n）"""
    return content.replace(b"\r\n", b"\n").split(b"\n")


def main():
    db_dir = "database"
    if "--dir" in sys.argv:
        db_dir = sys.argv[sys.argv.index("--dir") + 1]
    os.makedirs(db_dir, exist_ok=True)

    which = []
    if "--main" in sys.argv:
        which.append("main")
    if "--daily" in sys.argv:
        which.append("daily")
    if not which:
        which = ["daily"]  # 默认只下载每日更新（较小）

    for name in which:
        cvd = os.path.join(tempfile.gettempdir(), f"{name}.cvd")
        url = None
        for mirror in MIRRORS:
            try:
                url = mirror + name + ".cvd"
                download(url, cvd)
                break
            except Exception as e:
                print(f"[警告] {url} 失败: {e}")
                continue
        if not os.path.exists(cvd):
            print(f"[错误] 无法下载 {name}.cvd")
            continue

        try:
            files = parse_cvd(cvd)
        except Exception as e:
            print(f"[错误] 解析失败: {e}")
            continue

        # 写入 database/ 目录（按类型合并），带失败保护
        merged = {}
        for fname, content in files:
            key = os.path.splitext(os.path.basename(fname))[1]  # .hdb/.ndb/...
            merged.setdefault(key, []).append((fname, content))

        total_sigs = 0
        for ext, items in merged.items():
            out_path = os.path.join(db_dir, f"clamav{ext}")
            # 统计新库条数
            count = 0
            for fname, content in items:
                for line in split_lines(content):
                    line = line.strip()
                    if not line or line.startswith(b"#") or line.startswith(b"//"):
                        continue
                    count += 1
            # 失败保护：条数异常少（下载不完整/解析失败）时不覆盖已有完整库
            if count < 1000 and os.path.exists(out_path):
                print(f"[警告] {name}.cvd 仅解析出 {count} 条（疑似下载不完整），跳过覆盖 {out_path}")
                continue
            with open(out_path, "wb") as out:
                for fname, content in items:
                    for line in split_lines(content):
                        line = line.strip()
                        if not line or line.startswith(b"#") or line.startswith(b"//"):
                            continue
                        out.write(line + b"\n")
                        total_sigs += 1
            print(f"[生成] {out_path} ({os.path.getsize(out_path)//1024}KB)")
        print(f"[完成] {name}.cvd -> {total_sigs} 条签名写入 {db_dir}/")

    # 清理下载的 cvd
    for name in which:
        cvd = os.path.join(tempfile.gettempdir(), f"{name}.cvd")
        if os.path.exists(cvd):
            os.remove(cvd)
    print("[完成] 病毒库更新结束")


if __name__ == "__main__":
    main()
