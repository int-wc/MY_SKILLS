#!/usr/bin/env python3
"""
find_js_dumps.py — 查找已下载JS缓存目录和还原源码目录

用法:
  python3 find_js_dumps.py <base_dir> [--target <target_url>]
  python3 find_js_dumps.py /home/my/butiansrc/Exclusive_SRC/某公司/js_dumps

输出: 每个目标对应的 js_dump_dir 和 reconstructed_dir
"""
import sys
import os
import json
import hashlib

def find_dumps(base_dir, target_url=None):
    """查找JS dump目录"""
    if not os.path.isdir(base_dir):
        return {"status": "error", "error": f"目录不存在: {base_dir}", "dumps": []}

    dumps = []
    target_hash = None
    if target_url:
        target_hash = hashlib.md5(target_url.encode()).hexdigest()[:12]

    # 遍历 js_dumps 下的子目录
    for item in os.listdir(base_dir):
        item_path = os.path.join(base_dir, item)
        if os.path.isdir(item_path) and len(item) == 12:  # hash 目录
            js_files = [f for f in os.listdir(item_path) if f.endswith('.js') and not f.endswith('.map')]
            reconstructed = os.path.join(item_path, 'reconstructed')
            has_reconstructed = os.path.isdir(reconstructed) and len(os.listdir(reconstructed)) > 0

            if target_hash and item != target_hash:
                continue

            dumps.append({
                "target_hash": item,
                "dump_dir": item_path,
                "js_count": len(js_files),
                "has_reconstructed": has_reconstructed,
                "reconstructed_dir": reconstructed if has_reconstructed else None,
            })

    # 如果没有找到hash目录，直接检查base_dir本身
    if not dumps:
        js_files = [f for f in os.listdir(base_dir) if f.endswith('.js') and not f.endswith('.map')]
        reconstructed = os.path.join(base_dir, 'reconstructed')
        has_reconstructed = os.path.isdir(reconstructed) and len(os.listdir(reconstructed)) > 0
        if js_files or has_reconstructed:
            dumps.append({
                "target_hash": "direct",
                "dump_dir": base_dir,
                "js_count": len(js_files),
                "has_reconstructed": has_reconstructed,
                "reconstructed_dir": reconstructed if has_reconstructed else None,
            })

    return {
        "status": "ok",
        "base_dir": base_dir,
        "dump_count": len(dumps),
        "dumps": dumps,
    }

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='查找JS缓存目录')
    parser.add_argument('base_dir', help='js_dumps 基础目录或公司目录')
    parser.add_argument('--target', '-t', default='', help='目标URL过滤')
    args = parser.parse_args()

    result = find_dumps(args.base_dir, args.target)
    dumps = result.get('dumps', [])
    print(f"[*] 找到 {len(dumps)} 个缓存目录", file=sys.stderr)
    for d in dumps:
        recon = f" + reconstructed({len(os.listdir(d['reconstructed_dir']))}files)" if d.get('reconstructed_dir') else ''
        print(f"  {d['dump_dir']} ({d['js_count']}js{recon})", file=sys.stderr)
    print(json.dumps(result, ensure_ascii=False, indent=2))
