#!/usr/bin/env python3
"""Hunter API 资产采集脚本

从鹰图(Hunter) API 查询目标公司的 Web 资产并保存为 CSV。

依赖: pip install requests
使用: HUNTER_API_KEY=xxx python3 scripts/fetch_hunter.py "抖音"
"""
import argparse, csv, os, sys, time
from datetime import datetime

try:
    import requests
except ImportError:
    print("请先安装 requests: pip install requests")
    sys.exit(1)

HUNTER_API = "https://hunter.qianxin.com/openApi/search"
API_KEY = os.getenv("HUNTER_API_KEY", "")
PAGE_SIZE = 100
MAX_PAGES = 10
REQUEST_INTERVAL = 1.2

CSV_FIELDS = [
    "IP", "端口", "域名", "IP标签", "url", "网站标题", "高危协议",
    "协议", "通讯协议", "网站状态码", "操作系统", "备案单位",
    "备案号", "备案异常", "国家", "省份", "市区", "Web资产",
    "运营商", "注册机构", "应用/组件", "资产标签", "探查时间",
]


def build_query(company):
    return [
        f'web.title="{company}"',
        f'domain.suffix="{company}"',
        f'web.body="{company}"',
    ]


def fetch_page(query, page, api_key):
    params = {
        "api-key": api_key,
        "search": query,
        "page": str(page),
        "page_size": str(PAGE_SIZE),
        "is_web": "3",
    }
    try:
        resp = requests.get(HUNTER_API, params=params, timeout=30)
        data = resp.json()
        if data.get("code") == 200:
            return data.get("data")
        print(f"  API 错误: {data.get('code')} - {data.get('msg', '?')}")
        return None
    except Exception as e:
        print(f"  请求失败: {e}")
        return None


def transform(item):
    return {
        "IP": item.get("ip", ""),
        "端口": str(item.get("port", "")),
        "域名": item.get("domain", ""),
        "IP标签": "",
        "url": item.get("url", ""),
        "网站标题": item.get("web_title", ""),
        "高危协议": "否",
        "协议": item.get("protocol", ""),
        "通讯协议": item.get("protocol", ""),
        "网站状态码": str(item.get("status_code", "")),
        "操作系统": item.get("os", ""),
        "备案单位": item.get("company", ""),
        "备案号": item.get("number", ""),
        "备案异常": "",
        "国家": item.get("country", "中国"),
        "省份": item.get("province", ""),
        "市区": item.get("city", ""),
        "Web资产": "是",
        "运营商": item.get("isp", ""),
        "注册机构": "",
        "应用/组件": item.get("component", ""),
        "资产标签": "",
        "探查时间": item.get("updated_at", datetime.now().strftime("%m-%d-%y")),
    }


def fetch(company, api_key):
    print(f"正在查询: {company}")
    all_assets, seen = [], set()
    for q in build_query(company):
        print(f"  搜索: {q}")
        for page in range(1, MAX_PAGES + 1):
            data = fetch_page(q, page, api_key)
            if not data:
                break
            items = data.get("arr", [])
            total = data.get("total", 0)
            if not items:
                break
            for item in items:
                url = item.get("url", "")
                if url and url not in seen:
                    seen.add(url)
                    all_assets.append(transform(item))
            print(f"    第{page}页: {len(items)}条 (累计{len(all_assets)})")
            if page * PAGE_SIZE >= total or len(items) < PAGE_SIZE:
                break
            time.sleep(REQUEST_INTERVAL)
        time.sleep(REQUEST_INTERVAL)
    print(f"  ✅ 共获取 {len(all_assets)} 个资产")
    return all_assets


def save_csv(assets, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(assets)
    print(f"  💾 已保存: {path}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Hunter API 资产采集")
    p.add_argument("company", help="公司名称")
    p.add_argument("--output", "-o", help="CSV 输出路径")
    p.add_argument("--api-key", help="API Key（默认取 HUNTER_API_KEY）")
    args = p.parse_args()
    key = args.api_key or API_KEY
    if not key:
        print("错误: 请设置 HUNTER_API_KEY 环境变量或 --api-key")
        sys.exit(1)
    assets = fetch(args.company, key)
    if assets:
        save_csv(assets, args.output or f"hunter_info/{args.company}_assert.csv")
