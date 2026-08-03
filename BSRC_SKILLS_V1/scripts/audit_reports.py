#!/usr/bin/env python3
"""
Audit all reports against ByteSRC requirements.
Check: HTTP packets present, 200 OK verification, ByteSRC severity/business-tier compliance.
"""
import os
import re
import json

BASE_DIR = "/home/my/SRC/BSRC"

# ByteSRC 等级 · 业务档位接受类型速查（依据 ByteSRC安全报告处置规则V6.0）
# 六大业务（抖音/电商/飞书/财经/豆包/火山引擎）高系数资产可评"重大"
VULN_TYPES = {
    "高系数业务(飞书/今日头条/豆包/抖音/抖音电商/财经/西瓜视频/生活服务/火山引擎计网存储数安/BytePlus核心)": {
        "重大": ["抖音任意账号接管", "无交互获取手机号/身份证", "零元购", "0click RCE", "接管火山租户主账号", "篡改支付金额零元支付", "豆包任意登录用户账号接管"],
        "严重": ["直接获取核心场景/模块权限", "百万条以上敏感数据泄露", "核心系统严重逻辑缺陷(任意改密/任意登录)", "任意账号资金消费/无限制提现", "获取服务级关键凭证(AK/SK/证书/密钥)", "TEE任意代码执行(高权限)"],
        "高危": ["获取一般系统权限", "RCE/上传WebShell", "5000条以上敏感数据", "通字节内网回显SSRF(统一高系数)", "重要系统敏感越权", "客户端本地敏感信息泄露", "本地任意文件读写"],
        "中危": ["普通信息泄露(含敏感源)", "通字节内网无回显SSRF(中危1)", "非核心DB SQL注入", "存储XSS", "敏感JSONP劫持", "本地DB注入", "绕过限制用高级服务"],
        "低危": ["反射XSS", "无交互URL跳转", "短信轰炸/密码爆破", "路径泄露/.git/Django Debug/phpinfo/服务端日志", "CORS敏感信息泄漏", "BlindSSRF", "测试系统SQL注入"]
    },
    "中系数业务（番茄/剪映/懂车帝/Trae/巨量引擎/CIS/内部系统/即时零售等）": {
        "严重": ["直接获取核心场景权限", "RCE", "百万级敏感数据", "核心系统严重逻辑缺陷"],
        "高危": ["获取一般系统权限", "RCE/WebShell", "5000条以上敏感数据", "回显SSRF", "重要越权"],
        "中危": ["普通信息泄露", "存储XSS", "非核心DB注入", "无回显SSRF"],
        "低危": ["反射XSS", "URL跳转", "SQL注入", "SQLi"]
    },
    "低系数业务（扣子/AIDP/PICO/抖音开放平台/抖音云/服务市场/电商大学等）": {
        "严重": ["可直接利用的高危漏洞"],
        "高危": ["RCE", "WebShell", "批量敏感数据", "重要越权"],
        "中危": ["SSRF", "存储XSS", "信息泄露"],
        "低危": ["反射XSS", "URL跳转"],
        "抖音盒子": ["仅收高危"]
    },
    "忽略清单（全业务通用不收项）": {
        "不收": ["第三方供应商/外包/ISV/电商ISV漏洞", "火山引擎·BytePlus外部客户", "非中区产品", "无法复现", "内部已知公开漏洞(Jenkins等)", "专项排查中", "与模型提示和响应内容相关问题", "非信息安全的内容安全风险", "隐私合规问题", "用户名遍历", "SPF伪造", "简单DNS日志型SSRF", "Self-XSS", "恶作剧CSRF", "无法影响他人本地DoS", "静态目录遍历", "电商子主账号越权", "网络层DoS"]
    }
}

def check_report(md_path):
    """Check a report for required elements."""
    with open(md_path, "r", encoding="utf-8") as f:
        content = f.read()

    results = {
        "file": os.path.basename(md_path),
        "has_http_packets": False,
        "has_200_ok": False,
        "has_curl": False,
        "lines": len(content.splitlines()),
        "issues": []
    }

    # Check for HTTP request/response patterns
    if re.search(r'HTTP/1\.[01]\s+\d+', content):
        results["has_http_packets"] = True
    if re.search(r'200\s*OK|200 ok', content):
        results["has_200_ok"] = True
    if re.search(r'curl\s+', content):
        results["has_curl"] = True

    if not results["has_http_packets"]:
        results["issues"].append("缺少HTTP请求/返回包")
    if not results["has_200_ok"]:
        results["issues"].append("缺少200 OK验证")
    if not results["has_curl"]:
        results["issues"].append("缺少curl验证命令")

    return results


def _find_reports(company_dir):
    reports = []
    for subdir in ["submittable_reports", "reports"]:
        src_dir = os.path.join(company_dir, subdir)
        if not os.path.isdir(src_dir):
            continue
        for fname in os.listdir(src_dir):
            if not fname.endswith(".md") or fname in ("README.md", "evidence.md"):
                continue
            md_path = os.path.join(src_dir, fname)
            result = check_report(md_path)
            result["dir"] = subdir
            reports.append(result)
    return reports


def main():
    all_results = {}
    total_issues = 0
    total_ok = 0
    total_reports = 0

    # 指定业务线（company）时只审计它；否则遍历全部
    target = os.environ.get("AUDIT_COMPANY", "").strip()
    companies = sorted(os.listdir(BASE_DIR)) if not target else [target]

    for company in companies:
        company_dir = os.path.join(BASE_DIR, company)
        if target and not os.path.isdir(company_dir):
            print(f"⚠️ 未找到业务线目录: {company}")
            continue
        if not os.path.isdir(company_dir):
            continue

        reports = _find_reports(company_dir)

        if not reports:
            continue

        company_ok = sum(1 for r in reports if not r["issues"])
        company_issues = sum(len(r["issues"]) for r in reports)
        all_results[company] = reports
        total_reports += len(reports)
        total_ok += company_ok
        total_issues += company_issues

        print(f"\n{'='*70}")
        print(f"【{company}】共{len(reports)}份报告 | 合格:{company_ok} | 有问题的:{len(reports)-company_ok}")
        print(f"{'='*70}")
        for r in reports:
            status = "✅" if not r["issues"] else "❌"
            print(f"  {status} [{r['dir']}] {r['file']}")
            for issue in r["issues"]:
                print(f"       - {issue}")

    print(f"\n\n{'='*70}")
    print(f"总计: {total_reports}份报告 | 合格:{total_ok} | 有问题:{total_reports-total_ok}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()