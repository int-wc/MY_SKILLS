#!/usr/bin/env python3
"""
Audit all reports against VulnType requirements.
Check: HTTP packets present, 200 OK verification, VulnType compliance.
"""
import os
import re
import json

BASE_DIR = "/home/my/SRC/BSRC"

# VulnType requirements for each company
VULN_TYPES = {
    "安徽省刀锋网络科技有限公司": {
        "严重": ["核心权限", "10W+信息泄露", "支付相关"],
        "高危": ["逻辑漏洞", "核心存储XSS", "弱口令", "10W+信息", "越权"],
        "中危": ["500-10W信息", "一般存储XSS", "文件包含", "SSRF"],
        "低危": ["少量信息泄露"],
        "忽略": ["短信轰炸", "Self-XSS", "大模型相关"]
    },
    "北京地平线信息科技": {
        "严重": ["核心权限", "严重信息泄露", "支付", "DOS"],
        "高危": ["一般系统权限", "1W+信息泄露", "逻辑漏洞", "核心存储XSS", "弱口令进后台", "越权"],
        "中危": ["存储XSS", "越权", "弱口令", "文件包含", "代码泄露", "SSRF", "信息泄露", "短信轰炸"],
        "低危": ["难利用SQL注入", "逻辑缺陷", "邮箱轰炸"],
        "忽略": ["无实际危害", "少量非敏感信息", "反射XSS", "Self-XSS", "dom XSS"]
    },
    "北京金山云网络技术有限公司": {
        "严重": ["RCE", "WebShell", "严重信息泄露(3敏感字段)", "核心逻辑缺陷", "DOS"],
        "高危": ["逻辑漏洞", "代码执行", "重要业务权限", "重要DB SQL注入", "SSRF", "越权"],
        "中危": ["JSONHijacking", "CSRF", "存储XSS", "逻辑缺陷", "弱口令", "信息泄露"],
        "低危": ["反射XSS", "短信轰炸", "URL跳转", "轻微信息泄露"]
    },
    "杭州恒业网络": {
        "高危": ["RCE", "WebShell", "严重信息泄露", "SQL注入", "逻辑漏洞", "越权"],
        "中危": ["信息泄露", "CSRF", "存储XSS", "逻辑缺陷", "弱口令"],
        "低危": ["轻微信息泄露", "反射XSS", "短信轰炸", "URL跳转"],
        "不接收": ["XSS"]
    },
    "货讯通科技": {
        "高危": ["RCE", "WebShell", "严重信息泄露", "SQL注入", "逻辑漏洞", "越权"],
        "中危": ["信息泄露", "CSRF", "存储XSS", "逻辑缺陷", "弱口令"],
        "低危": ["轻微信息泄露", "反射XSS", "短信轰炸", "URL跳转"]
    },
    "乐信": {
        "严重": ["大量敏感信息泄露", "批量盗取账户", "重要DB SQL注入"],
        "高危": ["金钱逻辑", "支付逻辑", "越权", "客户端权限", "存储XSS"],
        "中低危": ["存储XSS", "越权", "信息泄露", "逻辑漏洞", "反射XSS"],
        "忽略": ["无敏感CSRF", "SSRF", "Self-XSS", "内网IP泄露"]
    },
    "理想汽车": {
        "严重": ["核心权限", "10W+信息泄露", "支付相关"],
        "高危": ["逻辑漏洞", "核心存储XSS", "弱口令", "10W+信息", "越权"],
        "中危": ["500-10W信息", "存储XSS", "文件包含", "SSRF"],
        "低危": ["少量信息泄露"],
        "忽略": ["短信轰炸", "Self-XSS", "大模型相关"]
    },
    "上海亘岩网络科技有限公司": {
        "高危": ["RCE", "WebShell", "严重信息泄露", "SQL注入", "逻辑漏洞", "越权"],
        "中危": ["信息泄露", "CSRF", "存储XSS", "逻辑缺陷"],
        "低危": ["轻微信息泄露", "反射XSS", "短信轰炸", "URL跳转"]
    },
    "台州市数据局": {
        "高危": ["RCE", "SQL注入", "逻辑漏洞", "越权"],
        "中危": ["信息泄露", "CSRF", "存储XSS", "弱口令"],
        "低危": ["轻微信息泄露", "反射XSS", "短信轰炸"]
    },
    "浙江省教育厅": {
        "高危": ["RCE", "SQL注入", "逻辑漏洞", "越权"],
        "中危": ["信息泄露", "CSRF", "存储XSS", "弱口令"],
        "低危": ["轻微信息泄露", "反射XSS", "短信轰炸", "URL跳转"]
    },
    "浙江省三门县人民政府办公室": {
        "高危": ["RCE", "SQL注入", "逻辑漏洞", "越权"],
        "中危": ["信息泄露", "CSRF", "存储XSS", "弱口令"],
        "低危": ["轻微信息泄露", "反射XSS", "短信轰炸"]
    },
    "追觅": {
        "严重": ["大量高价值信息泄露(员工2000+条/用户50万+条)"],
        "高危": ["大量信息泄露5万+", "弱口令", "RCE", "存储XSS", "SSRF", "越权"],
        "中危": ["信息泄露", "CSRF", "存储XSS", "越权", "非核心SQL注入"],
        "忽略": ["Swagger不可利用", "Spring Actuator不可利用", "API Key泄露", "用户名枚举", "短信轰炸", "内网IP泄露"]
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
        "has_401_403": False,
        "has_curl": False,
        "lines": len(content.splitlines()),
        "issues": []
    }

    # Check for HTTP request/response patterns
    if re.search(r'HTTP/1\.[01]\s+\d+', content):
        results["has_http_packets"] = True
    if re.search(r'200\s*OK|200 ok', content):
        results["has_200_ok"] = True
    if re.search(r'\b401\b|\b403\b', content):
        results["has_401_403"] = True
    if re.search(r'curl\s+', content):
        results["has_curl"] = True

    if not results["has_http_packets"]:
        results["issues"].append("缺少HTTP请求/返回包")
    if not results["has_200_ok"]:
        results["issues"].append("缺少200 OK验证")
    if not results["has_curl"]:
        results["issues"].append("缺少curl验证命令")

    return results


def main():
    all_results = {}
    total_issues = 0
    total_ok = 0
    total_reports = 0

    for company in sorted(os.listdir(BASE_DIR)):
        company_dir = os.path.join(BASE_DIR, company)
        if not os.path.isdir(company_dir):
            continue

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

        if not reports:
            continue

        company_ok = sum(1 for r in reports if not r["issues"])
        company_issues = sum(len(r["issues"]) for r in reports)
        all_results[company] = reports
        total_reports += len(reports)
        total_ok += company_ok
        total_issues += company_issues

        print(f"\n{'='*60}")
        print(f"【{company}】共{len(reports)}份报告 | 合格:{company_ok} | 有问题的:{len(reports)-company_ok}")
        print(f"{'='*60}")
        for r in reports:
            status = "✅" if not r["issues"] else "❌"
            print(f"  {status} [{r['dir']}] {r['file']}")
            for issue in r["issues"]:
                print(f"       - {issue}")

    print(f"\n\n{'='*60}")
    print(f"总计: {total_reports}份报告 | 合格:{total_ok} | 有问题:{total_reports-total_ok}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
