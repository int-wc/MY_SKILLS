#!/usr/bin/env python3
"""
Consolidate deep exploitation findings and update submittable_reports.
Reads verification results from all agents and updates reports accordingly.

Usage: python3 consolidate_findings.py
"""
import os
import re
import shutil
from datetime import datetime

BASE_DIR = "/home/my/edusrc"

# Reports flagged as invalid by agents - update this as agents complete
INVALID_REPORTS = {
    "台州市数据局": [
        "中危-普通的信息泄露_漏洞报告_网上信访系统SpringBootActuator未授权访问.md"
    ],
    "乐信": [
        "中低危_比较严重信息泄漏_鼎盛CRM系统Actuator未授权访问.md"
    ],
    "北京地平线信息科技": [
        "中危-一定程度的信息泄露_call-center-test-spring-boot-actuator-swagger-druid暴露.md"
    ],
    "安徽省刀锋网络科技有限公司": [
        "中危_普通信息泄露_V2Board节点面板暴露.md"
    ],
    "浙江省教育厅": [
        "中危_普通信息泄露_社团平台SpringBootActuator未授权访问.md"
    ],
    "上海亘岩网络科技有限公司": [
        "中危-普通的信息泄露_2-Verify-Express-Path-Disclosure.md"
    ],
    "货讯通科技": [
        "中危_普通信息泄露_ESG系统SpringBootActuator暴露.md",
        "中危_普通信息泄露_ShuttleBusQAActuator未授权访问.md"
    ]
}

# Reports that need downgrade / reclassification
DOWNGRADE_REPORTS = {
}

def update_submittable_readme(company):
    """Regenerate the submittable_reports README.md"""
    sub_dir = os.path.join(BASE_DIR, company, "submittable_reports")
    if not os.path.isdir(sub_dir):
        return

    # Read vuln type info
    info_path = None
    for f in os.listdir(os.path.join(BASE_DIR, company)):
        if "Information" in f and f.endswith(".html"):
            info_path = os.path.join(BASE_DIR, company, f)
            break
    vuln_path = None
    for f in os.listdir(os.path.join(BASE_DIR, company)):
        if "VulnType" in f and f.endswith(".html"):
            vuln_path = os.path.join(BASE_DIR, company, f)
            break

    # Get vuln summary from existing README
    existing_readme = os.path.join(sub_dir, "README.md")
    vuln_summary = "请参考VulnType.html或Information.html"
    if os.path.exists(existing_readme):
        with open(existing_readme, "r") as f:
            content = f.read()
        m = re.search(r'漏洞类型要求摘要\n\n(.+?)(?=\n##)', content, re.DOTALL)
        if m:
            vuln_summary = m.group(1).strip()

    # Collect current submittable reports
    reports = []
    for fname in sorted(os.listdir(sub_dir)):
        if not fname.endswith(".md") or fname == "README.md" or fname == "evidence.md":
            continue
        # Extract severity from filename
        severity = "其他"
        if "严重" in fname or "超危" in fname:
            severity = "严重"
        elif "高危" in fname:
            severity = "高危"
        elif "中危" in fname:
            severity = "中危"
        elif "低危" in fname:
            severity = "低危"
        reports.append((severity, fname))

    # Build README
    lines = [
        f"# {company} - 可提交漏洞报告",
        "",
        "## 漏洞类型要求摘要",
        "",
        vuln_summary,
        "",
        "## 统计",
        "",
        f"- 总报告数: {len(reports)}",
        f"- 可提交报告数: {len(reports)}",
        f"- 不可提交报告数: 0",
        "",
        "## 可提交报告列表",
        "",
    ]

    for sev in ["严重", "高危", "中危", "低危", "其他"]:
        sev_reports = [r for r in reports if r[0] == sev]
        if sev_reports:
            lines.append(f"### {sev}")
            lines.append("")
            for _, fname in sev_reports:
                lines.append(f"- **{fname}**")
            lines.append("")

    lines.extend([
        "---",
        f"*报告生成时间: {datetime.now().strftime('%Y-%m-%d')}*",
        "",
    ])

    with open(existing_readme, "w") as f:
        f.write("\n".join(lines))

    print(f"  Updated README for {company}: {len(reports)} reports")


def main():
    print("=" * 60)
    print("Consolidating Deep Exploitation Findings")
    print("=" * 60)

    # Phase 1: Remove invalid reports from submittable_reports
    print("\n[Phase 1] Removing invalid reports...")
    for company, reports in INVALID_REPORTS.items():
        sub_dir = os.path.join(BASE_DIR, company, "submittable_reports")
        for report in reports:
            report_path = os.path.join(sub_dir, report)
            if os.path.exists(report_path):
                # Move to a _invalid subfolder instead of deleting
                invalid_dir = os.path.join(sub_dir, "_invalid")
                os.makedirs(invalid_dir, exist_ok=True)
                shutil.move(report_path, os.path.join(invalid_dir, report))
                print(f"  ❌ {company}/{report} -> moved to _invalid/")
            else:
                html_path = report_path.replace(".md", ".html")
                if os.path.exists(html_path):
                    os.remove(html_path)
                    print(f"  🗑️ Removed orphan HTML: {company}/{html}")

    # Phase 2: Update README files
    print("\n[Phase 2] Updating README files...")
    for company in sorted(os.listdir(BASE_DIR)):
        company_dir = os.path.join(BASE_DIR, company)
        if not os.path.isdir(company_dir):
            continue
        sub_dir = os.path.join(company_dir, "submittable_reports")
        if not os.path.isdir(sub_dir):
            continue
        has_md = any(f.endswith(".md") and f not in ("README.md", "evidence.md") for f in os.listdir(sub_dir))
        if has_md:
            update_submittable_readme(company)

    # Phase 3: Generate summary
    print("\n[Phase 3] Summary...")
    total_valid = 0
    total_removed = 0
    for company in sorted(os.listdir(BASE_DIR)):
        sub_dir = os.path.join(BASE_DIR, company, "submittable_reports")
        if not os.path.isdir(sub_dir):
            continue
        valid_count = len([f for f in os.listdir(sub_dir) if f.endswith(".md") and f not in ("README.md", "evidence.md")])
        invalid_dir = os.path.join(sub_dir, "_invalid")
        removed_count = len([f for f in os.listdir(invalid_dir) if f.endswith(".md")]) if os.path.exists(invalid_dir) else 0
        if valid_count > 0 or removed_count > 0:
            print(f"  {company}: {valid_count} valid, {removed_count} removed")
            total_valid += valid_count
            total_removed += removed_count

    print(f"\n  Total: {total_valid} valid reports, {total_removed} removed")
    print("Done!")


if __name__ == "__main__":
    main()
