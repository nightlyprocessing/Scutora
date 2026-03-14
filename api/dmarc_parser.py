# Scutora
# Copyright (c) 2026 Joe Miglio. All rights reserved.
#
# This source file is proprietary and confidential.
# Unauthorized copying, modification, distribution, disclosure,
# or use of this file, in whole or in part, is strictly prohibited
# without the prior written permission of Joe Miglio.
#
# This file may contain trade secrets, confidential information,
# and other proprietary material related to the Scutora project.

import xml.etree.ElementTree as ET


def extract_domain_from_report(root):
    """
    Try to determine the DMARC report's target domain.

    Preference order:
    1. policy_published/domain
    2. identifiers/header_from (first record)
    """

    policy_domain = root.findtext(".//policy_published/domain")
    if policy_domain:
        return policy_domain.strip()

    header_from = root.findtext(".//record/identifiers/header_from")
    if header_from:
        return header_from.strip()

    return None


def parse_dmarc_report(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    report_domain = extract_domain_from_report(root)
    results = []

    for record in root.findall(".//record"):
        source_ip = record.findtext("row/source_ip")
        count = int(record.findtext("row/count", "0"))
        dkim = record.findtext("row/policy_evaluated/dkim")
        spf = record.findtext("row/policy_evaluated/spf")

        results.append({
            "source_ip": source_ip,
            "count": count,
            "dkim": dkim,
            "spf": spf
        })

    return {
        "domain": report_domain,
        "results": results
    }


def summarize_results(results):
    total_messages = sum(entry["count"] for entry in results)

    dkim_pass_count = sum(
        entry["count"] for entry in results if entry["dkim"] == "pass"
    )

    spf_pass_count = sum(
        entry["count"] for entry in results if entry["spf"] == "pass"
    )

    dkim_pass_rate = (dkim_pass_count / total_messages * 100) if total_messages else 0
    spf_pass_rate = (spf_pass_count / total_messages * 100) if total_messages else 0

    return {
        "total_messages": total_messages,
        "dkim_pass_count": dkim_pass_count,
        "spf_pass_count": spf_pass_count,
        "dkim_pass_rate": round(dkim_pass_rate, 2),
        "spf_pass_rate": round(spf_pass_rate, 2)
    }


if __name__ == "__main__":
    parsed = parse_dmarc_report("sample_dmarc.xml")
    report = parsed["results"]
    summary = summarize_results(report)

    print("DMARC Summary")
    print("-------------")
    print(f"Domain: {parsed['domain']}")
    print(f"Total messages: {summary['total_messages']}")
    print(f"DKIM pass count: {summary['dkim_pass_count']}")
    print(f"SPF pass count: {summary['spf_pass_count']}")
    print(f"DKIM pass rate: {summary['dkim_pass_rate']}%")
    print(f"SPF pass rate: {summary['spf_pass_rate']}%")
