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

from dmarc_parser import parse_dmarc_report, summarize_results
from diagnostics_agent import analyze_sender_issues


def evaluate_enforcement_readiness(summary, diagnostics):
    dkim_rate = float(summary.get("dkim_pass_rate", 0))
    spf_rate = float(summary.get("spf_pass_rate", 0))
    total_messages = int(summary.get("total_messages", 0))

    failing_sender_count = int(diagnostics.get("failing_sender_count", 0) or 0)
    suspicious_sender_count = int(diagnostics.get("suspicious_sender_count", 0) or 0)

    suspicious_message_volume = sum(
        int(sender.get("count", 0) or 0)
        for sender in diagnostics.get("suspicious_senders", [])
    )

    suspicious_message_rate = (
        (suspicious_message_volume / total_messages) * 100
        if total_messages > 0 else 0
    )

    # Low risk: very strong auth success and no suspicious senders
    if (
        dkim_rate >= 98
        and spf_rate >= 98
        and failing_sender_count == 0
        and suspicious_sender_count == 0
    ):
        risk_level = "Low"
        recommendation = "Increase DMARC policy to quarantine"

    # High risk: clearly elevated risk or weak auth posture
    elif (
        suspicious_sender_count >= 2
        or suspicious_message_volume >= 10
        or suspicious_message_rate >= 10
        or dkim_rate < 85
        or spf_rate < 75
    ):
        risk_level = "High"
        recommendation = "Do not increase enforcement yet"

    # Medium risk: mixed but not severe, remediation needed first
    else:
        risk_level = "Medium"
        recommendation = "Continue monitoring at p=none"

    return {
        "risk_level": risk_level,
        "recommendation": recommendation,
        "decision_factors": {
            "dkim_pass_rate": round(dkim_rate, 2),
            "spf_pass_rate": round(spf_rate, 2),
            "total_messages": total_messages,
            "failing_sender_count": failing_sender_count,
            "suspicious_sender_count": suspicious_sender_count,
            "suspicious_message_volume": suspicious_message_volume,
            "suspicious_message_rate": round(suspicious_message_rate, 2)
        }
    }


if __name__ == "__main__":
    parsed = parse_dmarc_report("sample_dmarc.xml")
    results = parsed["results"]
    summary = summarize_results(results)
    diagnostics = analyze_sender_issues(results)
    decision = evaluate_enforcement_readiness(summary, diagnostics)

    print("Risk Evaluation")
    print("---------------")
    print(f"Risk level: {decision['risk_level']}")
    print(f"Recommendation: {decision['recommendation']}")
    print(f"Decision factors: {decision['decision_factors']}")