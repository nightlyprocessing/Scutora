# Scutora Security Platform
# Copyright (c) 2026 Joe Miglio
#
# Licensed under the MIT License.
# See the LICENSE file in the project root for license information.

from dmarc_parser import parse_dmarc_report, summarize_results
from diagnostics_agent import analyze_sender_issues


def evaluate_enforcement_readiness(summary, diagnostics):
    dkim_rate = float(summary.get("dkim_pass_rate", 0))
    spf_rate = float(summary.get("spf_pass_rate", 0))
    total_messages = int(summary.get("total_messages", 0))

    failing_sender_count = int(diagnostics.get("failing_sender_count", 0) or 0)
    suspicious_sender_count = int(diagnostics.get("suspicious_sender_count", 0) or 0)

    suspicious_senders = diagnostics.get("suspicious_senders", []) or []
    classified_findings = diagnostics.get("classified_findings", []) or []

    suspicious_message_volume = sum(
        int(sender.get("count", 0) or 0)
        for sender in suspicious_senders
    )

    failing_message_volume = sum(
        int(finding.get("count", 0) or 0)
        for finding in classified_findings
    )

    suspicious_message_rate = (
        (suspicious_message_volume / total_messages) * 100
        if total_messages > 0 else 0
    )

    failing_message_rate = (
        (failing_message_volume / total_messages) * 100
        if total_messages > 0 else 0
    )

    # Low risk:
    # - very strong authentication overall
    # - no suspicious senders
    # - allows one tiny manual-review/misconfiguration case
    if (
        dkim_rate >= 99
        and spf_rate >= 97
        and suspicious_sender_count == 0
        and suspicious_message_volume == 0
        and failing_sender_count <= 1
        and failing_message_volume <= 3
        and failing_message_rate <= 3
    ):
        risk_level = "Low"
        recommendation = "Increase DMARC policy to quarantine"

    # High risk:
    # - clearly suspicious activity
    # - meaningful suspicious volume
    # - weak auth posture overall
    elif (
        suspicious_sender_count >= 2
        or suspicious_message_volume >= 10
        or suspicious_message_rate >= 10
        or dkim_rate < 85
        or spf_rate < 75
    ):
        risk_level = "High"
        recommendation = "Do not increase enforcement yet"

    # Medium risk:
    # - mixed but not severe
    # - remediation and review still needed before enforcement increase
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
            "failing_message_volume": failing_message_volume,
            "failing_message_rate": round(failing_message_rate, 2),
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