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


def evaluate_enforcement_readiness(summary):
    dkim_rate = summary["dkim_pass_rate"]
    spf_rate = summary["spf_pass_rate"]

    if dkim_rate >= 98 and spf_rate >= 98:
        recommendation = "Increase DMARC policy to quarantine"
        risk_level = "Low"
    elif dkim_rate >= 90 and spf_rate >= 95:
        recommendation = "Continue monitoring at p=none"
        risk_level = "Moderate"
    else:
        recommendation = "Do not increase enforcement yet"
        risk_level = "High"

    return {
        "risk_level": risk_level,
        "recommendation": recommendation
    }


if __name__ == "__main__":
    results = parse_dmarc_report("sample_dmarc.xml")
    summary = summarize_results(results)
    decision = evaluate_enforcement_readiness(summary)

    print("Risk Evaluation")
    print("---------------")
    print(f"Risk level: {decision['risk_level']}")
    print(f"Recommendation: {decision['recommendation']}")