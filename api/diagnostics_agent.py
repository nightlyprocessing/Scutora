# Scutora Security Platform
# Copyright (c) 2026 Joe Miglio
#
# Licensed under the MIT License.
# See the LICENSE file in the project root for license information.

def classify_sender_issue(entry):
    """
    Classify sender issues using simple deterministic rules.
    This is the first-pass classification layer before AI reasoning.
    """

    dkim = str(entry.get("dkim", "")).lower()
    spf = str(entry.get("spf", "")).lower()
    count = int(entry.get("count", 0))

    if dkim == "fail" and spf == "pass":
        return {
            "classification": "likely_misconfiguration",
            "reason": "SPF passes but DKIM fails, which often suggests incomplete or broken DKIM configuration rather than obvious spoofing."
        }

    if dkim == "fail" and spf == "fail":
        return {
            "classification": "potentially_unauthorized_sender",
            "reason": "Both DKIM and SPF failed, which is more consistent with unauthorized or suspicious sending."
        }

    if dkim == "pass" and spf == "fail":
        return {
            "classification": "manual_review_required",
            "reason": "DKIM passes but SPF fails. This can happen in forwarding or mixed sender scenarios and should be reviewed."
        }

    if count > 100:
        return {
            "classification": "manual_review_required",
            "reason": "High message volume warrants review even if the pattern is not clearly malicious."
        }

    return {
        "classification": "manual_review_required",
        "reason": "The sender pattern is not clearly attributable to either misconfiguration or unauthorized sending."
    }


def analyze_sender_issues(results):
    failing_senders = []
    suspicious_senders = []
    classified_findings = []

    for entry in results:
        source_ip = entry["source_ip"]
        count = entry["count"]
        dkim = entry["dkim"]
        spf = entry["spf"]

        sender_record = {
            "source_ip": source_ip,
            "count": count,
            "dkim": dkim,
            "spf": spf
        }

        if dkim == "fail" or spf == "fail":
            failing_senders.append(sender_record)

            classification = classify_sender_issue(sender_record)
            classified_findings.append({
                **sender_record,
                "classification": classification["classification"],
                "reason": classification["reason"]
            })

        if dkim == "fail" and spf == "fail":
            suspicious_senders.append(sender_record)

    return {
        "failing_senders": failing_senders,
        "suspicious_senders": suspicious_senders,
        "classified_findings": classified_findings,
        "failing_sender_count": len(failing_senders),
        "suspicious_sender_count": len(suspicious_senders)
    }


if __name__ == "__main__":
    from dmarc_parser import parse_dmarc_report
    import json

    results = parse_dmarc_report("sample_dmarc.xml")
    diagnostics = analyze_sender_issues(results)

    print(json.dumps(diagnostics, indent=2))