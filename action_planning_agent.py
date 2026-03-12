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

from typing import Any, Dict, List


def build_action_plan(
    domain: str,
    m365_posture: Dict[str, Any],
    gandi_posture: Dict[str, Any],
    summary: Dict[str, Any],
    diagnostics: Dict[str, Any],
    decision: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Build a proposed change plan based on:
    - Microsoft 365 posture
    - Gandi DNS posture
    - DMARC telemetry summary
    - diagnostics
    - governance recommendation

    This module does NOT execute anything.
    It only returns a proposed action plan for human approval.
    """

    proposed_actions: List[Dict[str, Any]] = []
    approval_required = True

    # DKIM enablement suggestion
    dkim = m365_posture.get("dkim", {})
    if not dkim.get("enabled", False):
        proposed_actions.append({
            "system": "m365_exchange_online",
            "action": "enable_dkim",
            "domain": domain,
            "reason": "DKIM is not currently enabled for the domain."
        })

    # DMARC record creation / update
    dmarc = gandi_posture.get("dmarc", {})
    current_dmarc_value = dmarc.get("value")

    recommendation = decision.get("recommendation", "").lower()

    if not dmarc.get("present", False):
        proposed_actions.append({
            "system": "gandi_livedns",
            "action": "create_dmarc_record",
            "domain": domain,
            "record_name": "_dmarc",
            "record_type": "TXT",
            "proposed_value": f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}",
            "reason": "No DMARC record currently exists."
        })
    else:
        if "quarantine" in recommendation and current_dmarc_value and "p=none" in current_dmarc_value:
            proposed_actions.append({
                "system": "gandi_livedns",
                "action": "update_dmarc_policy",
                "domain": domain,
                "record_name": "_dmarc",
                "record_type": "TXT",
                "current_value": current_dmarc_value,
                "proposed_value": current_dmarc_value.replace("p=none", "p=quarantine"),
                "reason": "Governance recommendation suggests staged movement to quarantine."
            })

        elif "reject" in recommendation and current_dmarc_value and "p=quarantine" in current_dmarc_value:
            proposed_actions.append({
                "system": "gandi_livedns",
                "action": "update_dmarc_policy",
                "domain": domain,
                "record_name": "_dmarc",
                "record_type": "TXT",
                "current_value": current_dmarc_value,
                "proposed_value": current_dmarc_value.replace("p=quarantine", "p=reject"),
                "reason": "Governance recommendation suggests movement to reject."
            })

    return {
        "domain": domain,
        "approval_required": approval_required,
        "proposed_actions": proposed_actions,
        "summary_context": {
            "total_messages": summary.get("total_messages"),
            "dkim_pass_rate": summary.get("dkim_pass_rate"),
            "spf_pass_rate": summary.get("spf_pass_rate"),
            "failing_sender_count": diagnostics.get("failing_sender_count"),
            "suspicious_sender_count": diagnostics.get("suspicious_sender_count"),
            "risk_level": decision.get("risk_level")
        }
    }


if __name__ == "__main__":
    mock_m365_posture = {
        "domain": "example.com",
        "dkim": {
            "configured": True,
            "enabled": False
        }
    }

    mock_gandi_posture = {
        "domain": "example.com",
        "dmarc": {
            "present": True,
            "value": "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
        }
    }

    mock_summary = {
        "total_messages": 168,
        "dkim_pass_rate": 86.31,
        "spf_pass_rate": 100.0
    }

    mock_diagnostics = {
        "failing_sender_count": 1,
        "suspicious_sender_count": 0
    }

    mock_decision = {
        "risk_level": "High",
        "recommendation": "Do not increase enforcement yet"
    }

    plan = build_action_plan(
        domain="example.com",
        m365_posture=mock_m365_posture,
        gandi_posture=mock_gandi_posture,
        summary=mock_summary,
        diagnostics=mock_diagnostics,
        decision=mock_decision
    )

    import json
    print(json.dumps(plan, indent=2))