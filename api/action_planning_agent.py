# Scutora Security Platform
# Copyright (c) 2026 Joe Miglio
#
# Licensed under the MIT License.
# See the LICENSE file in the project root for license information.

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
    next_steps: List[Dict[str, Any]] = []
    approval_required = True

    recommendation = decision.get("recommendation", "")
    recommendation_lower = recommendation.lower()
    risk_level = str(decision.get("risk_level", "Unknown"))

    failing_sender_count = diagnostics.get("failing_sender_count", 0) or 0
    suspicious_sender_count = diagnostics.get("suspicious_sender_count", 0) or 0

    # -------------------------
    # 1. M365 posture actions
    # -------------------------
    dkim = m365_posture.get("dkim", {})
    dkim_enabled = dkim.get("enabled", False)

    if not dkim_enabled:
        proposed_actions.append({
            "system": "m365_exchange_online",
            "action": "enable_dkim",
            "domain": domain,
            "reason": "DKIM is not currently enabled for the domain."
        })

        next_steps.append({
            "title": "Enable DKIM for the domain",
            "description": f"Turn on DKIM signing for {domain} in Microsoft 365 before increasing DMARC enforcement.",
            "reason": "DMARC enforcement should not be raised until legitimate mail is reliably authenticated with DKIM."
        })

    # -------------------------
    # 2. Gandi / DMARC posture
    # -------------------------
    dmarc = gandi_posture.get("dmarc", {})
    current_dmarc_value = dmarc.get("value")

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

        next_steps.append({
            "title": "Create a baseline DMARC record",
            "description": f"Publish a DMARC record for {domain} using p=none and aggregate reporting before considering stronger enforcement.",
            "reason": "A monitoring-only DMARC policy establishes telemetry without disrupting legitimate mail."
        })

    else:
        if "quarantine" in recommendation_lower and current_dmarc_value and "p=none" in current_dmarc_value:
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

            next_steps.append({
                "title": "Increase DMARC policy to quarantine",
                "description": "Move the DMARC record from p=none to p=quarantine as a staged enforcement step.",
                "reason": "Telemetry indicates the domain is approaching readiness for stronger protection."
            })

        elif "reject" in recommendation_lower and current_dmarc_value and "p=quarantine" in current_dmarc_value:
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

            next_steps.append({
                "title": "Increase DMARC policy to reject",
                "description": "Move the DMARC record from p=quarantine to p=reject after confirming authentication stability.",
                "reason": "The domain appears ready for full enforcement."
            })

    # -------------------------
    # 3. Diagnostics-driven governance steps
    # -------------------------
    if suspicious_sender_count > 0:
        next_steps.append({
            "title": "Investigate suspicious sending sources",
            "description": f"Review the {suspicious_sender_count} suspicious sender source(s) identified in the DMARC telemetry before making any enforcement changes.",
            "reason": "Potentially unauthorized sending must be validated before policy changes are introduced."
        })

    if failing_sender_count > 0:
        next_steps.append({
            "title": "Review failing sender authentication",
            "description": f"Investigate the {failing_sender_count} sender source(s) with authentication failures to determine whether they are misconfigured or unauthorized.",
            "reason": "Authentication failures may reflect either benign misconfiguration or abusive sending behavior."
        })

    # -------------------------
    # 4. Recommendation-driven general steps
    # -------------------------
    if "do not increase enforcement" in recommendation_lower:
        next_steps.append({
            "title": "Keep current DMARC enforcement unchanged",
            "description": "Do not increase DMARC enforcement at this time.",
            "reason": "Current telemetry and diagnostics do not yet support a safe policy increase."
        })

        next_steps.append({
            "title": "Continue monitoring DMARC telemetry",
            "description": "Collect and review additional aggregate reports before revisiting policy changes.",
            "reason": "More telemetry is needed to confirm that legitimate senders are aligned and suspicious activity is understood."
        })

    elif "quarantine" in recommendation_lower:
        next_steps.append({
            "title": "Monitor post-change mail flow",
            "description": "After moving to quarantine, review aggregate reports and confirm that legitimate senders continue to authenticate successfully.",
            "reason": "Staged enforcement changes should be validated before stronger action is considered."
        })

    elif "reject" in recommendation_lower:
        next_steps.append({
            "title": "Monitor post-change enforcement impact",
            "description": "After moving to reject, validate that legitimate mail continues to authenticate and that abusive traffic is being blocked.",
            "reason": "Full enforcement should still be monitored to catch any edge cases or overlooked senders."
        })

    # -------------------------
    # 5. Always require approval
    # -------------------------
    next_steps.append({
        "title": "Obtain human approval before implementation",
        "description": "Have the proposed governance and DNS changes reviewed before applying them in production.",
        "reason": "Email authentication changes can affect legitimate business communication and should not be applied automatically."
    })

    return {
        "domain": domain,
        "approval_required": approval_required,
        "proposed_actions": proposed_actions,
        "next_steps": next_steps,
        "summary_context": {
            "total_messages": summary.get("total_messages"),
            "dkim_pass_rate": summary.get("dkim_pass_rate"),
            "spf_pass_rate": summary.get("spf_pass_rate"),
            "failing_sender_count": failing_sender_count,
            "suspicious_sender_count": suspicious_sender_count,
            "risk_level": risk_level,
            "recommendation": recommendation
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
