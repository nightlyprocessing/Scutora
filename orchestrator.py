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

import os
import json

from dmarc_parser import parse_dmarc_report, summarize_results
from diagnostics_agent import analyze_sender_issues
from risk_agent import evaluate_enforcement_readiness
from ai_reasoning_agent import generate_reasoning
from discovery_agent_m365 import discover_m365_posture
from discovery_agent_gandi import discover_gandi_posture
from action_planning_agent import build_action_plan


def run_scutora_analysis(
    xml_file: str,
    domain: str = "scutora.com",
    use_mock_m365: bool = True,
    use_mock_gandi: bool = True
):
    """
    Run the Scutora end-to-end analysis pipeline.

    Important:
    - This function uses the XML file path explicitly passed in.
    - It does NOT fall back to sample_dmarc.xml during normal execution.
    """

    if not xml_file:
        raise ValueError("xml_file was not provided to run_scutora_analysis().")

    if not os.path.exists(xml_file):
        raise FileNotFoundError(f"XML file not found: {xml_file}")

    gandi_api_token = os.getenv("GANDI_API_TOKEN")

    m365_posture = discover_m365_posture(
        domain=domain,
        use_mock=use_mock_m365
    )

    gandi_posture = discover_gandi_posture(
        domain=domain,
        api_token=gandi_api_token,
        use_mock=use_mock_gandi
    )

    results = parse_dmarc_report(xml_file)
    summary = summarize_results(results)
    diagnostics = analyze_sender_issues(results)
    decision = evaluate_enforcement_readiness(summary)
    reasoning = generate_reasoning(summary, diagnostics, decision)

    action_plan = build_action_plan(
        domain=domain,
        m365_posture=m365_posture,
        gandi_posture=gandi_posture,
        summary=summary,
        diagnostics=diagnostics,
        decision=decision
    )

    return {
        "domain": domain,
        "telemetry_source": {
            "xml_file": xml_file
        },
        "m365_posture": m365_posture,
        "gandi_posture": gandi_posture,
        "summary": summary,
        "diagnostics": diagnostics,
        "decision": decision,
        "reasoning": reasoning,
        "action_plan": action_plan
    }


if __name__ == "__main__":
    demo_file = "sample_dmarc.xml"

    if not os.path.exists(demo_file):
        raise FileNotFoundError(
            "sample_dmarc.xml was not found. This __main__ block is only for local testing."
        )

    analysis = run_scutora_analysis(
        xml_file=demo_file,
        domain="scutora.com",
        use_mock_m365=True,
        use_mock_gandi=True
    )

    print(json.dumps(analysis, indent=2))