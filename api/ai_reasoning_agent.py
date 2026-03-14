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
from openai import AzureOpenAI


def generate_reasoning(summary, diagnostics, decision):
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    api_key = os.getenv("AZURE_OPENAI_API_KEY")
    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")
    api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")

    missing = []
    if not endpoint:
        missing.append("AZURE_OPENAI_ENDPOINT")
    if not api_key:
        missing.append("AZURE_OPENAI_API_KEY")
    if not deployment:
        missing.append("AZURE_OPENAI_DEPLOYMENT_NAME")

    if missing:
        raise ValueError(
            f"Missing Azure OpenAI environment variables: {', '.join(missing)} | "
            f"endpoint_present={bool(endpoint)} | "
            f"api_key_present={bool(api_key)} | "
            f"deployment_present={bool(deployment)} | "
            f"deployment_value={repr(deployment)}"
        )

    client = AzureOpenAI(
        api_key=api_key,
        api_version=api_version,
        azure_endpoint=endpoint
    )

    prompt = f"""
You are an email authentication governance analyst.

Your task is to interpret DMARC telemetry findings conservatively and accurately.
Do not claim certainty where only signal exists.
Use the classifications provided by the diagnostics layer.

Respond in four short sections:
1. Authentication Summary
2. Diagnostics Interpretation
3. Risk Assessment
4. Recommended Action

Important rules:
- If SPF passes but DKIM fails, explain that this often suggests misconfiguration rather than definite abuse.
- If both SPF and DKIM fail, explain that this is more consistent with potentially unauthorized sending.
- If the evidence is ambiguous, explicitly say that manual review is required.
- Keep the explanation concise, professional, and enterprise-appropriate.

Telemetry Summary:
{summary}

Diagnostics:
{diagnostics}

Decision:
{decision}
"""

    response = client.chat.completions.create(
        model=deployment,
        messages=[
            {
                "role": "system",
                "content": "You are a security analyst specializing in DMARC, DKIM, SPF, and email authentication governance."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.2
    )

    return {
        "reasoning_summary": response.choices[0].message.content
    }
