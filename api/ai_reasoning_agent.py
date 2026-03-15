# Scutora Security Platform
# Copyright (c) 2026 Joe Miglio
#
# Licensed under the MIT License.
# See the LICENSE file in the project root for license information.

import os
from openai import AzureOpenAI


def generate_reasoning(summary, diagnostics, decision):
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    api_key = os.getenv("AZURE_OPENAI_API_KEY")
    deployment = "scutora-reasoner"
    api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")

    missing = []
    if not endpoint:
        missing.append("AZURE_OPENAI_ENDPOINT")
    if not api_key:
        missing.append("AZURE_OPENAI_API_KEY")

    if missing:
        raise ValueError(
            f"Missing Azure OpenAI environment variables: {', '.join(missing)} | "
            f"endpoint_present={bool(endpoint)} | "
            f"api_key_present={bool(api_key)} | "
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
