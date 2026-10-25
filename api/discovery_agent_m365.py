# Scutora Security Platform
# Copyright (c) 2026 Joe Miglio
#
# Licensed under the MIT License.
# See the LICENSE file in the project root for license information.

import json
import re
import subprocess
from typing import Any, Dict


_DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$"
)
_DKIM_SCRIPT = r"""
try {
    $config = Get-DkimSigningConfig -Identity $env:SCUTORA_M365_DOMAIN |
        Select-Object Domain,Enabled,Selector1CNAME,Selector2CNAME |
        ConvertTo-Json -Compress
    Write-Output $config
}
catch {
    Write-Output '{"error":"Failed to query DKIM config"}'
}
"""


def _valid_domain(domain: str) -> bool:
    return isinstance(domain, str) and bool(_DOMAIN_RE.fullmatch(domain))


def discover_m365_posture(domain: str, use_mock: bool = True) -> Dict[str, Any]:
    """
    Discover Microsoft 365 / Exchange Online email authentication posture
    for a given domain.

    In mock mode, returns a sample posture object. In live mode, runs a
    constant PowerShell script and passes the validated domain through the
    process environment, never by interpolating it into executable code.
    """
    if not _valid_domain(domain):
        raise ValueError("A valid DNS domain is required.")

    if use_mock:
        return {
            "domain": domain,
            "source": "m365_mock",
            "dkim": {
                "configured": True,
                "enabled": True,
                "selector1_cname_expected": f"selector1._domainkey.{domain}",
                "selector2_cname_expected": f"selector2._domainkey.{domain}"
            },
            "notes": [
                "Mock mode enabled",
                "Exchange Online PowerShell not queried"
            ]
        }

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _DKIM_SCRIPT],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env={**__import__("os").environ, "SCUTORA_M365_DOMAIN": domain}
        )

        stdout = result.stdout.strip()
        if not stdout:
            return {
                "domain": domain,
                "source": "m365_live",
                "dkim": {"configured": False, "enabled": False},
                "notes": ["No output returned from Exchange Online PowerShell"]
            }

        data = json.loads(stdout)
        if "error" in data:
            return {
                "domain": domain,
                "source": "m365_live",
                "dkim": {"configured": False, "enabled": False},
                "notes": [data["error"]]
            }

        return {
            "domain": domain,
            "source": "m365_live",
            "dkim": {
                "configured": True,
                "enabled": bool(data.get("Enabled", False)),
                "selector1_cname_expected": data.get("Selector1CNAME"),
                "selector2_cname_expected": data.get("Selector2CNAME")
            },
            "notes": []
        }

    except Exception:
        return {
            "domain": domain,
            "source": "m365_live",
            "dkim": {"configured": False, "enabled": False},
            "notes": ["Exception while querying Exchange Online."]
        }


if __name__ == "__main__":
    posture = discover_m365_posture("example.com", use_mock=True)
    print(json.dumps(posture, indent=2))
