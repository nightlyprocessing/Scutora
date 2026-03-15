# Scutora Security Platform
# Copyright (c) 2026 Joe Miglio
#
# Licensed under the MIT License.
# See the LICENSE file in the project root for license information.

import json
import subprocess
from typing import Any, Dict


def discover_m365_posture(domain: str, use_mock: bool = True) -> Dict[str, Any]:
    """
    Discover Microsoft 365 / Exchange Online email authentication posture
    for a given domain.

    In mock mode, returns a sample posture object.
    In live mode, attempts to call Exchange Online PowerShell.
    """

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

    ps_script = f"""
    try {{
        $config = Get-DkimSigningConfig -Identity "{domain}" | Select-Object Domain,Enabled,Selector1CNAME,Selector2CNAME | ConvertTo-Json -Compress
        Write-Output $config
    }}
    catch {{
        Write-Output '{{"error":"Failed to query DKIM config"}}'
    }}
    """

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            check=False
        )

        stdout = result.stdout.strip()
        if not stdout:
            return {
                "domain": domain,
                "source": "m365_live",
                "dkim": {
                    "configured": False,
                    "enabled": False
                },
                "notes": [
                    "No output returned from Exchange Online PowerShell"
                ]
            }

        data = json.loads(stdout)

        if "error" in data:
            return {
                "domain": domain,
                "source": "m365_live",
                "dkim": {
                    "configured": False,
                    "enabled": False
                },
                "notes": [
                    data["error"]
                ]
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

    except Exception as exc:
        return {
            "domain": domain,
            "source": "m365_live",
            "dkim": {
                "configured": False,
                "enabled": False
            },
            "notes": [
                f"Exception while querying Exchange Online: {exc}"
            ]
        }


if __name__ == "__main__":
    posture = discover_m365_posture("example.com", use_mock=True)
    print(json.dumps(posture, indent=2))