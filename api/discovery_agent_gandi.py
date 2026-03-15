# Scutora Security Platform
# Copyright (c) 2026 Joe Miglio
#
# Licensed under the MIT License.
# See the LICENSE file in the project root for license information.

import os
import json
import urllib.request
from typing import Any, Dict, List, Optional


def _gandi_get_records(domain: str, api_token: str) -> List[Dict[str, Any]]:
    url = f"https://api.gandi.net/v5/livedns/domains/{domain}/records"

    request = urllib.request.Request(url)
    request.add_header("Authorization", f"Bearer {api_token}")
    request.add_header("Content-Type", "application/json")

    with urllib.request.urlopen(request) as response:
        payload = response.read().decode("utf-8")
        return json.loads(payload)


def _find_record(records: List[Dict[str, Any]], rrset_name: str, rrset_type: str) -> Optional[Dict[str, Any]]:
    for record in records:
        if record.get("rrset_name") == rrset_name and record.get("rrset_type") == rrset_type:
            return record
    return None


def discover_gandi_posture(
    domain: str,
    api_token: Optional[str] = None,
    use_mock: bool = True
) -> Dict[str, Any]:
    """
    Discover DNS posture from Gandi LiveDNS for a given domain.

    In mock mode, returns a sample posture object.
    In live mode, queries Gandi API for SPF and DMARC records.
    """

    if use_mock:
        return {
            "domain": domain,
            "source": "gandi_mock",
            "dmarc": {
                "present": True,
                "rrset_name": "_dmarc",
                "value": f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}"
            },
            "spf": {
                "present": True,
                "value": "v=spf1 include:spf.protection.outlook.com -all"
            },
            "notes": [
                "Mock mode enabled",
                "Gandi API not queried"
            ]
        }

    if not api_token:
        api_token = os.getenv("GANDI_API_TOKEN")

    if not api_token:
        return {
            "domain": domain,
            "source": "gandi_live",
            "dmarc": {
                "present": False,
                "value": None
            },
            "spf": {
                "present": False,
                "value": None
            },
            "notes": [
                "Missing GANDI_API_TOKEN environment variable"
            ]
        }

    try:
        records = _gandi_get_records(domain, api_token)

        dmarc_record = _find_record(records, "_dmarc", "TXT")
        root_txt_records = [
            r for r in records
            if r.get("rrset_name") == "@" and r.get("rrset_type") == "TXT"
        ]

        spf_value = None
        for record in root_txt_records:
            for value in record.get("rrset_values", []):
                if value.lower().startswith("v=spf1"):
                    spf_value = value
                    break

        return {
            "domain": domain,
            "source": "gandi_live",
            "dmarc": {
                "present": dmarc_record is not None,
                "rrset_name": "_dmarc",
                "value": dmarc_record.get("rrset_values", [None])[0] if dmarc_record else None
            },
            "spf": {
                "present": spf_value is not None,
                "value": spf_value
            },
            "notes": []
        }

    except Exception as exc:
        return {
            "domain": domain,
            "source": "gandi_live",
            "dmarc": {
                "present": False,
                "value": None
            },
            "spf": {
                "present": False,
                "value": None
            },
            "notes": [
                f"Exception while querying Gandi LiveDNS: {exc}"
            ]
        }


if __name__ == "__main__":
    posture = discover_gandi_posture("scutora.com", use_mock=True)
    print(json.dumps(posture, indent=2))