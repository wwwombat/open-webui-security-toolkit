"""
title: MITRE ATT&CK Mapper
author: wwwombat
version: 1.0.0
license: MIT
description: >
  Query the MITRE ATT&CK framework via the public TAXII 2.1 API.
  Look up techniques by ID (e.g. T1059) or keyword, and return
  tactic, technique description, detection guidance, and mitigations.
  No API key required.
requirements: httpx
"""

import httpx
import json
from typing import Any
from pydantic import BaseModel, Field


TAXII_ROOT = "https://cti-taxii.mitre.org/taxii/"
ENTERPRISE_COLLECTION = "https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/objects/"

HEADERS = {
    "Accept": "application/stix+json;version=2.1",
    "User-Agent": "wwwombat-security-toolkit/1.0",
}


class Tools:
    class Valves(BaseModel):
        pass  # No API key required for MITRE ATT&CK

    def __init__(self):
        self.valves = self.Valves()

    def lookup_technique(self, technique_id: str) -> str:
        """
        Look up a MITRE ATT&CK technique by ID (e.g. T1059, T1059.001).
        Returns tactic mapping, description, detection guidance, and mitigations.
        :param technique_id: ATT&CK technique ID, e.g. 'T1059' or 'T1059.001'
        :return: Formatted technique details
        """
        technique_id = technique_id.strip().upper()

        try:
            # Fetch all attack-pattern objects filtered by external ID
            params = {
                "match[type]": "attack-pattern",
            }
            with httpx.Client(http2=False, timeout=20) as client:
                resp = client.get(
                    ENTERPRISE_COLLECTION,
                    headers=HEADERS,
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()

            objects = data.get("objects", [])

            # Find the technique matching the requested ID
            match = None
            for obj in objects:
                ext_refs = obj.get("external_references", [])
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").upper() == technique_id:
                        match = obj
                        break
                if match:
                    break

            if not match:
                return f"No ATT&CK technique found for ID: {technique_id}. Verify the ID at https://attack.mitre.org"

            return self._format_technique(match, technique_id)

        except httpx.HTTPStatusError as e:
            return f"ATT&CK API error: HTTP {e.response.status_code}"
        except Exception as e:
            return f"ATT&CK lookup failed: {str(e)}"

    def search_techniques(self, keyword: str) -> str:
        """
        Search MITRE ATT&CK techniques by keyword (e.g. 'phishing', 'lateral movement', 'credential dumping').
        Returns up to 5 matching techniques with IDs and tactic mappings.
        :param keyword: Search term to match against technique names and descriptions
        :return: List of matching techniques
        """
        keyword = keyword.strip().lower()

        try:
            params = {
                "match[type]": "attack-pattern",
            }
            with httpx.Client(http2=False, timeout=20) as client:
                resp = client.get(
                    ENTERPRISE_COLLECTION,
                    headers=HEADERS,
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()

            objects = data.get("objects", [])

            matches = []
            for obj in objects:
                # Skip deprecated/revoked techniques
                if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue

                name = obj.get("name", "").lower()
                desc = obj.get("description", "").lower()

                if keyword in name or keyword in desc:
                    ext_id = ""
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            ext_id = ref.get("external_id", "")
                            break

                    tactics = [
                        phase.get("phase_name", "").replace("-", " ").title()
                        for phase in obj.get("kill_chain_phases", [])
                        if phase.get("kill_chain_name") == "mitre-attack"
                    ]

                    matches.append({
                        "id": ext_id,
                        "name": obj.get("name", "Unknown"),
                        "tactics": tactics,
                        "description": obj.get("description", "")[:200].strip(),
                    })

                if len(matches) >= 5:
                    break

            if not matches:
                return f"No ATT&CK techniques found matching keyword: '{keyword}'"

            lines = [f"ATT&CK techniques matching '{keyword}':\n"]
            for m in matches:
                tactics_str = ", ".join(m["tactics"]) if m["tactics"] else "Unknown"
                lines.append(f"**{m['id']} — {m['name']}**")
                lines.append(f"  Tactic(s): {tactics_str}")
                lines.append(f"  {m['description']}...")
                lines.append(f"  Reference: https://attack.mitre.org/techniques/{m['id'].replace('.', '/')}/\n")

            lines.append("Use lookup_technique('<ID>') for full details including detection and mitigations.")
            return "\n".join(lines)

        except httpx.HTTPStatusError as e:
            return f"ATT&CK API error: HTTP {e.response.status_code}"
        except Exception as e:
            return f"ATT&CK search failed: {str(e)}"

    def _format_technique(self, obj: dict, technique_id: str) -> str:
        """Format a STIX attack-pattern object into a readable report."""
        name = obj.get("name", "Unknown")
        description = obj.get("description", "No description available.")
        detection = obj.get("x_mitre_detection", "No detection guidance available.")
        is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
        platforms = ", ".join(obj.get("x_mitre_platforms", [])) or "Unknown"
        data_sources = ", ".join(obj.get("x_mitre_data_sources", [])) or "None listed"

        tactics = [
            phase.get("phase_name", "").replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        tactics_str = ", ".join(tactics) if tactics else "Unknown"

        # Build ATT&CK URL
        url_id = technique_id.replace(".", "/")
        url = f"https://attack.mitre.org/techniques/{url_id}/"

        # Truncate long descriptions for readability
        if len(description) > 800:
            description = description[:800].strip() + "... [truncated]"

        lines = [
            f"## MITRE ATT&CK: {technique_id} — {name}",
            f"{'(Sub-technique)' if is_subtechnique else '(Technique)'}",
            "",
            f"**Tactic(s):** {tactics_str}",
            f"**Platforms:** {platforms}",
            f"**Data Sources:** {data_sources}",
            "",
            "### Description",
            description,
            "",
            "### Detection",
            detection[:600].strip() + ("..." if len(detection) > 600 else ""),
            "",
            f"**Reference:** {url}",
            "",
            "_Source: MITRE ATT&CK Enterprise Matrix via TAXII 2.1 API_",
        ]

        return "\n".join(lines)
