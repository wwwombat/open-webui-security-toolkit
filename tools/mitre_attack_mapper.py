"""
title: MITRE ATT&CK Mapper
author: wwwombat
version: 1.2.0
license: MIT
description: >
  Query the MITRE ATT&CK Enterprise Matrix from a local STIX bundle.
  Look up techniques by ID (e.g. T1059, T1059.001) or keyword, and return
  tactic, technique description, detection guidance, and ATT&CK reference URL.
  Reads from local cache at /home/wwwombat/data/attack/enterprise-attack.json
  for sub-second lookups with no external API dependency.
requirements: pydantic
"""

import json
import os
from functools import lru_cache
from pydantic import BaseModel, Field

DEFAULT_CACHE_PATH = "/home/wwwombat/data/attack/enterprise-attack.json"


@lru_cache(maxsize=4)
def _load_attack_data(cache_path: str) -> list:
    """Load and cache the ATT&CK STIX bundle in memory on first call (per path)."""
    if not os.path.exists(cache_path):
        raise FileNotFoundError(
            f"ATT&CK bundle not found at {cache_path}. "
            f"Run: curl -L https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json "
            f"-o {cache_path}"
        )
    with open(cache_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Return only attack-pattern objects, filtering revoked/deprecated
    return [
        obj for obj in data.get("objects", [])
        if obj.get("type") == "attack-pattern"
        and not obj.get("revoked")
        and not obj.get("x_mitre_deprecated")
    ]


def _get_ext_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _get_tactics(obj: dict) -> list:
    return [
        phase.get("phase_name", "").replace("-", " ").title()
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    ]


class Tools:
    class Valves(BaseModel):
        stix_bundle_path: str = Field(
            default=DEFAULT_CACHE_PATH,
            description=(
                "Path (inside the container) to the MITRE ATT&CK Enterprise "
                "STIX bundle JSON. Must match the docker-compose volume mount."
            ),
        )

    def __init__(self):
        self.valves = self.Valves()

    def lookup_technique(self, technique_id: str) -> str:
        """
        Look up a MITRE ATT&CK technique by ID (e.g. T1059, T1059.001).
        Returns tactic mapping, platforms, data sources, description, and detection guidance.
        :param technique_id: ATT&CK technique ID, e.g. 'T1059' or 'T1059.001'
        :return: Formatted technique details from local ATT&CK cache
        """
        technique_id = technique_id.strip().upper()

        try:
            objects = _load_attack_data(self.valves.stix_bundle_path)
        except FileNotFoundError as e:
            return str(e)
        except Exception as e:
            return f"Failed to load ATT&CK data: {str(e)}"

        match = None
        for obj in objects:
            if _get_ext_id(obj).upper() == technique_id:
                match = obj
                break

        if not match:
            return (
                f"No ATT&CK technique found for ID: {technique_id}. "
                f"Verify the ID at https://attack.mitre.org"
            )

        return self._format_technique(match, technique_id)

    def search_techniques(self, keyword: str) -> str:
        """
        Search MITRE ATT&CK techniques by keyword (e.g. 'phishing', 'credential dumping', 'lateral movement').
        Returns up to 5 matching techniques with IDs and tactic mappings.
        :param keyword: Search term to match against technique names and descriptions
        :return: List of matching techniques from local ATT&CK cache
        """
        keyword = keyword.strip().lower()

        try:
            objects = _load_attack_data(self.valves.stix_bundle_path)
        except FileNotFoundError as e:
            return str(e)
        except Exception as e:
            return f"Failed to load ATT&CK data: {str(e)}"

        matches = []
        for obj in objects:
            name = obj.get("name", "").lower()
            desc = obj.get("description", "").lower()

            if keyword in name or keyword in desc:
                ext_id = _get_ext_id(obj)
                tactics = _get_tactics(obj)
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
            url_id = m['id'].replace('.', '/')
            lines.append(f"**{m['id']} — {m['name']}**")
            lines.append(f"  Tactic(s): {tactics_str}")
            lines.append(f"  {m['description']}...")
            lines.append(f"  Reference: https://attack.mitre.org/techniques/{url_id}/\n")

        lines.append("Use lookup_technique('<ID>') for full details including detection guidance.")
        return "\n".join(lines)

    def _format_technique(self, obj: dict, technique_id: str) -> str:
        """Format a STIX attack-pattern object into a readable report."""
        name = obj.get("name", "Unknown")
        description = obj.get("description", "No description available.")

        # Many techniques (e.g. T1047) have an empty x_mitre_detection field.
        # Fall back to the technique description so the Detection section is
        # still useful rather than a bare "no guidance" line.
        detection = (obj.get("x_mitre_detection") or "").strip()
        detection_is_fallback = False
        if not detection:
            desc_fallback = (obj.get("description") or "").strip()
            if desc_fallback:
                detection = desc_fallback
                detection_is_fallback = True
            else:
                detection = "No detection guidance available."

        is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
        platforms = ", ".join(obj.get("x_mitre_platforms", [])) or "Unknown"
        data_sources = ", ".join(obj.get("x_mitre_data_sources", [])) or "None listed"
        tactics_str = ", ".join(_get_tactics(obj)) or "Unknown"

        url_id = technique_id.replace(".", "/")
        url = f"https://attack.mitre.org/techniques/{url_id}/"

        if len(description) > 800:
            description = description[:800].strip() + "... [truncated]"
        if len(detection) > 600:
            detection = detection[:600].strip() + "..."

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
            (
                "_ATT&CK lists no dedicated detection guidance for this "
                "technique; showing the technique description as a fallback._\n\n"
                + detection
            ) if detection_is_fallback else detection,
            "",
            f"**Reference:** {url}",
            "",
            "_Source: MITRE ATT&CK Enterprise Matrix v16 — local cache_",
        ]

        return "\n".join(lines)
