"""
title: MITRE ATT&CK Mapper
author: wwwombat
version: 1.3.0
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

CACHE_PATH = "/home/wwwombat/data/attack/enterprise-attack.json"


@lru_cache(maxsize=1)
def _load_bundle() -> dict:
    """Load STIX bundle once and return indexed lookup structures."""
    if not os.path.exists(CACHE_PATH):
        raise FileNotFoundError(
            f"ATT&CK bundle not found at {CACHE_PATH}. "
            f"Run: curl -L https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json "
            f"-o {CACHE_PATH}"
        )
    with open(CACHE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])
    obj_by_id = {o["id"]: o for o in objects}

    techniques = [
        o for o in objects
        if o.get("type") == "attack-pattern"
        and not o.get("revoked")
        and not o.get("x_mitre_deprecated")
    ]

    # Build index: technique STIX id -> list of detection-strategy objects
    # v14+ replaced x_mitre_detection and x_mitre_data_sources with a graph:
    #   detection-strategy --(detects)--> attack-pattern
    #   detection-strategy --x_mitre_analytic_refs--> analytic
    #   analytic --x_mitre_log_source_references.x_mitre_data_component_ref--> data-component
    detection_index: dict[str, list] = {}
    for o in objects:
        if (
            o.get("type") == "relationship"
            and o.get("relationship_type") == "detects"
            and not o.get("revoked", False)
            and not o.get("x_mitre_deprecated", False)
        ):
            src = obj_by_id.get(o.get("source_ref", ""))
            target_id = o.get("target_ref", "")
            if src and src.get("type") == "x-mitre-detection-strategy":
                detection_index.setdefault(target_id, []).append(src)

    return {
        "techniques": techniques,
        "obj_by_id": obj_by_id,
        "detection_index": detection_index,
    }


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


def _get_data_sources(technique_stix_id: str) -> list[str]:
    """Return sorted unique data component names for a technique via the v14+ graph."""
    bundle = _load_bundle()
    obj_by_id = bundle["obj_by_id"]
    detection_index = bundle["detection_index"]

    component_names: set[str] = set()
    for strategy in detection_index.get(technique_stix_id, []):
        for analytic_ref in strategy.get("x_mitre_analytic_refs", []):
            analytic = obj_by_id.get(analytic_ref, {})
            for log_src in analytic.get("x_mitre_log_source_references", []):
                comp = obj_by_id.get(log_src.get("x_mitre_data_component_ref", ""), {})
                if comp.get("name"):
                    component_names.add(comp["name"])

    return sorted(component_names)


def _get_detection_text(technique_stix_id: str, description: str) -> str:
    """Build detection guidance from v14+ detection strategies and analytics."""
    bundle = _load_bundle()
    obj_by_id = bundle["obj_by_id"]
    strategies = bundle["detection_index"].get(technique_stix_id, [])

    if not strategies:
        return (
            "[Detection field removed in ATT&CK v14+ STIX bundle — "
            "see reference URL for current detection guidance]\n\n"
            + description
        )

    lines = []
    for strategy in strategies:
        lines.append(f"**{strategy.get('name', 'Detection Strategy')}**")
        for analytic_ref in strategy.get("x_mitre_analytic_refs", []):
            analytic = obj_by_id.get(analytic_ref, {})
            if not analytic or analytic.get("x_mitre_deprecated"):
                continue
            platforms = ", ".join(analytic.get("x_mitre_platforms", []))
            desc = analytic.get("description", "")
            log_src_parts = [
                f"{ls.get('name', '')} ({ls.get('channel', '')})"
                for ls in analytic.get("x_mitre_log_source_references", [])
                if ls.get("name")
            ]
            entry = f"- {desc}"
            if platforms:
                entry += f" _[{platforms}]_"
            lines.append(entry)
            if log_src_parts:
                lines.append(f"  _Log sources: {', '.join(log_src_parts)}_")

    return "\n".join(lines)


class Tools:
    class Valves(BaseModel):
        pass

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
            techniques = _load_bundle()["techniques"]
        except FileNotFoundError as e:
            return str(e)
        except Exception as e:
            return f"Failed to load ATT&CK data: {str(e)}"

        match = None
        for obj in techniques:
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
            techniques = _load_bundle()["techniques"]
        except FileNotFoundError as e:
            return str(e)
        except Exception as e:
            return f"Failed to load ATT&CK data: {str(e)}"

        matches = []
        for obj in techniques:
            name = obj.get("name", "").lower()
            desc = obj.get("description", "").lower()

            if keyword in name or keyword in desc:
                ext_id = _get_ext_id(obj)
                tactics = _get_tactics(obj)
                matches.append(
                    {
                        "id": ext_id,
                        "name": obj.get("name", "Unknown"),
                        "tactics": tactics,
                        "description": obj.get("description", "")[:200].strip(),
                    }
                )

            if len(matches) >= 5:
                break

        if not matches:
            return f"No ATT&CK techniques found matching keyword: '{keyword}'"

        lines = [f"ATT&CK techniques matching '{keyword}':\n"]
        for m in matches:
            tactics_str = ", ".join(m["tactics"]) if m["tactics"] else "Unknown"
            url_id = m["id"].replace(".", "/")
            lines.append(f"**{m['id']} — {m['name']}**")
            lines.append(f"  Tactic(s): {tactics_str}")
            lines.append(f"  {m['description']}...")
            lines.append(
                f"  Reference: https://attack.mitre.org/techniques/{url_id}/\n"
            )

        lines.append(
            "Use lookup_technique('<ID>') for full details including detection guidance."
        )
        return "\n".join(lines)

    def _format_technique(self, obj: dict, technique_id: str) -> str:
        """Format a STIX attack-pattern object into a readable report."""
        name = obj.get("name", "Unknown")
        description = obj.get("description", "No description available.")
        is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
        platforms = ", ".join(obj.get("x_mitre_platforms", [])) or "Unknown"
        tactics_str = ", ".join(_get_tactics(obj)) or "Unknown"

        # v14+: resolve data sources and detection via the detection-strategy graph
        data_source_names = _get_data_sources(obj["id"])
        data_sources = ", ".join(data_source_names) if data_source_names else "None listed"
        detection = _get_detection_text(obj["id"], description)

        url_id = technique_id.replace(".", "/")
        url = f"https://attack.mitre.org/techniques/{url_id}/"

        if len(description) > 800:
            description = description[:800].strip() + "... [truncated]"
        if len(detection) > 1500:
            detection = detection[:1500].strip() + "... [truncated]"

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
            detection,
            "",
            f"**Reference:** {url}",
            "",
            "_Source: MITRE ATT&CK Enterprise Matrix (local cache)_",
        ]

        return "\n".join(lines)
