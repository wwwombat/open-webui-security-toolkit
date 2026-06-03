"""
title: NVD CVE Lookup
author: Anonymous
author_url: https://github.com/wwwombat
description: Query the NIST National Vulnerability Database (NVD) API 2.0 for CVE details including CVSS scores, descriptions, affected products, and references. Supports both single CVE lookup and keyword-based vulnerability search.
required_open_webui_version: 0.4.0
requirements: httpx
version: 1.0.0
licence: MIT
"""

import re
import json
from typing import Optional
from pydantic import BaseModel, Field
import httpx


class Tools:
    def __init__(self):
        """Initialize the NVD CVE Lookup Tool."""
        self.valves = self.Valves()

    class Valves(BaseModel):
        nvd_api_key: str = Field(
            "",
            description="NVD API key for higher rate limits. Get one free at https://nvd.nist.gov/developers/request-an-api-key (optional but recommended)",
        )
        request_timeout: int = Field(
            30,
            description="HTTP request timeout in seconds",
        )

    async def lookup_cve(self, cve_id: str) -> str:
        """
        Look up a specific CVE by its ID from the National Vulnerability Database.
        Returns CVSS scores, description, affected products, weakness types, and references.
        :param cve_id: The CVE identifier, e.g. CVE-2024-3400 or 2024-3400
        """
        # Normalize CVE ID format
        cve_id = cve_id.upper().strip()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
            return f"Invalid CVE ID format: {cve_id}. Expected format: CVE-YYYY-NNNN (e.g., CVE-2024-3400)"

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {"User-Agent": "OpenWebUI-NVD-Tool/1.0"}

        if self.valves.nvd_api_key:
            headers["apiKey"] = self.valves.nvd_api_key

        try:
            async with httpx.AsyncClient(timeout=self.valves.request_timeout, http2=False) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as e:
            return f"NVD API error: HTTP {e.response.status_code}"
        except httpx.RequestError as e:
            return f"Network error reaching NVD API: {e}"
        except Exception as e:
            return f"Unexpected error: {e}"

        if data.get("totalResults", 0) == 0:
            return f"{cve_id} was not found in the National Vulnerability Database."

        cve = data["vulnerabilities"][0]["cve"]
        return self._format_cve(cve)

    async def search_cves(
        self,
        keyword: str,
        max_results: int = 10,
        days_back: int = 365,
    ) -> str:
        """
        Search the National Vulnerability Database for CVEs matching a keyword or phrase.
        Useful for finding vulnerabilities related to a specific product, vendor, or technology.
        Returns results sorted by most recent first.
        :param keyword: Search term, e.g. 'SonicWall', 'Apache Log4j', 'Microsoft Exchange'
        :param max_results: Maximum number of results to return (1-20, default 10)
        :param days_back: How many days back to search (default 365, max 730)
        """
        from datetime import datetime, timedelta, timezone

        max_results = max(1, min(20, max_results))
        days_back = max(1, min(120, days_back))

        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days_back)

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000Z"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT00:00:00.000Z"),
        }
        headers = {"User-Agent": "OpenWebUI-NVD-Tool/1.0"}

        if self.valves.nvd_api_key:
            headers["apiKey"] = self.valves.nvd_api_key

        try:
            async with httpx.AsyncClient(timeout=self.valves.request_timeout, http2=False) as client:
                response = await client.get(url, params=params, headers=headers)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as e:
            return f"NVD API error: HTTP {e.response.status_code}"
        except httpx.RequestError as e:
            return f"Network error reaching NVD API: {e}"
        except Exception as e:
            return f"Unexpected error: {e}"

        total = data.get("totalResults", 0)
        if total == 0:
            return f"No CVEs found matching '{keyword}'."

        results = []
        results.append(
            f"Found {total} total CVEs matching '{keyword}' (showing up to {max_results}):\n"
        )

        results.append(
            "Note: Results limited to last " + str(days_back) + " days (NVD API max is 120 days). "
            "Date range: " + start_date.strftime("%Y-%m-%d") + " to " + end_date.strftime("%Y-%m-%d") + ". "
            "For older CVEs, use lookup_cve with a specific CVE ID or visit https://nvd.nist.gov directly.\n"
        )

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "Unknown")
            published = cve.get("published", "Unknown")[:10]

            # Get description
            desc = "No description available."
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", desc)
                    break

            # Get CVSS score
            score_str = self._extract_cvss_summary(cve)

            # Truncate description for search results
            if len(desc) > 300:
                desc = desc[:297] + "..."

            results.append(f"[{cve_id}] ({published}) {score_str}")
            results.append(f"  {desc}\n")

        return "\n".join(results)

    def _extract_cvss_summary(self, cve: dict) -> str:
        """Extract the highest-priority CVSS score as a summary string."""
        metrics = cve.get("metrics", {})

        # Try CVSS 4.0 first, then 3.1, then 3.0, then 2.0
        for version_key, score_field, version_label in [
            ("cvssMetricV40", "cvssData", "CVSS 4.0"),
            ("cvssMetricV31", "cvssData", "CVSS 3.1"),
            ("cvssMetricV30", "cvssData", "CVSS 3.0"),
            ("cvssMetricV2", "cvssData", "CVSS 2.0"),
        ]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                m = metric_list[0]
                cvss = m.get(score_field, {})
                base_score = cvss.get("baseScore", "N/A")
                severity = cvss.get("baseSeverity", m.get("baseSeverity", "N/A"))
                return f"{version_label}: {base_score} ({severity})"

        return "CVSS: Not yet scored"

    def _format_cve(self, cve: dict) -> str:
        """Format a full CVE record into a readable string."""
        cve_id = cve.get("id", "Unknown")
        published = cve.get("published", "Unknown")
        modified = cve.get("lastModified", "Unknown")
        status = cve.get("vulnStatus", "Unknown")

        # Description
        desc = "No description available."
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", desc)
                break

        # CVSS scores (all available versions)
        scores = []
        metrics = cve.get("metrics", {})
        for version_key, score_field, version_label in [
            ("cvssMetricV40", "cvssData", "CVSS 4.0"),
            ("cvssMetricV31", "cvssData", "CVSS 3.1"),
            ("cvssMetricV30", "cvssData", "CVSS 3.0"),
            ("cvssMetricV2", "cvssData", "CVSS 2.0"),
        ]:
            for m in metrics.get(version_key, []):
                cvss = m.get(score_field, {})
                base_score = cvss.get("baseScore", "N/A")
                severity = cvss.get("baseSeverity", m.get("baseSeverity", "N/A"))
                vector = cvss.get("vectorString", "N/A")
                source = m.get("source", "Unknown")
                exploitability = m.get("exploitabilityScore", "N/A")
                impact = m.get("impactScore", "N/A")
                scores.append(
                    f"  {version_label} ({source}): {base_score} ({severity})\n"
                    f"    Vector: {vector}\n"
                    f"    Exploitability: {exploitability} | Impact: {impact}"
                )

        scores_str = "\n".join(scores) if scores else "  Not yet scored"

        # Weaknesses (CWE)
        weaknesses = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value", "")
                if val and val != "NVD-CWE-noinfo" and val != "NVD-CWE-Other":
                    weaknesses.append(val)
        weaknesses_str = ", ".join(weaknesses) if weaknesses else "Not classified"

        # Affected configurations / CPE matches
        affected = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable", False):
                        cpe = match.get("criteria", "")
                        # Parse CPE string into readable format
                        parts = cpe.split(":")
                        if len(parts) >= 6:
                            vendor = parts[3].replace("_", " ").title()
                            product = parts[4].replace("_", " ").title()
                            version_start = match.get("versionStartIncluding", "")
                            version_end = match.get(
                                "versionEndExcluding",
                                match.get("versionEndIncluding", ""),
                            )
                            version_info = parts[5] if parts[5] != "*" else ""
                            if version_start and version_end:
                                affected.append(
                                    f"  {vendor} {product} ({version_start} to {version_end})"
                                )
                            elif version_info:
                                affected.append(f"  {vendor} {product} {version_info}")
                            else:
                                affected.append(f"  {vendor} {product} (all versions)")

        affected_str = (
            "\n".join(affected[:15])
            if affected
            else "  Not specified / awaiting analysis"
        )

        # References
        refs = []
        for r in cve.get("references", []):
            url = r.get("url", "")
            tags = ", ".join(r.get("tags", []))
            tag_str = f" [{tags}]" if tags else ""
            refs.append(f"  {url}{tag_str}")
        refs_str = "\n".join(refs[:10]) if refs else "  None available"

        return (
            f"=== {cve_id} ===\n"
            f"Status: {status}\n"
            f"Published: {published}\n"
            f"Last Modified: {modified}\n\n"
            f"DESCRIPTION:\n{desc}\n\n"
            f"CVSS SCORES:\n{scores_str}\n\n"
            f"WEAKNESSES: {weaknesses_str}\n\n"
            f"AFFECTED PRODUCTS:\n{affected_str}\n\n"
            f"REFERENCES:\n{refs_str}\n\n"
            f"NVD Link: https://nvd.nist.gov/vuln/detail/{cve_id}"
        )

