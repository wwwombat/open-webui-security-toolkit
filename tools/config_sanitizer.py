"""
title: Security Config Sanitizer
author: wwwombat
author_url: https://github.com/wwwombat
description: Inlet filter that scrubs sensitive data from firewall configurations and other infrastructure exports before they reach the LLM. Targets passwords, pre-shared keys, SNMP communities, hashes, certificates, serial numbers, and other credential material. Optimized for SonicWall SonicOS configs but broadly applicable to network device exports.
required_open_webui_version: 0.4.0
version: 2.0.0
licence: MIT
"""

import re
import logging
from typing import Dict, Any, List, Tuple
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)


class Filter:
    class Valves(BaseModel):
        enabled: bool = Field(
            True,
            description="Enable or disable the sanitizer globally",
        )
        redact_public_ips: bool = Field(
            False,
            description="Redact public (non-RFC1918) IPv4 addresses. Disabled by default to preserve useful context for analysis.",
        )
        log_redactions: bool = Field(
            True,
            description="Log a summary of redaction counts (no sensitive data is logged)",
        )

    def __init__(self):
        self.name = "Security Config Sanitizer"
        self.valves = self.Valves()
        self._patterns = self._compile_patterns()

    def _compile_patterns(self) -> List[Tuple[re.Pattern, str, str]]:
        """
        Pre-compile all regex patterns once at initialization.
        Returns a list of (compiled_pattern, replacement_string, label) tuples.
        """
        raw_patterns = [
            # ── Passwords, secrets, and pre-shared keys ──
            # Matches: password "value", secret value, preshared-key 0x..., shared-key "quoted value"
            (
                r'(?i)(password|passwd|secret|shared-secret|preshared-key|shared-key|pre-shared-key|auth-password|priv-password)\s*[:=]?\s*("([^"]+)"|\S+)',
                r"\1 [REDACTED_SECRET]",
                "password/secret",
            ),
            # ── RADIUS and TACACS+ shared secrets ──
            (
                r"(?i)(radius-server|tacacs-server)\s+.*?(secret|key)\s+\d*\s*(\S+)",
                r"\1 [REDACTED_AUTH_SERVER] \2 [REDACTED_SECRET]",
                "radius/tacacs secret",
            ),
            # ── SNMP community strings ──
            (
                r"(?i)(snmp-server\s+community)\s+(\S+)",
                r"\1 [REDACTED_SNMP_COMMUNITY]",
                "snmp community",
            ),
            # SNMPv3 auth and privacy passwords
            (
                r"(?i)(snmp-server\s+user\s+\S+\s+\S+\s+v3\s+(?:auth|priv)\s+\S+)\s+(\S+)",
                r"\1 [REDACTED_SNMPV3_SECRET]",
                "snmpv3 secret",
            ),
            # ── LDAP bind passwords ──
            (
                r"(?i)(ldap-bind-password|bind-password|bindpw)\s*[:=]?\s*(\S+)",
                r"\1 [REDACTED_LDAP_BIND_PW]",
                "ldap bind password",
            ),
            # ── API keys and tokens ──
            (
                r"(?i)(api[_-]?key|token|bearer|authorization)\s*[:=]\s*[\"']?([A-Za-z0-9\-_.~+/]{20,})[\"']?",
                r"\1 [REDACTED_API_KEY]",
                "api key/token",
            ),
            # ── Cryptographic hashes (MD5, SHA-1, SHA-256, SHA-512, NTLM) ──
            # MD5 (32 hex chars)
            (
                r"(?<![A-Fa-f0-9])[a-fA-F0-9]{32}(?![A-Fa-f0-9])",
                "[REDACTED_HASH_MD5]",
                "md5 hash",
            ),
            # SHA-1 (40 hex chars)
            (
                r"(?<![A-Fa-f0-9])[a-fA-F0-9]{40}(?![A-Fa-f0-9])",
                "[REDACTED_HASH_SHA1]",
                "sha1 hash",
            ),
            # SHA-256 (64 hex chars)
            (
                r"(?<![A-Fa-f0-9])[a-fA-F0-9]{64}(?![A-Fa-f0-9])",
                "[REDACTED_HASH_SHA256]",
                "sha256 hash",
            ),
            # ── Private keys and certificates ──
            (
                r"(?s)(-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----).+?(-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----)",
                r"\1\n[REDACTED_PRIVATE_KEY]\n\2",
                "private key",
            ),
            # ── SonicWall-specific serial number format ──
            # SonicWall serials: 12 or 16 uppercase hex, typically preceded by a label
            (
                r"(?i)(serial[_\s-]?(?:number)?|sn)\s*[:=]?\s*([0-9A-F]{12,16})\b",
                r"\1 [REDACTED_SERIAL]",
                "serial number",
            ),
            # ── Base64-encoded blobs (likely encrypted passwords in config exports) ──
            # Targets long base64 strings that appear after key-value assignments
            (
                r'(?i)(encrypted|enc|cipher|hash)\s*[:=]\s*"?([A-Za-z0-9+/]{40,}={0,2})"?',
                r"\1 [REDACTED_ENCRYPTED_BLOB]",
                "encrypted blob",
            ),
            # ── Email addresses (may indicate admin accounts) ──
            (
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "[REDACTED_EMAIL]",
                "email address",
            ),
        ]

        compiled = []
        for pattern, replacement, label in raw_patterns:
            try:
                compiled.append((re.compile(pattern), replacement, label))
            except re.error as e:
                log.warning(f"Failed to compile pattern '{label}': {e}")

        return compiled

    def _build_ip_pattern(self) -> Tuple[re.Pattern, str, str]:
        """
        Build a pattern that matches public IPv4 addresses while preserving
        RFC1918 private ranges (10.x, 172.16-31.x, 192.168.x) and loopback.
        """
        pattern = (
            r"\b"
            r"(?!10\.)"
            r"(?!127\.)"
            r"(?!172\.(?:1[6-9]|2[0-9]|3[01])\.)"
            r"(?!192\.168\.)"
            r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
            r"\b"
        )
        return (re.compile(pattern), "[REDACTED_PUBLIC_IP]", "public ip")

    def _scrub(self, text: str) -> Tuple[str, Dict[str, int]]:
        """
        Apply all sanitization patterns to the input text.
        Returns the scrubbed text and a dict of redaction counts by category.
        """
        counts: Dict[str, int] = {}

        for compiled_pattern, replacement, label in self._patterns:
            text, n = compiled_pattern.subn(replacement, text)
            if n > 0:
                counts[label] = counts.get(label, 0) + n

        # Conditionally apply public IP redaction
        if self.valves.redact_public_ips:
            ip_pattern, ip_replacement, ip_label = self._build_ip_pattern()
            text, n = ip_pattern.subn(ip_replacement, text)
            if n > 0:
                counts[ip_label] = counts.get(ip_label, 0) + n

        return text, counts

    async def inlet(
        self, body: Dict[str, Any], __user__: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Intercepts the prompt payload BEFORE it reaches the LLM.
        Scrubs sensitive data from all message content strings.
        """
        if not self.valves.enabled:
            return body

        if "messages" not in body:
            return body

        total_counts: Dict[str, int] = {}

        for message in body["messages"]:
            if "content" not in message or not isinstance(message["content"], str):
                continue

            scrubbed_text, counts = self._scrub(message["content"])
            message["content"] = scrubbed_text

            for label, count in counts.items():
                total_counts[label] = total_counts.get(label, 0) + count

        if total_counts and self.valves.log_redactions:
            summary = ", ".join(f"{label}: {count}" for label, count in total_counts.items())
            log.info(f"[Security Sanitizer] Redactions applied: {summary}")

        return body
