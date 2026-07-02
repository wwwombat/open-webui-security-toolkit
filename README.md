# Open WebUI Security Toolkit

A collection of custom tools, model presets, and configurations for building a cybersecurity-focused Open WebUI instance. Designed for security analysts, incident responders, and IT operations professionals who want to augment their workflows with locally-hosted AI backed by real-time threat intelligence.

## Overview

This toolkit extends [Open WebUI](https://github.com/open-webui/open-webui) with:

- **Custom Tools** that connect to security-relevant APIs (NVD, threat feeds, etc.) so your models can fetch live vulnerability and threat data during conversations
- **Model Presets** with system prompts tailored for cybersecurity analysis tasks like incident response, compliance mapping, and vulnerability assessment
- **Documentation** covering setup, configuration, and usage patterns

## Architecture

The toolkit is designed around a hybrid local/cloud inference model:

- **Local models** (via Ollama) handle routine tasks: drafting, formatting, quick triage, and general Q&A where speed and zero API cost matter
- **Cloud models** (e.g., Anthropic Claude) handle complex analytical work: multi-framework compliance mapping, incident investigation, nuanced vendor security questionnaire responses, and deep reasoning tasks

Both tiers share the same system prompts, knowledge bases, and tool bindings through Open WebUI's model preset system.

## Tools

| Tool | Type | Description |
|------|------|-------------|
| [NVD CVE Lookup](tools/nvd_cve_lookup.py) | Tool | Query NIST NVD for CVE details, CVSS scores, affected products, and references. Supports single CVE lookup and keyword search. |
| [Config Sanitizer](tools/config_sanitizer.py) | Filter | Inlet filter that scrubs sensitive data (passwords, pre-shared keys, hashes, SNMP communities, serial numbers, certificates, API keys) from firewall configs and infrastructure exports before they reach the LLM. Optimized for SonicWall SonicOS but broadly applicable. |
| [MITRE ATT&CK Mapper](tools/mitre_attck_mapper.py) | Tool | Maps observed techniques and indicators to ATT&CK framework tactics, techniques, and mitigations. Resolves detection guidance via ATT&CK's v14+ detection-strategy → analytic → data-component graph, with a description fallback as a last resort. Runs against a locally cached STIX bundle — no external API calls, no rate limits. |

### Planned Tools

- **Shodan Host Lookup** - Query Shodan for exposed services and known vulnerabilities on a given IP/host
- **AbuseIPDB Checker** - Check IP reputation and abuse reports
- **EPSS Score Lookup** - Fetch Exploit Prediction Scoring System probabilities for prioritization
  
## Model Presets

| Preset | Base Model | Use Case |
|--------|------------|----------|
| [Cyber Analyst](models/cyber-analyst.md) | Local (Ollama) | Routine security analysis, drafting, log triage |
| Cyber Analyst Pro | Cloud (Claude) | Complex incident analysis, compliance mapping, deep reasoning |

Both presets use the same system prompt and tool bindings -- the only difference is the underlying model engine.

## Quick Start

### Prerequisites

- [Open WebUI](https://docs.openwebui.com/) v0.9.x or later
- [Ollama](https://ollama.com/) with at least one model pulled
- (Optional) An Anthropic API key for the cloud-tier preset
- (Optional) An [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) for higher rate limits

### Installing a Tool

1. Open your Open WebUI instance and navigate to **Workspace > Tools**
2. Click **+ New Tool**
3. Copy the contents of the desired tool file (e.g., `tools/nvd_cve_lookup.py`) into the code editor
4. Click **Save**
5. (Optional) Click the gear icon to configure any API keys in the tool's Valves
6. Navigate to **Workspace > Models**, edit your model preset, and enable the tool in the **Tools** section

### MITRE ATT&CK Mapper Setup

This tool reads from a local STIX bundle rather than calling out to MITRE's servers, so it needs the enterprise ATT&CK dataset present on disk before it'll return results.

1. Download the current `enterprise-attack.json` STIX bundle from [MITRE/CTI](https://github.com/mitre/cti)
2. Place it at `<data_dir>/attack/enterprise-attack.json` on the host
3. Mount the parent data directory (not just the file) into the container via `docker-compose.yml`:
```yaml
   volumes:
     - /path/to/data:/path/to/data:ro
```
   A directory mount matters here, not a single-file mount — Open WebUI's tool-update workflow copies files through that same path, and a single-file bind mount also won't pick up atomic-rename updates to the bundle.
4. Restart the Open WebUI container to pick up the mount

### Installing a Model Preset

1. Navigate to **Workspace > Models** and click **+ New Model**
2. Set the **Name**, **Base Model**, and **Description**
3. Copy the system prompt from the desired preset file (e.g., `models/cyber-analyst.md`) into the **System Prompt** field
4. Enable the tools you want bound to this preset
5. Click **Save**

See [docs/setup-guide.md](docs/setup-guide.md) for detailed setup instructions.

## Security Considerations

- **No hardcoded secrets.** API keys are configured at runtime through Open WebUI's Valves system, never stored in code.
- **Config sanitization.** The Config Sanitizer filter scrubs credentials, hashes, keys, and other sensitive material from infrastructure exports before they reach the LLM. Always verify redaction output before sharing analysis results externally.
- **Tool execution.** Open WebUI tools execute Python on your server. Only install tools you've reviewed and trust.
- **Network exposure.** If your Open WebUI instance is network-accessible, restrict access appropriately. These tools make outbound API calls to public services (NVD, etc.).

## Contributing

Contributions welcome. If you build a security-relevant tool or model preset, open a PR.

### Repository setup

This repo ships git hooks in `.githooks/`. Git does not enable a repo's hooks
automatically on clone, so after cloning run this once to activate them:

```
git config core.hooksPath .githooks
```

The `commit-msg` hook strips `Co-Authored-By: Claude ...` trailers from commit
messages; other co-authors and trailers are preserved. Its behavior is covered
by a test script:

```
.githooks/test-commit-msg.sh
```

## License

MIT
