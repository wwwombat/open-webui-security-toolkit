# Setup Guide

This guide walks through setting up a cybersecurity-focused Open WebUI instance from scratch using a hybrid local/cloud architecture.

## Getting the Toolkit

Clone this repository, then enable its git hooks:

```bash
git clone https://github.com/wwwombat/open-webui-security-toolkit.git
cd open-webui-security-toolkit
git config core.hooksPath .githooks
```

Git does not activate a repository's hooks automatically on clone, so the
`core.hooksPath` step above is required (run it once per clone). It enables the
`commit-msg` hook in `.githooks/`, which strips `Co-Authored-By: Claude ...`
trailers from commit messages while preserving human co-authors.

## Prerequisites

### Hardware

For GPU-accelerated local inference, a system with:
- Modern CPU (Ryzen 5000/7000 series or Intel 12th gen+)
- 32GB+ RAM
- NVIDIA GPU with 8GB+ VRAM (RTX 3070 or better recommended)
- SSD storage for model files (models range from 4-40GB each)

### Software

- Docker and Docker Compose (recommended) or Python 3.11+
- [Ollama](https://ollama.com/) for local model serving
- NVIDIA Container Toolkit (for GPU passthrough in Docker)

## Step 1: Install Ollama and Pull Models

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull recommended models for cybersecurity work
ollama pull dolphin-llama3          # 8B, uncensored - good for security analysis
ollama pull nomic-embed-text        # Embedding model for RAG/Knowledge bases
ollama pull qwen2.5:14b-instruct-q4_K_M  # 14B, strong reasoning (optional, needs ~10GB VRAM)
```

### Model Selection by VRAM Budget

| VRAM | Recommended Model | Notes |
|------|-------------------|-------|
| 8GB | dolphin-llama3 (8B) | Good baseline, uncensored for security topics |
| 10-12GB | qwen2.5:14b-instruct-q4_K_M | Noticeable quality jump for structured analysis |
| 16-24GB | qwen2.5:32b-instruct-q4_K_M | Strong analytical capability, approaches cloud quality |
| CPU-only | llama3:8b | Slower but functional for simple tasks |

## Step 2: Install Open WebUI

### Docker (Recommended)

```bash
docker run -d \
  --name open-webui \
  --network=host \
  -v open-webui:/app/backend/data \
  -e OLLAMA_BASE_URL=http://localhost:11434 \
  --restart always \
  ghcr.io/open-webui/open-webui:main
```

Access at `http://localhost:8080`. The first user to sign up becomes the admin.

### Pip Install (Alternative)

```bash
pip install open-webui
open-webui serve
```

## Step 3: Add Cloud Model Provider (Optional)

For the hybrid architecture, add Anthropic (or another cloud provider) as an additional connection:

1. Go to **Admin Panel > Settings > Connections**
2. Under the OpenAI section, click **+ Add Connection**
3. Enter the API Base URL: `https://api.anthropic.com/v1`
4. Enter your API key
5. Click **Save**

Open WebUI auto-detects the Anthropic endpoint and fetches available Claude models.

## Step 4: Install Tools

1. Go to **Workspace > Tools**
2. Click **+ New Tool**
3. Copy the contents of a tool file from this repo's `tools/` directory into the editor
4. Click **Save**
5. Click the gear icon next to the tool to configure API keys via Valves

### Tool-Specific Configuration

#### NVD CVE Lookup

- **nvd_api_key**: Optional but recommended. Get a free key at https://nvd.nist.gov/developers/request-an-api-key
  - Without key: 5 requests per 30 seconds
  - With key: 50 requests per 30 seconds

## Step 5: Create Model Presets

### Cyber Analyst (Local)

1. Go to **Workspace > Models** and click **+ New Model**
2. **Name**: Cyber Analyst
3. **Base Model**: Select your local Ollama model (e.g., dolphin-llama3)
4. **Description**: Cybersecurity analysis, incident response, and threat assessment
5. **System Prompt**: Copy from `models/cyber-analyst.md`
6. Enable capabilities: Vision, Web Search, Code Interpreter
7. Under **Tools**, check the NVD CVE Lookup tool
8. Click **Save**

### Cyber Analyst Pro (Cloud)

1. Repeat the above steps
2. **Name**: Cyber Analyst Pro
3. **Base Model**: Select a Claude model from your Anthropic connection
4. Use the same system prompt, tools, and capability settings
5. Click **Save**

## Step 6: Create Knowledge Bases (Optional)

1. Go to **Workspace > Knowledge**
2. Click **+ New Collection**
3. Name it (e.g., "Security Documentation")
4. Upload relevant documents (compliance reports, policies, standards, playbooks)
5. Go back to **Workspace > Models**, edit each Cyber Analyst preset, and bind the knowledge collection under the **Knowledge** section

## Usage Tips

### Choosing Local vs. Cloud

Use the **local** Cyber Analyst preset for:
- Drafting routine communications and reports
- Quick CVE lookups and basic triage
- Formatting and structuring documents
- General security Q&A

Use the **cloud** Cyber Analyst Pro preset for:
- Complex incident analysis requiring chain-of-thought reasoning
- Multi-framework compliance mapping (e.g., NIST CSF + SOC 2 + PCI DSS simultaneously)
- Nuanced vendor security questionnaire responses
- Correlating attack chains across multiple log sources
- Any task where the local model's output quality isn't sufficient

### Switching Models Mid-Conversation

Open WebUI lets you change models without losing context. Start with the local preset, and if you need more analytical depth, switch to the Pro variant from the model dropdown at the top of the chat.
