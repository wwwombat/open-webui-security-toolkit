# Model Stack

Documents the current Ollama model inventory on wwwombat-ai, the rationale behind each selection, and how they map to workspaces in Open WebUI.

## Current Models

| Model | Tag | Size | Role |
|---|---|---|---|
| gemma4 | e4b | ~5GB | Daily driver — general analysis, triage, drafting |
| Hermes-4 | 14B-GGUF:Q5_K_M | ~10GB | Security research — uncensored, coursework assistant |
| nomic-embed-text | latest | ~274MB | RAG embeddings — Knowledge collection retrieval |

---

### gemma4:e4b

**Role:** Daily driver for the Cyber Analyst workspace.

**Why this model:** Strong instruction following, fast inference on 12GB VRAM, good reasoning quality for log triage and general security Q&A. The `e4b` quantization hits a good balance between output quality and VRAM headroom — the full model would spill into system RAM on this hardware.

**Workspace:** Cyber Analyst

**Best for:**
- Log triage and summarization
- CVE analysis (paired with NVD tool)
- Drafting incident documentation
- General security Q&A

---

### Hermes-4-14B-GGUF:Q5_K_M

**Role:** Security research and coursework assistant.

**Why this model:** Hermes 3 is an uncensored fine-tune that follows system prompt instructions without alignment refusals. This is the correct model for penetration testing research, offensive security coursework, and red team conceptual work where a standard aligned model would hedge or refuse. Network isolation (vmbr1, planned) is the architectural safety layer — not the model.

**Workspace:** Coursework Assistant

**Key characteristic:** Unlike gemma4, Hermes 3 reliably follows strict formatting constraints in the system prompt. gemma4 was observed ignoring formatting rules during testing; Hermes 3 did not.

**Best for:**
- Penetration testing coursework (Pen Testing I/II)
- Offensive security research and threat modeling
- Red team concept development
- Adversarial model behavior research

**Deployment note:** Keep on local infrastructure only. Not routed through LiteLLM to cloud. Sensitive research stays on-premises.

---

### nomic-embed-text

**Role:** RAG embedding engine.

**Why this model:** Dedicated embedding model for Knowledge collection retrieval. Keeps vectorization workload separate from inference models. All six Knowledge collections in Open WebUI use nomic-embed-text for chunk embedding.

**Not used for:** Inference or chat. Embedding only.

---

## Pruned Models (Removed)

The following models were removed during the May 2026 optimization pass to reclaim VRAM and reduce model management overhead:

| Model | Reason for Removal |
|---|---|
| llama3:8b | Superseded by gemma4:e4b for general tasks |
| deepseek-coder:6.7b | Functionality covered by gemma4 for current use cases |
| dolphin3:latest | Retained for red team research sessions only — not a persistent stack member |
| mistral:7b | Redundant with hermes3 at similar size |

> **Note on Dolphin:** dolphin3 was evaluated for red team research use (see `docs/research/dolphin-red-team-evaluation.md`). It is not a permanent stack member but can be pulled for specific research sessions. `ollama pull dolphin3:latest` when needed, `ollama rm dolphin3:latest` when done.

---

## Workspace → Model Mapping

| Workspace | Base Model | Tools Enabled | Purpose |
|---|---|---|---|
| Cyber Analyst | gemma4:e4b | NVD CVE Lookup | Routine security analysis, triage |
| Cyber Analyst Pro | Claude Sonnet (via API) | NVD CVE Lookup, Web Search | Deep reasoning, compliance mapping |
| Coursework Assistant | hermes3:8b | None | Security coursework, research |

---

## Hardware Context

- **GPU:** RTX 3080 Ti 12GB VRAM
- **RAM:** 32GB system / 24GB allocated to wwwombat-ai VM
- **Swap:** Expanded from 4GB to 12GB to handle model spill under load

The 12GB VRAM ceiling is the primary constraint on model selection. Models above ~8B parameters at 4-bit quantization risk spilling into system RAM, which causes a significant inference speed penalty (PCIe bandwidth vs. GPU bandwidth). Current stack is sized to keep all active inference in VRAM.

**GPU upgrade under consideration:** RTX 5070 Ti (16GB GDDR7) would meaningfully expand the model size ceiling. RTX 5070 (12GB) assessed as a lateral move — same VRAM ceiling, not worth the cost.
