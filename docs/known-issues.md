# Known Issues

## OWUI Knowledge Collection Ingest: ChromaDB `metadatas` type error

**Status:** Patched (2026-06-13) — most file types now ingest correctly
**Issue ref:** open-webui/open-webui#24974

### What's happening

Open WebUI's knowledge ingestion pipeline passes metadata to ChromaDB containing Python
types that ChromaDB doesn't accept (`None`, nested dicts). This caused a `400: argument
'metadatas': Cannot convert Python object to MetadataValue` error for nearly all file
types, so files were uploaded but never actually landed in the RAG knowledge base.

The upstream file sync was working fine — files arrived on schedule. The
failure was in the OWUI → ChromaDB step, not the file sync.

### Current state after patch

6 of 10 files in the test collection now ingest successfully. The 4 remaining
failures are `empty content` errors for files OWUI genuinely can't extract text from:
- Blank test PDFs
- Scanned PDFs without an OCR path triggered (word count ≥ 10 so OCR skipped, but
  OWUI's own extractor also fails — likely corrupt or image-only with no text layer)
- Oversized textbook (`vdoc.pub_computer-internet-security...pdf`)

These are not metadata type errors and won't be fixed by this patch.

### The patch

Two files were modified inside the running container:

| File | Fix |
|---|---|
| `/app/backend/open_webui/routers/retrieval.py` | `embedding_config` nested dict → `json.dumps()`; metadata list wrapped with `process_metadata()` |
| `/app/backend/open_webui/retrieval/vector/utils.py` | `process_metadata()` fixed to skip `None` and correctly type-gate all values to ChromaDB primitives |

Patched files are saved at `~/ai-stack/patches/`. Full diff and reapplication procedure
are documented in `~/ai-stack/patches/README.md`.

**Important:** The patch lives in the container's writable layer only. It is lost if the
container is recreated (image update, `docker compose up -d --force-recreate`, etc.).
Reapplication is a two-command copy + restart — see `~/ai-stack/patches/README.md`.

A volume-mount fix in `docker-compose.yml` is tracked as a TODO to make the patch
persistent automatically.

### The `owui_ingest.py` script

The ingest script at `~/scripts/owui_ingest.py` (symlinked into this repo at
`scripts/owui_ingest.py`) was also updated during this session:

- **Skips Word temp files** (`~$*.docx`) — Word creates these lock files when a document
  is open; they're zero-byte and were previously causing spurious upload attempts
- **Tracks failed files in state** — `~/logs/owui_ingest_state.json` now records
  `{"status": "failed", "hash": "..."}` for files that fail, so the cron job doesn't
  retry them every 30 minutes. To force a retry after a fix, delete the relevant entry
  from the state file.

---

## Hermes-4-14B CUDA compatibility

**Status:** Pending
See `model-stack.md` — Hermes-4-14B-GGUF is blocked on NVIDIA Driver 580 / CUDA 13.0
compatibility with Ollama. Coursework Assistant workspace is running
`qwen2.5:14b-instruct-q4_K_M` as a temporary substitute.
