# Knowledge Infrastructure

Documents the RAG (Retrieval-Augmented Generation) pipeline on wwwombat-ai — how files get from FLOKI into Open WebUI Knowledge collections, and how those collections are configured.

## Architecture Overview

```
FLOKI (Windows, 10.20.1.10)
  └── NTFS Share (/floki-school)
        │
        │  [Stage 1: cron rsync — automated]
        ▼
wwwombat-ai: /mnt/floki-school (CIFS mount)
        │
        │  [Stage 2: ingest.py — manual trigger]
        ▼
Open WebUI Knowledge Collections
  └── Embedded via nomic-embed-text
```

The pipeline is **two-stage and currently semi-automated.** Stage 1 (rsync) runs on a cron schedule. Stage 2 (ingestion into Open WebUI) requires a manual trigger. Full end-to-end automation (phase two) is not yet wired — see Outstanding Work below.

---

## Stage 1: CIFS Mount & rsync

FLOKI's coursework share is mounted at `/mnt/floki-school` on wwwombat-ai via CIFS. The mount is persistent across reboots via `/etc/fstab`.

A cron job on wwwombat-ai rsyncs new and updated files from the CIFS mount to a local staging directory, decoupling the ingestion process from the live network share.

---

## Stage 2: Ingestion Script

**Script:** `~/ai-stack/knowledge-ingest/ingest.py`

Calls the Open WebUI API to embed documents into Knowledge collections using nomic-embed-text. The script is **idempotent** — re-running it against already-ingested files does not create duplicates.

**Trigger:** Manual (`python3 ingest.py`) after significant file additions or at the end of a semester when new coursework arrives.

---

## Knowledge Collections

Six collections are currently active, organized by course and semester:

| Collection | Contents | File Count (approx.) |
|---|---|---|
| Penetration Testing I | Course materials, labs, notes | — |
| Penetration Testing II | Course materials, labs, notes | — |
| Network Security | Course materials | — |
| Digital Forensics | Course materials | — |
| Security Reference Library | NIST/MITRE framework PDFs | 5 |
| Infrastructure Reference | wwwombat deployment docs | 1 |

**Total ingested:** 245 files across 6 collections (as of May 2026)

### Security Reference Library Contents

| Document | Source |
|---|---|
| NIST CSF 2.0 | NIST |
| NIST SP 800-53 Rev 5 | NIST |
| NIST SP 800-171 Rev 3 | NIST |
| NIST SP 800-61 Rev 2 | NIST |
| MITRE ATT&CK Design and Philosophy | MITRE |

---

## RAG Configuration

Configured in Open WebUI under Admin > Settings > RAG:

| Parameter | Value | Rationale |
|---|---|---|
| Embedding Model | nomic-embed-text | Dedicated local embedding, no external API calls |
| Top K | 10 | Retrieves 10 chunks per query for broader coverage |
| Chunk Overlap | 200 tokens | Reduces context fragmentation at chunk boundaries |

### Known Chunking Issue

Markdown files with heavy header structure (multiple `##` / `###` levels) chunk awkwardly under the current settings. Headers can land at the end of one chunk and their content at the start of the next, degrading retrieval quality. **Prose-format documents retrieve better than heavily structured ones.**

**Planned fix:** RAG re-chunking pass — restructure problematic documents into prose format before re-ingestion. Flagged for a future session.

---

## File Naming Convention

The tilde (`~`) prefix on filenames (e.g., `~Final_Report.docx`) is a personal convention that sorts files to the top of Windows Explorer's detailed view. These are **final versions**, not drafts or temporary files. The ingestion script handles tilde-prefixed files normally.

---

## Outstanding Work

### Phase Two: Full End-to-End Automation

Currently the rsync and ingestion stages are decoupled. Full automation requires wiring them together via one of:

- **Cron approach:** Add a second cron job that runs `ingest.py` after rsync completes
- **inotifywait approach:** File watcher triggers ingestion immediately when new files land in the staging directory

This is logged on the project roadmap as a future phase. Manual trigger is acceptable for current coursework volume.

### RAG Re-chunking

Existing heavily-structured markdown files in the coursework collections may need to be re-formatted and re-ingested to improve retrieval fidelity. Lower priority until the collections grow large enough that retrieval quality degrades noticeably.
