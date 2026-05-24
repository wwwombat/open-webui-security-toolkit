# Infrastructure Reference Configs

Reference configurations for running a private AI + cybersecurity sandbox on a single-node Proxmox homelab. These are provided as starting points — adapt to your hardware and network.

## Stack Overview

The docker-compose.yml runs four services on a single Ubuntu Server VM with GPU passthrough:

| Service | Role | Port |
|---------|------|------|
| Ollama | Local LLM inference with GPU acceleration | 11434 |
| Open WebUI | Browser-based chat interface | 3000 |
| SearXNG | Privacy-respecting metasearch (internal only) | none |
| Kokoro Web | Local text-to-speech via Kokoro-82M (internal only) | none |

SearXNG and Kokoro are not exposed to the host network. Only Open WebUI can reach them over the internal Docker network.

## System Tuning

### sysctl (sysctl/99-ai-inference.conf)

- vm.swappiness=10: Strongly prefer RAM over swap for model weights
- vm.overcommit_memory=1: Allow large mmap allocations (Ollama mmaps model files)

Install: sudo cp sysctl/99-ai-inference.conf /etc/sysctl.d/ && sudo sysctl --system

### GPU Persistence (systemd/nvidia-persistenced-override.service)

Keeps the NVIDIA GPU initialized between inference calls, eliminating cold-start latency. Without this, nvidia-smi -pm 1 resets on every reboot.

Install:

    sudo cp systemd/nvidia-persistenced-override.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable nvidia-persistenced-override.service

### SearXNG (searxng/)

Minimal SearXNG configuration tuned for API use by Open WebUI. Generate your own secret key before deploying:

    openssl rand -hex 32

Replace CHANGE_ME_GENERATE_WITH_openssl_rand_-hex_32 in settings.yml with the output.

## Hardware Reference

This stack was developed and tested on:

- Host: Proxmox VE 9.1, AMD Ryzen 9 5900X (12C/24T), 32GB RAM
- VM: Ubuntu 24.04 LTS, 24GB RAM, 12 vCPUs, 180GB disk
- GPU: NVIDIA RTX 3080 Ti (12GB VRAM) via PCIe passthrough with VFIO
- Network: Cloudflare Zero Trust Tunnel for secure remote access

## Additional Hardening Applied (not in config files)

- noatime mount option on root filesystem
- Docker log rotation: json-file driver, 50MB max, 3 files
- Docker default-ulimits nofile set to 65536
- Unnecessary services disabled: ModemManager, multipathd, snapd, unattended-upgrades
- SSH key-only authentication (password auth disabled)
