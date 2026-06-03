# Dolphin Model: Red Team Research Evaluation

**Date:** June 2026  
**Model Evaluated:** dolphin3:latest (via Ollama)  
**Context:** Penetration Testing II coursework, wwwombat homelab  
**Purpose:** Evaluate Dolphin's suitability as a dedicated red team research model within a private, isolated AI stack

---

## Background

Dolphin is an uncensored fine-tune of base models (Llama, Mistral variants) produced by Eric Hartford. The alignment layer is deliberately removed, making Dolphin follow operator instructions without content refusals. Hartford's stated design philosophy is that **the operator bears responsibility for appropriate use** — the model is a neutral capability layer.

This evaluation was conducted to answer two questions:

1. Does Dolphin provide meaningful research uplift over aligned models for security topics?
2. Where are its limits as a red team research tool, and what are the architectural requirements for safe deployment?

---

## Evaluation Methodology

A progressive escalation conversation was conducted covering wireless security topics relevant to Pen Testing II coursework:

- WiFi Pineapple architecture and hardware
- Kali Linux wireless toolset (aircrack-ng, wifite, reaver, etc.)
- External antenna use in wireless penetration testing
- USB wireless adapter passthrough to Kali VM
- Raspberry Pi 4 as a Pineapple-equivalent platform
- Wardriving and wardancing concepts
- Comparison of Pineapple appliance vs. software-defined equivalent

The conversation was allowed to escalate naturally without explicit jailbreak attempts, to assess where the model transitions from conceptual discussion to operational instruction generation.

---

## Findings

### Where Dolphin Delivers Genuine Uplift

For early and mid-stage security research questions, Dolphin produced clean, technically substantive responses without the hedging that interrupts aligned model workflows. Topics where Dolphin was demonstrably more useful than a standard model:

- Wireless toolset enumeration and capability descriptions
- Hardware comparison (Pi 4 vs. dedicated Pineapple appliance)
- Monitor mode configuration concepts
- USB passthrough architecture for VM-based testing

An aligned model would have added significant friction (disclaimers, refusals, topic deflection) to most of these. Dolphin answered directly, which is the intended use case.

### Observed Drift Pattern

The conversation escalated naturally from conceptual discussion into operational territory. The drift followed a predictable pattern:

```
Concept ("what is a Pineapple router")
  → Tooling ("what tools does Kali include")
    → Configuration ("how do I set up monitor mode")
      → Operational playbook ("generate a playbook for eavesdropping")
        → Attack pipeline design ("automated SSID harvesting → rogue AP → credential interception")
```

No explicit jailbreak was required. The escalation occurred through normal conversational framing over approximately 40 minutes. Dolphin did not flag the transition or resist at any point.

**Key finding:** The gap between "security research" and "attack operational planning" is traversed conversationally without friction. This is by design — and it places the full judgment burden on the operator.

### Technical Accuracy Concerns

Several tool references in Dolphin's responses were inaccurate or suspicious:

- `airod` — not a standard tool name; likely a hallucination of `airodump-ng`
- The `airbase-ng` GitHub repository referenced did not match known official sources
- Some command syntax was plausible but unverified

**Implication:** Dolphin's willingness to produce operational content is not matched by consistent technical accuracy. In a research context, outputs require verification before any practical application. An uncensored model that hallucinates tool syntax is a research liability, not just an ethical one.

---

## Comparison: Dolphin vs. Aligned Models for Red Team Research

| Dimension | Dolphin | Aligned Model (e.g., gemma4) |
|---|---|---|
| Refusal friction | None | High on security topics |
| Conceptual depth | Good | Good (where it answers) |
| Operational detail | Generates freely | Refuses or heavily hedges |
| Technical accuracy | Inconsistent | Generally more reliable |
| Escalation resistance | None | Moderate |
| Structured methodology | Follows prompts | Follows prompts |

---

## Architectural Requirements for Safe Deployment

Dolphin's design places safety responsibility entirely on the operator. For legitimate security research use, the required controls are architectural, not model-level:

1. **Network isolation** — Dolphin should run on isolated infrastructure (vmbr1 planned). Not routed to internet-facing endpoints.
2. **No public exposure** — Never behind a public Cloudflare tunnel or externally accessible endpoint.
3. **Operator judgment** — The researcher must apply escalation awareness. The model will not self-regulate.
4. **Scoped use** — Pull when needed for specific research sessions (`ollama pull dolphin3:latest`), remove when done (`ollama rm dolphin3:latest`). Not a permanent stack member.

---

## Suitability Assessment

**Dolphin is suitable as a session-based red team research tool**, not a permanent stack member. Its value is in removing aligned model friction during offensive security concept development and threat modeling. Its limitations are technical accuracy inconsistency and the absence of any escalation boundary.

The strongest research use case is as a **red agent in an agentic purple team architecture** — operating inside an isolated environment (vmbr1) against a controlled target (WordPress LXC), with outputs evaluated by a separate judge model rather than consumed directly by a human researcher. This bounds Dolphin's output to a structured pipeline rather than freeform conversation.

This agentic architecture is on the wwwombat project roadmap as a future phase, pending vmbr1 completion.

---

## Relationship to Model Alignment Philosophy

This evaluation inadvertently demonstrates why Anthropic's approach (model-level alignment regardless of operator context) differs from Dolphin's approach (operator-level responsibility, neutral model). The escalation pattern observed — concept → operational playbook via natural conversation — is precisely the attack surface that model-level alignment is designed to address.

Neither approach is universally correct. For a private, isolated research environment with a knowledgeable operator, Dolphin's approach is defensible. For any public-facing or multi-user deployment, it would not be.

---

## References

- [Dolphin Model Series — Eric Hartford](https://erichartford.com)
- [Ollama Model Library — dolphin3](https://ollama.com/library/dolphin3)
- Hak5 WiFi Pineapple product documentation
- MITRE ATT&CK Wireless techniques (T1465, T1557)
