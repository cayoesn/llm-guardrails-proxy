# 🛡️ LLM Guardrails Proxy (Enterprise Edition)

Security, governance, and moderation intercepting proxy for LLMs featuring a **Single-Pass PII Sanitizer**, **Atomic Deanonymizer**, **Llama-Guard Safety Filter**, and **Multi-Layer Injection Defense**.

---

## 🌟 Architecture & Enterprise Capabilities

- **Single-Pass PII Sanitizer & Redaction Engine**:
  - Unified compilation with Named Capture Groups into a single deterministic finite state machine:
    $$\mathcal{O}(|T|) \quad \text{instead of} \quad \mathcal{O}(M \times |T|)$$
  - Eliminates repeated sequential passes and excessive string allocations while redacting SSNs, international national IDs (e.g., Brazilian CPF), emails, phone numbers, credit cards, and API keys with referential consistency.
- **Atomic Reversible Deanonymizer**:
  - Atomic rehydration via an exact regex ordered by token length, immune to partial collisions or placeholder prefix bugs.
- **Multi-Layer Prompt Injection & Jailbreak Defense**:
  - Scans for instruction-override signatures and forced roleplay (`DAN`, `developer mode`, `ignore instructions`).
  - **Delimiter Hijacking**: Intercepts system-prompt tag breakouts (`</system>`, `[INST]`, `<|im_start|>`).
  - **Obfuscation Deep Inspection**: Speculative real-time decoding of Base64 payloads to thwart steganographic and encoded attacks.
- **Llama-Guard Safety Classifier**:
  - Evaluates content against a strict 6-category risk taxonomy (Violence, Hate Speech, Cyberattacks, Sexual Content, Illegal Acts, and PII Leakage) with millisecond-level blocking.

---

## 📊 Complexity & Performance Analysis

| Mechanism | Previous Approach | Optimized Approach (Staff) | Guarantee |
| :--- | :--- | :--- | :--- |
| **PII Sanitization** | $M$ sequential `re.sub` passes | Single unified pass $\mathcal{O}(\|T\|)$ | Zero string re-scans |
| **Rehydration (Unmask)** | Looped `text.replace` | Unified atomic regex $\mathcal{O}(\|T\|)$ | Immune to substring collisions |
| **Injection Inspection** | Plain-text regex only | Heuristics + Delimiters + Base64 Decoding | Coverage against obfuscated attacks |

---

## 🚀 Running with Docker

```bash
docker compose up -d --build
```

---

## 🧪 Automated Tests (100% Hermetic Suite)

Run the hermetic test suite with coverage:

```bash
docker run --rm -v $(pwd):/workspace -w /workspace -e PYTHONPATH=/workspace portfolio-spec-engine:test pytest tests -v --cov=app/core
```
