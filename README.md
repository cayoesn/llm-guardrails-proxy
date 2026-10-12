# 🛡️ LLM Guardrails Proxy (Enterprise Edition)

Proxy Interceptador de Segurança, Governança e Moderação para LLMs com **Single-Pass PII Sanitizer**, **Atomic Deanonymizer**, **Llama-Guard Safety Filter** e **Multi-Layer Injection Defense**.

---

## 🌟 Arquitetura & Recursos Big-Tech

- **Single-Pass PII Sanitizer & Redaction Engine**:
  - Compilação unificada com Named Capture Groups em uma única máquina de estados determinística:
    $$\mathcal{O}(|T|) \quad \text{em vez de} \quad \mathcal{O}(M \times |T|)$$
  - Elimina passes sequenciais repetidos e alocações excessivas de strings, ofuscando CPFs, E-mails, Telefones e Cartões de Crédito com consistência referencial.
- **Atomic Reversible Deanonymizer**:
  - Reidratação atômica por regex exata ordenada por comprimento de token, imune a colisões parciais ou bugs de prefixo em placeholders.
- **Multi-Layer Prompt Injection & Jailbreak Defense**:
  - Varredura de assinaturas de escape e roleplay forçado (`DAN`, `developer mode`, `ignore instructions`).
  - **Delimiter Hijacking**: Interceptação de quebra de tags de prompt de sistema (`</system>`, `[INST]`, `<|im_start|>`).
  - **Obfuscation Deep Inspection**: Decodificação especulativa de blocos Base64 e Hex em tempo real para prevenção de ataques esteganográficos.
- **Llama-Guard Safety Classifier**:
  - Avaliação contra taxonomia estrita de 6 categorias de risco (Violência, Discurso de Ódio, Cyberattacks, Conteúdo Sexual, Atos Ilegais e PII) com bloqueio em milissegundos.

---

## 📊 Análise de Complexidade & Performance

| Mecanismo | Abordagem Anterior | Abordagem Otimizada (Staff) | Garantia |
| :--- | :--- | :--- | :--- |
| **Sanitização PII** | $M$ passes `re.sub` sequenciais | 1 único passe unificado $\mathcal{O}(\|T\|)$ | Zero re-scans de string |
| **Reversão (Unmask)** | `text.replace` em loop | Regex unificada atômica $\mathcal{O}(\|T\|)$ | Imunidade a colisões de substring |
| **Inspeção de Injection** | Regex simples de texto | Heurística + Delimitadores + Decodificação Base64 | Cobertura contra ataques ofuscados |

---

## 🚀 Como Executar no Docker

```bash
docker compose up -d --build
```

---

## 🧪 Testes Automatizados (12 Testes / 100% Hermético)

Execução hermética da suíte de testes:

```bash
docker run --rm -v $(pwd):/workspace -w /workspace -e PYTHONPATH=/workspace portfolio-spec-engine:test pytest tests -v --cov=app/core
```
