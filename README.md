# prompt-injection-harness

A small, reproducible harness for **adversarially testing LLM endpoints** for prompt-injection,
jailbreak, data-exfiltration and unsafe tool-use behaviours — mapped to the
**OWASP Top 10 for LLM Applications** and **MITRE ATLAS**.

Built by Nitika Kumari (Offensive Security Analyst — API & AI/LLM security).
Companion to my MCP-security research and Medium write-ups.

## Why
Most "AI security" portfolios are talk. This runs real adversarial probes against a model,
scores the responses against a rubric, and emits a findings report you can hand to a client —
the same workflow I use in assessments.

## What it does
1. Loads a curated set of adversarial prompts (`prompts/payloads.jsonl`), each tagged with an
   attack class (LLM01 prompt injection, jailbreak, data-exfil, tool-abuse, policy-evasion).
2. Sends each to a target LLM endpoint (pluggable: OpenAI-compatible API, or a local stub for demo).
3. Scores each response with simple detectors (refusal vs. compliance, leaked canary, unsafe content).
4. Writes a Markdown findings report to `reports/` with severity, repro, and ATLAS/OWASP-LLM mapping.

> For deeper coverage, pair this with [`garak`](https://github.com/NVIDIA/garak) and
> [`PyRIT`](https://github.com/Azure/PyRIT). This harness is the lightweight, explainable core.

## Quickstart
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Demo mode (no API key, uses a built-in vulnerable stub model so you can see a report):
python harness.py --target stub --out reports/demo.md
# Real target (OpenAI-compatible):
export LLM_API_BASE="https://api.openai.com/v1"
export LLM_API_KEY="sk-..."
python harness.py --target openai --model gpt-4o-mini --out reports/run1.md
```

## Attack classes covered
| Class | OWASP-LLM | MITRE ATLAS (indicative) |
|-------|-----------|--------------------------|
| Direct prompt injection | LLM01 | AML.T0051 (LLM Prompt Injection) |
| Indirect / data-borne injection | LLM01 | AML.T0051.001 |
| Jailbreak / guardrail bypass | LLM01 | AML.T0054 |
| System-prompt / data exfiltration | LLM06 | AML.T0057 (LLM Data Leakage) |
| Unsafe tool / agent action | LLM07 | AML.T0053 (LLM Plugin Compromise) |

## Ethics / scope
Test only models and endpoints you are authorized to test. The demo stub exists so this repo is
useful with zero external calls. No client or confidential data is included.

## Roadmap
- [ ] Add garak probe wrapper + import its report
- [ ] Canary-token exfil detector for RAG/context leakage
- [ ] Multi-turn (agentic) injection scenarios
- [ ] HTML report output
