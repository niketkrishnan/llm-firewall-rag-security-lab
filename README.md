# LLM Firewall and RAG/Agent Security Evaluation Lab

A defensive LLM application-security project that implements gateway controls and a reproducible regression corpus for prompt injection, indirect injection, sensitive-data leakage, and excessive tool authority.

> **Authorized-use notice:** The lab uses local fixtures and bounded policy checks. It does not connect to production systems, execute shell commands, or send messages.

## Current MVP

The MVP provides an input firewall, untrusted-context signal, canary/secret redaction, output inspection, tool allowlisting, and a JSON evaluation report. It does not require an LLM API key; a model adapter can be added later behind the same policy boundary.

## Run locally

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python evaluate.py
pytest
```

## OWASP mapping

The starter corpus maps to prompt injection, indirect prompt injection, sensitive-information handling, and excessive agency. The next milestone will add structured-output validation, citation checks, RAG poisoning fixtures, and a vulnerable-baseline comparison.

## Evaluation

The report computes attack-block rate, benign-block rate, and total accuracy. These are local-corpus metrics only; they are not a claim of universal model safety. A future release will publish corpus version, model adapter, latency, and attack-success results for each control configuration.

## Development milestones

The repository history is organized into incremental documentation, implementation, testing, evaluation, and release milestones.
