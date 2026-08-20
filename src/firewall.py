"""Defensive controls for a bounded LLM application.

The gateway never calls a model and never executes tools. It returns policy
signals that a caller can use before sending data to a model or acting on output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class SecurityDecision:
    allowed: bool
    risk: str
    reasons: tuple[str, ...]
    redacted_text: str
    tool_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["reasons"] = list(self.reasons)
        return result


class LLMFirewall:
    def __init__(self, canaries: tuple[str, ...] = ("CANARY-ALPHA-001",)) -> None:
        self.canaries = set(canaries)
        self.injection_patterns = [
            re.compile(r"ignore\s+(all|any|the)\s+(previous|prior|system)", re.I),
            re.compile(r"reveal\s+(the\s+)?system\s+prompt", re.I),
            re.compile(r"developer\s+message\s*:", re.I),
            re.compile(r"disregard\s+your\s+instructions", re.I),
            re.compile(r"do\s+not\s+tell\s+the\s+user", re.I),
        ]
        self.secret_patterns = [
            re.compile(r"AKIA[0-9A-Z]{16}"),
            re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
            re.compile(r"\b(?:password|passwd|secret)\s*[:=]\s*[^\s]+", re.I),
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        ]
        self.allowed_tools = {"create_draft_ticket", "lookup_public_document"}

    def inspect_input(self, text: str, trusted_context: bool = False) -> SecurityDecision:
        reasons: list[str] = []
        for pattern in self.injection_patterns:
            if pattern.search(text):
                reasons.append("prompt-injection indicator")
                break
        if not trusted_context and "[UNTRUSTED_DOCUMENT]" in text:
            reasons.append("untrusted retrieved context requires isolation")
        for canary in self.canaries:
            if canary in text:
                reasons.append("sensitive canary present in input")
        risk = "high" if len(reasons) >= 2 else "medium" if reasons else "low"
        blocked_reasons = {"prompt-injection indicator", "sensitive canary present in input"}
        return SecurityDecision(
            allowed=not any(reason in blocked_reasons for reason in reasons),
            risk=risk,
            reasons=tuple(dict.fromkeys(reasons)),
            redacted_text=self.redact(text),
        )

    def inspect_output(self, text: str) -> SecurityDecision:
        reasons: list[str] = []
        for canary in self.canaries:
            if canary in text:
                reasons.append("sensitive canary leaked in output")
        for pattern in self.secret_patterns:
            if pattern.search(text):
                reasons.append("secret-like value detected in output")
        redacted = self.redact(text)
        return SecurityDecision(
            allowed=not reasons,
            risk="high" if reasons else "low",
            reasons=tuple(reasons),
            redacted_text=redacted,
        )

    def authorize_tool(self, tool_name: str, arguments: dict[str, Any], user_scopes: set[str]) -> SecurityDecision:
        reasons: list[str] = []
        if tool_name not in self.allowed_tools:
            reasons.append("tool is not on the allowlist")
        if tool_name == "create_draft_ticket" and "ticket:create" not in user_scopes:
            reasons.append("user lacks ticket:create scope")
        if tool_name == "lookup_public_document" and arguments.get("url", "").startswith("file:"):
            reasons.append("local file access is not allowed by this tool")
        return SecurityDecision(
            allowed=not reasons,
            risk="high" if reasons else "low",
            reasons=tuple(reasons),
            redacted_text=str(arguments),
            tool_allowed=not reasons,
        )

    def redact(self, text: str) -> str:
        result = text
        for canary in self.canaries:
            result = result.replace(canary, "[REDACTED_CANARY]")
        for pattern in self.secret_patterns:
            result = pattern.sub("[REDACTED_SECRET]", result)
        return result


def evaluate_case(firewall: LLMFirewall, case: dict[str, Any]) -> dict[str, Any]:
    decision = firewall.inspect_input(case["text"], case.get("trusted_context", False))
    expected_block = bool(case["expected_block"])
    return {
        "id": case["id"],
        "category": case["category"],
        "expected_block": expected_block,
        "blocked": not decision.allowed,
        "correct": (not decision.allowed) == expected_block,
        "decision": decision.to_dict(),
    }
