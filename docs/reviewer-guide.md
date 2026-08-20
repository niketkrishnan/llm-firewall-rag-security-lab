# Reviewer Guide

## Five-minute path

1. Run `python evaluate.py` and inspect the JSON evaluation artifact.
2. Trace `inspect_input`, `inspect_output`, `inspect_structured_output`, and `authorize_tool`.
3. Review tests for direct and indirect injection, canary leakage, active content, and unauthorized tools.
4. Discuss why model output and tool authorization are separate policy boundaries.

## Evidence of engineering judgment

The lab is deliberately offline and recommendation-only. It demonstrates security controls without pretending that a small corpus proves model safety.
