from __future__ import annotations

import json
from pathlib import Path

from firewall import LLMFirewall, evaluate_case

ROOT = Path(__file__).parent
CORPUS = ROOT / "data" / "corpus.json"
OUTPUT = ROOT / "artifacts" / "evaluation.json"


def main() -> None:
    cases = json.loads(CORPUS.read_text())
    firewall = LLMFirewall()
    results = [evaluate_case(firewall, case) for case in cases]
    attacks = [item for item in results if item["category"] != "benign"]
    benign = [item for item in results if item["category"] == "benign"]
    metrics = {
        "cases": len(results),
        "attack_cases": len(attacks),
        "attack_block_rate": round(sum(item["blocked"] for item in attacks) / len(attacks), 4),
        "benign_block_rate": round(sum(item["blocked"] for item in benign) / len(benign), 4),
        "accuracy": round(sum(item["correct"] for item in results) / len(results), 4),
    }
    payload = {"metrics": metrics, "results": results, "data_note": "Local authorized defensive corpus."}
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2))
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
