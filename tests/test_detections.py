"""Check the shipped Sigma rules against labeled synthetic samples.

A deliberately small evaluator: it supports exactly the features these rules use
(`contains`, `contains|all`, `selection` and `1 of selection_*`), and fails on anything else.
"""

import json
from pathlib import Path

import pytest
import yaml

DET = Path(__file__).resolve().parents[1] / "detections"
RULES = {
    "tj_actions_payload_fetch_proxy.yml": "proxy.jsonl",
    "tj_actions_memdump_exec_linux.yml": "process_creation.jsonl",
}


def match_selection(sel: dict, event: dict) -> bool:
    for key, want in sel.items():
        field, *mods = key.split("|")
        value = str(event.get(field, ""))
        wants = want if isinstance(want, list) else [want]
        if mods == ["contains"]:
            if not any(w in value for w in wants):
                return False
        elif mods == ["contains", "all"]:
            if not all(w in value for w in wants):
                return False
        else:
            raise AssertionError(f"unsupported modifier {mods}")
    return True


def matches(rule: dict, event: dict) -> bool:
    det = rule["detection"]
    cond = det["condition"]
    sels = {k: v for k, v in det.items() if k != "condition"}
    if cond == "selection":
        return match_selection(sels["selection"], event)
    if cond == "1 of selection_*":
        return any(match_selection(v, event) for k, v in sels.items() if k.startswith("selection_"))
    raise AssertionError(f"unsupported condition {cond}")


@pytest.mark.parametrize(("rule_file", "samples"), RULES.items())
def test_rule_matches_positives_only(rule_file, samples):
    rule = yaml.safe_load((DET / rule_file).read_text())
    assert rule["level"] in ("high", "critical") and rule["references"]
    rows = [json.loads(line) for line in (DET / "samples" / samples).read_text().splitlines() if line]
    assert any(r["label"] == "positive" for r in rows) and any(r["label"] == "negative" for r in rows)
    for r in rows:
        assert matches(rule, r) is (r["label"] == "positive"), r["note"]
