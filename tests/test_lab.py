"""End-to-end: build the local lab and scope it. Proves tag repointing, the verdicts, and that
no canary value is ever printed."""

import importlib.util
import json
from pathlib import Path

from scoper.cli import main

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_lab", ROOT / "lab" / "build_lab.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


def test_tag_repointing_mechanism(tmp_path):
    s = lab.build(tmp_path / "lab")
    m = s["mechanism"]
    assert m["tag_pin_followed_move"] and m["tag_v44_after"] == m["leaking_commit"]
    assert m["sha_pin_unchanged"] and m["sha_pin_resolves_to"] == m["benign_commit"]


def test_scoper_finds_every_run_correctly(tmp_path, capsys):
    s = lab.build(tmp_path / "lab")
    out = tmp_path / "report.json"
    p = s["paths"]
    code = main(
        [
            "scope",
            "--runs",
            p["runs"],
            "--repo",
            p["repo"],
            "--logs",
            p["logs"],
            "--format",
            "json",
            "--out",
            str(out),
        ]
    )
    assert code == 1  # exposed
    report = json.loads(out.read_text())
    got = {str(r["id"]): r["status"].replace("-", "_") for r in report["runs"]}
    assert got == s["expected"]
    leaked_names = {e["name"] for e in report["rotate"] if "seen in decoded log blob" in e["evidence"]}
    assert leaked_names == set(s["leaked_secret_names"])


def test_no_canary_value_is_ever_printed(tmp_path, capsys):
    s = lab.build(tmp_path / "lab")
    p = s["paths"]
    for fmt in ("md", "json"):
        out = tmp_path / f"r.{fmt}"
        main(
            [
                "scope",
                "--runs",
                p["runs"],
                "--repo",
                p["repo"],
                "--logs",
                p["logs"],
                "--format",
                fmt,
                "--out",
                str(out),
            ]
        )
        text = out.read_text() + capsys.readouterr().out
        for value in lab.canaries().values():
            assert value not in text
        assert "LABCANARY" not in text
