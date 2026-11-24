import io
import json
import zipfile

import pytest

from scoper.cli import main
from scoper.report import md

from .canary import CANARIES, double_b64, dump
from .conftest import SAFE_SHA, TJ_BAD

WF = ".github/workflows/ci.yml"
WF_TAG = (
    "on: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n"
    "      - uses: tj-actions/changed-files@v45\n"
    "        env:\n          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n"
    "      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
)
WF_PIN = f"on: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: tj-actions/changed-files@{SAFE_SHA}\n"


def _zip(path, member, text):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(member, text)
    path.write_bytes(buf.getvalue())


@pytest.fixture
def scenario(make_repo, tmp_path):
    repo, (sha_tag, sha_pin) = make_repo([{WF: WF_TAG}, {WF: WF_PIN}])
    runs = [
        {"id": 101, "name": "ci", "path": WF, "head_sha": sha_tag, "run_started_at": "2025-03-14T16:00:00Z"},
        {"id": 102, "name": "ci", "path": WF, "head_sha": sha_tag, "run_started_at": "2025-03-12T09:00:00Z"},
        {"id": 103, "name": "ci", "path": WF, "head_sha": sha_pin, "run_started_at": "2025-03-15T10:00:00Z"},
        {
            "id": 104,
            "name": "ci|<b>",
            "path": WF,
            "head_sha": "e" * 40,
            "run_started_at": "2025-03-15T11:00:00Z",
        },
    ]
    runs_file = tmp_path / "runs.json"
    runs_file.write_text(json.dumps({"total_count": 4, "workflow_runs": runs}))
    logs = tmp_path / "logs"
    logs.mkdir()
    leak = f"2025-03-14T16:00:05.0000000Z {double_b64(dump(CANARIES))}\n"
    _zip(logs / "logs_101.zip", "build/3_Get changed files.txt", leak)
    _zip(logs / "logs_103.zip", "build/1_Set up job.txt", "2025-03-15T10:00:01.0000000Z ok\n")
    return repo, runs_file, logs


def test_scope_json_end_to_end(scenario, tmp_path, capsys):
    repo, runs_file, logs = scenario
    out = tmp_path / "r.json"
    code = main(["scope", "--runs", str(runs_file), "--repo", str(repo), "--logs", str(logs),
                 "--format", "json", "--out", str(out)])  # fmt: skip
    assert code == 1
    data = json.loads(out.read_text())
    status = {r["id"]: r["status"] for r in data["runs"]}
    assert status == {101: "exposed", 102: "out-of-window", 103: "not-exposed", 104: "possibly-exposed"}
    run101 = data["runs"][0]
    assert {s["name"] for s in run101["leaked_secrets"]} == set(CANARIES)
    assert set(run101["secret_refs"]) == {"AWS_ACCESS_KEY_ID", "NPM_TOKEN"}
    rotate = {r["name"]: r for r in data["rotate"]}
    assert "GITHUB_TOKEN" in rotate and "NPM_TOKEN" in rotate
    assert rotate["GH_PAT"]["evidence"] == ["seen in decoded log blob"]
    assert "seen in decoded log blob" in data["rotate"][0]["evidence"]  # blob evidence sorted first
    text = out.read_text()
    for value in CANARIES.values():
        assert value not in text


def test_scope_markdown_neutralises_untrusted_text(scenario, capsys):
    repo, runs_file, logs = scenario
    code = main(["scope", "--runs", str(runs_file), "--repo", str(repo), "--logs", str(logs)])
    out = capsys.readouterr().out
    assert code == 1
    assert "EXPOSED runs found" in out and "## Rotate" in out
    assert "<b>" not in out
    for value in CANARIES.values():
        assert value not in out


def test_log_evidence_overrides_clean_workflow(scenario, tmp_path):
    repo, runs_file, logs = scenario
    leak = f"2025-03-15T10:00:05.0000000Z {double_b64(dump({'X': 'canary-x'}))}\n"
    _zip(logs / "logs_103.zip", "build/1.txt", leak)
    out = tmp_path / "r.json"
    main(["scope", "--runs", str(runs_file), "--repo", str(repo), "--logs", str(logs),
          "--format", "json", "--out", str(out)])  # fmt: skip
    run103 = next(r for r in json.loads(out.read_text())["runs"] if r["id"] == 103)
    assert run103["status"] == "exposed"
    assert any("log evidence" in n for n in run103["notes"])


def test_inconclusive_exit_code_without_exposure(make_repo, tmp_path):
    runs = tmp_path / "runs.json"
    runs.write_text(
        json.dumps([{"id": 1, "path": WF, "head_sha": "a" * 40, "run_started_at": "2025-03-14T01:00:00Z"}])
    )
    assert main(["scope", "--runs", str(runs)]) == 2


def test_clean_exit_code(tmp_path):
    runs = tmp_path / "runs.json"
    runs.write_text(
        json.dumps([{"id": 1, "path": WF, "head_sha": "a" * 40, "run_started_at": "2024-01-01T00:00:00Z"}])
    )
    assert main(["scope", "--runs", str(runs)]) == 0


def test_workflows_command(tmp_path, capsys):
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True)
    (d / "a.yml").write_text(WF_TAG)
    assert main(["workflows", str(d)]) == 2
    assert "mutable-in-scope CVE-2025-30066" in capsys.readouterr().out
    (d / "b.yml").write_text(WF_PIN.replace(SAFE_SHA, TJ_BAD))
    assert main(["workflows", str(d), "--format", "json"]) == 1
    rows = json.loads(capsys.readouterr().out)
    assert {r["verdict"] for r in rows} == {"mutable-in-scope", "malicious-pin"}


def test_workflows_command_reports_bad_yaml(tmp_path, capsys):
    f = tmp_path / "bad.yml"
    f.write_text("jobs: [oops\n")
    assert main(["workflows", str(f)]) == 2


def test_logs_command(scenario, capsys):
    _, _, logs = scenario
    assert main(["logs", str(logs / "logs_101.zip")]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["kind"] == "b64x2"
    assert main(["logs", str(logs / "logs_103.zip")]) == 0
    assert main(["logs", str(logs / "missing.zip")]) == 2


def test_usage_errors(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("nope")
    assert main(["scope", "--runs", str(bad)]) == 3
    assert main(["scope", "--runs", str(tmp_path / "none.json")]) == 3
    inc = tmp_path / "inc.yaml"
    inc.write_text("x: 1")
    assert main(["--incidents", str(inc), "logs", str(tmp_path)]) == 3


def test_md_helper():
    assert md("a|b\n`c`<d>[e]") == "a b  c  d  e "
