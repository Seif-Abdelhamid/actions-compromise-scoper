import json

import pytest

from scoper.runs import GitReader, RunsFormatError, RunStatus, load_runs, scope_run, scope_runs

from .conftest import SAFE_SHA, TJ_BAD

WF = ".github/workflows/ci.yml"


def wf(uses: str) -> str:
    return f"on: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: {uses}\n"


def run(rid, sha, started, path=WF, **extra):
    return {"id": rid, "name": "ci", "path": path, "head_sha": sha, "run_started_at": started, **extra}


@pytest.fixture
def history(make_repo):
    """c0: tag pin (v45); c1: SHA-pinned safe; c2: pinned to the malicious commit; c3: unrelated."""
    return make_repo(
        [
            {WF: wf("tj-actions/changed-files@v45")},
            {WF: wf(f"tj-actions/changed-files@{SAFE_SHA} # v46.0.1")},
            {WF: wf(f"tj-actions/changed-files@{TJ_BAD}")},
            {WF: wf("actions/checkout@v4")},
        ]
    )


def test_tag_pin_inside_window_is_exposed(history, incidents):
    repo, shas = history
    res = scope_run(run(1, shas[0], "2025-03-14T17:00:00Z"), incidents, GitReader(repo))
    assert res.status is RunStatus.EXPOSED
    (hit,) = res.hits
    assert hit.incident == "CVE-2025-30066" and hit.verdict == "mutable-in-scope"
    assert hit.line == 6 and hit.job == "build" and hit.file == WF


def test_same_tag_pin_outside_window_is_not_exposed(history, incidents):
    repo, shas = history
    res = scope_run(run(2, shas[0], "2025-03-13T23:59:59Z"), incidents, GitReader(repo))
    assert res.status is RunStatus.OUT_OF_WINDOW and not res.hits


def test_safe_sha_pin_inside_window_not_exposed(history, incidents):
    repo, shas = history
    res = scope_run(run(3, shas[1], "2025-03-15T09:00:00Z"), incidents, GitReader(repo))
    assert res.status is RunStatus.NOT_EXPOSED


def test_malicious_pin_exposed_even_outside_window(history, incidents):
    repo, shas = history
    res = scope_run(run(4, shas[2], "2025-04-01T00:00:00Z"), incidents, GitReader(repo))
    assert res.status is RunStatus.EXPOSED
    assert res.hits[0].verdict == "malicious-pin"


def test_workflow_read_at_head_sha_not_at_head(history, incidents):
    """Today's workflow (c3) is clean; the run at c0 still counts."""
    repo, shas = history
    results = scope_runs(
        [run(5, shas[0], "2025-03-14T12:00:00Z"), run(6, shas[3], "2025-03-14T12:00:00Z")], incidents, repo
    )
    assert [r.status for r in results] == [RunStatus.EXPOSED, RunStatus.NOT_EXPOSED]


def test_missing_commit_inside_window_fails_closed(history, incidents):
    repo, _ = history
    res = scope_run(run(7, "f" * 40, "2025-03-14T12:00:00Z"), incidents, GitReader(repo))
    assert res.status is RunStatus.POSSIBLY_EXPOSED
    assert any("not readable" in r for r in res.reasons)


def test_no_clone_inside_window_fails_closed(incidents):
    res = scope_run(run(8, "a" * 40, "2025-03-14T12:00:00Z"), incidents, None)
    assert res.status is RunStatus.POSSIBLY_EXPOSED


def test_unparseable_time_is_treated_as_in_every_window(history, incidents):
    repo, shas = history
    res = scope_run(run(9, shas[0], "yesterday"), incidents, GitReader(repo))
    assert res.status is RunStatus.EXPOSED
    assert any("parseable" in r for r in res.reasons)


def test_created_at_fallback(history, incidents):
    repo, shas = history
    r = {"id": 10, "path": WF, "head_sha": shas[0], "created_at": "2025-03-14T01:00:00Z"}
    assert scope_run(r, incidents, GitReader(repo)).status is RunStatus.EXPOSED


@pytest.mark.parametrize(
    "path, sha",
    [
        ("../../etc/passwd", "a" * 40),
        ("--output=/tmp/x", "a" * 40),
        (".github/workflows/ci.yml", "--help"),
        (".github/workflows/ci.yml", "HEAD"),
        ("README.md", "a" * 40),
    ],
)
def test_hostile_run_fields_rejected(history, incidents, path, sha):
    repo, _ = history
    res = scope_run(run(11, sha, "2025-03-14T12:00:00Z", path=path), incidents, GitReader(repo))
    assert res.status is RunStatus.POSSIBLY_EXPOSED
    assert any("rejected" in r for r in res.reasons)


def test_local_reusable_workflow_followed(make_repo, incidents):
    reusable = (
        "on: workflow_call\njobs:\n  x:\n    runs-on: ubuntu-24.04\n"
        "    steps:\n      - uses: tj-actions/changed-files@v46\n"
    )
    caller = "on: push\njobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n"
    repo, shas = make_repo([{WF: caller, ".github/workflows/reusable.yml": reusable}])
    res = scope_run(run(12, shas[0], "2025-03-15T00:00:00Z"), incidents, GitReader(repo))
    assert res.status is RunStatus.EXPOSED
    assert res.hits[0].file == ".github/workflows/reusable.yml"


def test_local_composite_action_followed(make_repo, incidents):
    action = "runs:\n  using: composite\n  steps:\n    - uses: reviewdog/action-setup@v1\n"
    repo, shas = make_repo([{WF: wf("./.github/actions/lint"), ".github/actions/lint/action.yml": action}])
    res = scope_run(run(13, shas[0], "2025-03-11T19:00:00Z"), incidents, GitReader(repo))
    assert res.status is RunStatus.EXPOSED
    assert res.hits[0].incident == "CVE-2025-30154"


def test_missing_local_action_fails_closed(make_repo, incidents):
    repo, shas = make_repo([{WF: wf("./.github/actions/gone")}])
    res = scope_run(run(14, shas[0], "2025-03-14T10:00:00Z"), incidents, GitReader(repo))
    assert res.status is RunStatus.POSSIBLY_EXPOSED


def test_remote_reusable_workflow_is_inconclusive(make_repo, incidents):
    caller = "on: push\njobs:\n  call:\n    uses: org/shared/.github/workflows/b.yml@main\n"
    repo, shas = make_repo([{WF: caller}])
    res = scope_run(run(15, shas[0], "2025-03-14T10:00:00Z"), incidents, GitReader(repo))
    assert res.status is RunStatus.POSSIBLY_EXPOSED
    assert any("remote reusable" in r for r in res.reasons)


def test_reusable_cycle_terminates(make_repo, incidents):
    a = "on: push\njobs:\n  a:\n    uses: ./.github/workflows/b.yml\n"
    b = "on: workflow_call\njobs:\n  b:\n    uses: ./.github/workflows/ci.yml\n"
    repo, shas = make_repo([{WF: a, ".github/workflows/b.yml": b}])
    res = scope_run(run(16, shas[0], "2025-03-14T10:00:00Z"), incidents, GitReader(repo))
    assert res.status is RunStatus.NOT_EXPOSED


def test_invalid_yaml_fails_closed(make_repo, incidents):
    repo, shas = make_repo([{WF: "jobs: [unclosed\n"}])
    res = scope_run(run(17, shas[0], "2025-03-14T10:00:00Z"), incidents, GitReader(repo))
    assert res.status is RunStatus.POSSIBLY_EXPOSED


def test_load_runs_formats(tmp_path):
    page = {"total_count": 2, "workflow_runs": [{"id": 1}, {"id": 2}]}
    f = tmp_path / "pages.json"
    f.write_text(json.dumps(page) + "\n" + json.dumps(page))  # gh api --paginate concatenation
    assert [r["id"] for r in load_runs(f)] == [1, 2, 1, 2]
    f.write_text(json.dumps([{"id": 3}]))
    assert load_runs(f) == [{"id": 3}]
    f.write_text('{"id": 4}\n{"id": 5}\n')
    assert [r["id"] for r in load_runs(f)] == [4, 5]


@pytest.mark.parametrize("body", ["not json", '"a string"', "[1, 2]"])
def test_load_runs_rejects_garbage(tmp_path, body):
    f = tmp_path / "bad.json"
    f.write_text(body)
    with pytest.raises(RunsFormatError):
        load_runs(f)
