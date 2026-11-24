import pytest

from scoper.workflows import PinKind, Verdict, classify, extract_uses, parse_uses

from .conftest import RD_BAD, SAFE_SHA, TJ_BAD


@pytest.mark.parametrize(
    "raw, kind, action, ref",
    [
        ("tj-actions/changed-files@v45", PinKind.TAG, "tj-actions/changed-files", "v45"),
        ("tj-actions/changed-files@v35.7.7-sec", PinKind.TAG, "tj-actions/changed-files", "v35.7.7-sec"),
        ("tj-actions/changed-files@main", PinKind.BRANCH, "tj-actions/changed-files", "main"),
        (f"tj-actions/changed-files@{TJ_BAD.upper()}", PinKind.FULL_SHA, "tj-actions/changed-files", TJ_BAD),
        ("tj-actions/changed-files@0e58ed8", PinKind.SHORT_SHA, "tj-actions/changed-files", "0e58ed8"),
        ("github/codeql-action/init@v3", PinKind.TAG, "github/codeql-action", "v3"),
        ("tj-actions/changed-files", PinKind.NO_REF, "tj-actions/changed-files", None),
        ("./.github/actions/setup", PinKind.LOCAL, None, None),
        ("docker://alpine:3.20", PinKind.DOCKER, None, None),
    ],
)
def test_parse_uses(raw, kind, action, ref):
    u = parse_uses(raw)
    assert u.kind is kind
    assert u.action == action
    assert u.ref == ref


def test_subpath_kept():
    u = parse_uses("github/codeql-action/init@v3")
    assert u.subpath == "init"


WORKFLOW = """\
name: ci
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: changed
        id: changed
        uses: tj-actions/changed-files@v44
      - run: echo hi
  call:
    uses: org/shared/.github/workflows/build.yml@main
  local-call:
    uses: ./.github/workflows/reusable.yml
"""


def test_extract_uses_with_lines_and_jobs():
    refs = extract_uses(WORKFLOW)
    raws = [(r.raw, r.job, r.step, r.line) for r in refs]
    assert ("actions/checkout@v4", "lint", 0, 7) in raws
    assert ("tj-actions/changed-files@v44", "lint", 1, 10) in raws
    assert ("org/shared/.github/workflows/build.yml@main", "call", None, 13) in raws
    assert ("./.github/workflows/reusable.yml", "local-call", None, 15) in raws


def test_extract_uses_composite_action():
    text = "runs:\n  using: composite\n  steps:\n    - uses: reviewdog/action-setup@v1\n"
    (ref,) = extract_uses(text)
    assert ref.action == "reviewdog/action-setup" and ref.job is None and ref.line == 4


def test_extract_uses_empty_and_odd_shapes():
    assert extract_uses("") == []
    assert extract_uses("jobs: [1, 2]") == []
    assert extract_uses("jobs:\n  a:\n    steps: notalist\n") == []


def _inc(incidents, cid):
    return {i.id: i for i in incidents}[cid]


@pytest.mark.parametrize(
    "raw, cid, verdict",
    [
        (f"tj-actions/changed-files@{TJ_BAD}", "CVE-2025-30066", Verdict.MALICIOUS_PIN),
        ("tj-actions/changed-files@0e58ed86", "CVE-2025-30066", Verdict.MALICIOUS_PIN),
        (f"tj-actions/changed-files@{SAFE_SHA}", "CVE-2025-30066", Verdict.SAFE_PIN),
        ("tj-actions/changed-files@v35", "CVE-2025-30066", Verdict.MUTABLE_IN_SCOPE),
        ("TJ-Actions/Changed-Files@main", "CVE-2025-30066", Verdict.MUTABLE_IN_SCOPE),
        ("tj-actions/changed-files", "CVE-2025-30066", Verdict.MUTABLE_IN_SCOPE),
        ("tj-actions/changed-files@abcdef1", "CVE-2025-30066", Verdict.MUTABLE_IN_SCOPE),
        ("reviewdog/action-setup@v1", "CVE-2025-30154", Verdict.MUTABLE_IN_SCOPE),
        ("reviewdog/action-setup@v2", "CVE-2025-30154", Verdict.MUTABLE_OUT_OF_SCOPE),
        (f"reviewdog/action-setup@{RD_BAD}", "CVE-2025-30154", Verdict.MALICIOUS_PIN),
        (f"reviewdog/action-shellcheck@{SAFE_SHA}", "CVE-2025-30154", Verdict.DEPENDENT),
        ("actions/checkout@v4", "CVE-2025-30066", None),
        ("tj-actions/changed-files-extra@v1", "CVE-2025-30066", None),
        ("./local", "CVE-2025-30066", None),
    ],
)
def test_classify(incidents, raw, cid, verdict):
    assert classify(parse_uses(raw), _inc(incidents, cid)) is verdict
