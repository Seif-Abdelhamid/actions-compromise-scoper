"""Local lab: reproduce tag repointing and generate an incident corpus for the scoper.

Everything is local git plus synthetic files. No network, no real malware, no real secrets:
the "malicious" commit only echoes a pre-encoded blob of canary values.

Part 1 (mechanism): a stand-in action repo publishes tag v44 on a benign commit, then the
tag is force-moved to a canary-leaking commit. A tag pin resolves to the new commit; a
full-SHA pin keeps resolving to the old one.

Part 2 (corpus): a consumer repo whose history uses tj-actions/changed-files by tag and by
SHA, plus a reviewdog transitive dependent; a REST-shaped runs export with runs inside and
outside the published windows; run logs, one of which carries the double-base64 canary dump.

Usage: python lab/build_lab.py OUTDIR   -> prints a JSON summary (shas, expected verdicts)
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess  # nosec B404 - fixed git argv only
import sys
from pathlib import Path

ENV = {
    "GIT_AUTHOR_NAME": "Lab",
    "GIT_AUTHOR_EMAIL": "lab@example.invalid",
    "GIT_COMMITTER_NAME": "Lab",
    "GIT_COMMITTER_EMAIL": "lab@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def canaries() -> dict[str, str]:
    """Fake secrets, built at runtime so no token-shaped literal sits in the repo."""
    return {
        "AWS_ACCESS_KEY_ID": "AK" + "IA" + "LABCANARY" + "0" * 7,
        "GH_PAT": "gh" + "p_" + "LABCANARY" + "x" * 27,
        "NPM_TOKEN": "np" + "m_" + "LABCANARY" + "y" * 27,
    }


def dump(secrets: dict[str, str]) -> str:
    return ",".join(f'"{k}":{{"value":{json.dumps(v)},"isSecret":true}}' for k, v in secrets.items())


def double_b64(text: str) -> str:
    return base64.b64encode(base64.b64encode(text.encode())).decode()


def git(repo: Path, *args: str) -> str:
    env = {**os.environ, **ENV}
    git_bin = shutil.which("git")
    if git_bin is None:
        raise RuntimeError("git not found on PATH")
    return subprocess.run(  # noqa: S603  # nosec B603
        [git_bin, "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,  # noqa: S607
    ).stdout.strip()


def commit(repo: Path, files: dict[str, str], msg: str) -> str:
    for rel, content in files.items():
        f = repo / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, "utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)
    return git(repo, "rev-parse", "HEAD")


BENIGN_ACTION = """name: changed-files (lab stand-in)
runs:
  using: composite
  steps:
    - run: echo "changed files: README.md"
      shell: bash
"""


def leaking_action(blob: str) -> str:
    # Stand-in for the real payload: no memory dump, it only prints a pre-encoded canary blob.
    return f"""name: changed-files (lab stand-in, repointed)
runs:
  using: composite
  steps:
    - run: echo "changed files: README.md"
      shell: bash
    - run: echo "{blob}"
      shell: bash
"""


def workflow(uses: str, secrets: list[str]) -> str:
    env = "".join(f"      {s}: ${{{{ secrets.{s} }}}}\n" for s in secrets)
    return f"""name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
{env}    steps:
      - uses: actions/checkout@v4
      - uses: {uses}
"""


def build(out: Path) -> dict:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    secrets = canaries()
    blob = double_b64(dump(secrets))

    # ---- Part 1: tag repointing on a stand-in action repo ----
    action = out / "standin-changed-files"
    action.mkdir()
    git(action, "init", "-q", "-b", "main")
    benign = commit(action, {"action.yml": BENIGN_ACTION}, "v44: benign")
    git(action, "tag", "v44")
    tag_before = git(action, "rev-parse", "v44^{commit}")
    leaking = commit(action, {"action.yml": leaking_action(blob)}, "unrelated-looking change")
    git(action, "tag", "-f", "v44", leaking)  # the attacker's move: same tag name, new commit
    tag_after = git(action, "rev-parse", "v44^{commit}")
    sha_pin_resolves_to = git(action, "rev-parse", f"{benign}^{{commit}}")

    # ---- Part 2: consumer repo history ----
    app = out / "app"
    app.mkdir()
    git(app, "init", "-q", "-b", "main")
    c0 = commit(
        app,
        {".github/workflows/ci.yml": workflow("tj-actions/changed-files@v44", list(secrets))},
        "ci uses changed-files by tag",
    )
    c1 = commit(
        app,
        {".github/workflows/release.yml": workflow(f"tj-actions/changed-files@{benign}", ["NPM_TOKEN"])},
        "release pins changed-files to a full SHA",
    )
    c2 = commit(
        app,
        {".github/workflows/lint.yml": workflow("reviewdog/action-shellcheck@v1", ["GH_PAT"])},
        "lint uses reviewdog/action-shellcheck",
    )
    missing_sha = "deadbeef" * 5  # a commit that is not in the clone (force-pushed away)

    runs = [
        {
            "id": 1001,
            "name": "ci",
            "path": ".github/workflows/ci.yml",
            "head_sha": c0,
            "run_started_at": "2025-03-14T16:00:00Z",
            "event": "push",
        },
        {
            "id": 1002,
            "name": "release",
            "path": ".github/workflows/release.yml",
            "head_sha": c1,
            "run_started_at": "2025-03-14T17:00:00Z",
            "event": "push",
        },
        {
            "id": 1003,
            "name": "ci",
            "path": ".github/workflows/ci.yml",
            "head_sha": c0,
            "run_started_at": "2025-03-20T09:00:00Z",
            "event": "push",
        },
        {
            "id": 1004,
            "name": "ci",
            "path": ".github/workflows/ci.yml",
            "head_sha": missing_sha,
            "run_started_at": "2025-03-15T08:00:00Z",
            "event": "push",
        },
        {
            "id": 1005,
            "name": "lint",
            "path": ".github/workflows/lint.yml",
            "head_sha": c2,
            "run_started_at": "2025-03-11T19:00:00Z",
            "event": "pull_request",
        },
    ]
    (out / "runs.json").write_text(json.dumps({"total_count": len(runs), "workflow_runs": runs}, indent=2))

    logs = out / "logs"
    for rid, lines in {
        1001: ["Run tj-actions/changed-files@v44", "changed files: README.md", blob, "Post job cleanup."],
        1002: ["Run tj-actions/changed-files@" + benign, "changed files: README.md"],
        1003: ["Run tj-actions/changed-files@v44", "changed files: README.md"],
    }.items():
        d = logs / str(rid)
        d.mkdir(parents=True)
        (d / "1_build.txt").write_text(
            "\n".join(f"2025-03-14T16:00:0{i}Z {t}" for i, t in enumerate(lines)) + "\n"
        )

    return {
        "mechanism": {
            "benign_commit": benign,
            "leaking_commit": leaking,
            "tag_v44_before": tag_before,
            "tag_v44_after": tag_after,
            "tag_pin_followed_move": tag_after == leaking and tag_before == benign,
            "sha_pin_resolves_to": sha_pin_resolves_to,
            "sha_pin_unchanged": sha_pin_resolves_to == benign,
        },
        "expected": {
            "1001": "exposed",
            "1002": "not_exposed",
            "1003": "out_of_window",
            "1004": "possibly_exposed",
            "1005": "exposed",
        },
        "leaked_secret_names": sorted(secrets),
        "paths": {"repo": str(app), "runs": str(out / "runs.json"), "logs": str(logs)},
    }


if __name__ == "__main__":
    print(json.dumps(build(Path(sys.argv[1])), indent=2))
