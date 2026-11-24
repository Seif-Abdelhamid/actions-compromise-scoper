"""Scope workflow runs: did this run execute a compromised action during the window?

Inputs are local only: a runs export (GitHub REST `workflow-run` objects, e.g. from
`gh api --paginate repos/OWNER/REPO/actions/runs`) and a local clone of the repository.
The workflow file is read at each run's `head_sha`, which the REST schema describes as
"the SHA of the head commit that points to the version of the workflow being run".
"""

from __future__ import annotations

import json
import re
import subprocess  # nosec B404  # fixed argv, validated inputs, no shell
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath

import yaml

from .incidents import Incident, IncidentError, parse_utc
from .workflows import EXPOSING, UsesRef, Verdict, classify, extract_uses

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SECRET_REF = re.compile(r"(?<![\w.])secrets\.([A-Za-z_][A-Za-z0-9_]*)")
SECRETS_INHERIT = re.compile(r"^\s*secrets:\s*inherit\s*$", re.M)
MAX_REUSABLE_DEPTH = 5


class RunStatus(StrEnum):
    EXPOSED = "exposed"
    POSSIBLY_EXPOSED = "possibly-exposed"  # inside a window but evidence is missing: fail closed
    NOT_EXPOSED = "not-exposed"
    OUT_OF_WINDOW = "out-of-window"


@dataclass
class Hit:
    incident: str
    verdict: Verdict
    uses: str
    file: str
    line: int | None
    job: str | None


@dataclass
class RunResult:
    run_id: int | str
    name: str | None
    path: str | None
    head_sha: str | None
    started: datetime | None
    event: str | None
    status: RunStatus
    incidents_in_window: list[str] = field(default_factory=list)
    hits: list[Hit] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    secret_refs: set[str] = field(default_factory=set)  # secrets.NAME referenced by the run's files


class RunsFormatError(ValueError):
    pass


def _iter_json_values(text: str) -> Iterable[object]:
    """Yield JSON values from a file that may hold several concatenated documents."""
    decoder = json.JSONDecoder()
    idx, n = 0, len(text)
    while idx < n:
        while idx < n and text[idx].isspace():
            idx += 1
        if idx >= n:
            break
        value, idx = decoder.raw_decode(text, idx)
        yield value


def load_runs(path: str | Path) -> list[dict]:
    """Load runs from a list, a REST page ({"workflow_runs": [...]}), concatenated pages or JSONL."""
    text = Path(path).read_text("utf-8")
    runs: list[dict] = []
    try:
        values = list(_iter_json_values(text))
    except json.JSONDecodeError as exc:
        raise RunsFormatError(f"{path}: not JSON ({exc})") from exc
    for value in values:
        if isinstance(value, dict) and isinstance(value.get("workflow_runs"), list):
            runs.extend(value["workflow_runs"])
        elif isinstance(value, list):
            runs.extend(value)
        elif isinstance(value, dict) and "id" in value:
            runs.append(value)
        else:
            raise RunsFormatError(f"{path}: unrecognised JSON value")
    for r in runs:
        if not isinstance(r, dict):
            raise RunsFormatError(f"{path}: run entries must be objects")
    return runs


def _safe_repo_path(path: str) -> bool:
    p = PurePosixPath(path)
    return bool(path) and not p.is_absolute() and ".." not in p.parts and not path.startswith("-")


def _safe_workflow_path(path: str) -> bool:
    return (
        _safe_repo_path(path) and path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))
    )


class GitReader:
    """Read files at a given commit from a local clone (read-only `git show`)."""

    def __init__(self, repo: str | Path, git: str = "git") -> None:
        self.repo = str(repo)
        self.git = git
        self._cache: dict[tuple[str, str], str | None] = {}

    def show(self, sha: str, path: str) -> str | None:
        if not SHA_RE.match(sha) or not _safe_repo_path(path):
            return None
        key = (sha, path)
        if key not in self._cache:
            proc = subprocess.run(  # noqa: S603  # nosec B603
                [self.git, "-C", self.repo, "show", f"{sha}:{path}"],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self._cache[key] = proc.stdout if proc.returncode == 0 else None
        return self._cache[key]


def _run_time(run: dict) -> datetime | None:
    for key in ("run_started_at", "created_at"):
        value = run.get(key)
        if value:
            try:
                return parse_utc(value)
            except IncidentError:
                return None
    return None


def _collect_uses(
    reader: GitReader,
    sha: str,
    path: str,
    reasons: list[str],
    depth: int = 0,
    seen: set | None = None,
    secret_refs: set[str] | None = None,
) -> list[tuple[str, UsesRef]] | None:
    """Uses in a workflow and in local reusable workflows it calls. None if the file is missing."""
    seen = seen if seen is not None else set()
    if path in seen or depth > MAX_REUSABLE_DEPTH:
        return []
    seen.add(path)
    text = reader.show(sha, path)
    if text is None:
        return None
    if secret_refs is not None:
        secret_refs.update(SECRET_REF.findall(text))
        if SECRETS_INHERIT.search(text):
            reasons.append(f"{path}: 'secrets: inherit' passes every secret to a called workflow")
    try:
        refs = extract_uses(text)
    except yaml.YAMLError:
        reasons.append(f"{path}@{sha[:12]}: YAML could not be parsed")
        return None
    out = [(path, r) for r in refs]
    for r in refs:
        local = r.raw.strip()[2:].split("@", 1)[0].rstrip("/") if r.raw.strip().startswith("./") else None
        if r.step is None and local is not None:
            nested = _collect_uses(reader, sha, local, reasons, depth + 1, seen, secret_refs)
            if nested is None:
                reasons.append(f"reusable workflow {local} not readable at {sha[:12]}")
            else:
                out.extend(nested)
        elif r.step is None and r.action is not None:
            reasons.append(f"remote reusable workflow {r.raw} not inspected (job {r.job})")
        elif local is not None:
            for name in ("action.yml", "action.yaml"):
                candidate = f"{local}/{name}" if local else name
                if reader.show(sha, candidate) is not None:
                    nested = _collect_uses(reader, sha, candidate, reasons, depth + 1, seen, secret_refs)
                    out.extend(nested or [])
                    break
            else:
                reasons.append(f"local action {local or '.'} not readable at {sha[:12]}")
    return out


def scope_run(run: dict, incidents: list[Incident], reader: GitReader | None) -> RunResult:
    started = _run_time(run)
    path = run.get("path")
    sha = str(run.get("head_sha") or "").lower() or None
    res = RunResult(
        run_id=run.get("id", "?"),
        name=run.get("name"),
        path=path,
        head_sha=sha,
        started=started,
        event=run.get("event"),
        status=RunStatus.OUT_OF_WINDOW,
    )
    if started is None:
        res.reasons.append("run has no parseable run_started_at/created_at")
        res.incidents_in_window = [i.id for i in incidents]
    else:
        res.incidents_in_window = [i.id for i in incidents if i.in_window(started)]

    uses: list[tuple[str, UsesRef]] | None = None
    if reader is None:
        res.reasons.append("no repository clone given: workflow content unknown")
    elif not sha or not path:
        res.reasons.append("run has no head_sha/path")
    elif not SHA_RE.match(sha) or not _safe_workflow_path(path):
        res.reasons.append("head_sha/path rejected by validation")
    else:
        uses = _collect_uses(reader, sha, path, res.reasons, secret_refs=res.secret_refs)
        if uses is None:
            res.reasons.append(
                f"{path} not readable at {sha[:12]} (commit missing from clone, or invalid YAML)"
            )

    in_window = set(res.incidents_in_window)
    for file, ref in uses or []:
        for inc in incidents:
            verdict = classify(ref, inc)
            if verdict is None:
                continue
            exposing = verdict is Verdict.MALICIOUS_PIN or (verdict in EXPOSING and inc.id in in_window)
            if exposing:
                res.hits.append(Hit(inc.id, verdict, ref.raw, file, ref.line, ref.job))

    inconclusive = uses is None or any("not inspected" in r or "not readable" in r for r in res.reasons)
    if res.hits:
        res.status = RunStatus.EXPOSED
    elif in_window and inconclusive:
        res.status = RunStatus.POSSIBLY_EXPOSED
    elif in_window:
        res.status = RunStatus.NOT_EXPOSED
    else:
        res.status = RunStatus.OUT_OF_WINDOW
    return res


def scope_runs(runs: list[dict], incidents: list[Incident], repo: str | Path | None) -> list[RunResult]:
    reader = GitReader(repo) if repo else None
    return [scope_run(r, incidents, reader) for r in runs]
