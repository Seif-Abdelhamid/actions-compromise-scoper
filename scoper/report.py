"""Join run scoping and log evidence into one incident report (JSON + Markdown)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .incidents import Incident
from .logs import LogScan, scan_logs
from .runs import RunResult, RunStatus

EXIT_CLEAN, EXIT_EXPOSED, EXIT_INCONCLUSIVE = 0, 1, 2
_MD_UNSAFE = re.compile(r"[\r\n|`<>\[\]]")


def md(text: object) -> str:
    """Neutralise text from untrusted inputs (run names, file names) for a Markdown table."""
    return _MD_UNSAFE.sub(" ", str(text))[:200]


@dataclass
class RunReport:
    run: RunResult
    logs: LogScan | None
    status: RunStatus
    leaked: list[dict] = field(default_factory=list)  # name, fingerprint, type_hint (never values)
    notes: list[str] = field(default_factory=list)


def find_run_logs(logs_dir: Path, run_id: object) -> Path | None:
    """Locate logs for a run: logs_<id>.zip, <id>.zip or a directory named <id>."""
    rid = str(run_id)
    if not rid.isdigit():
        return None
    for candidate in (logs_dir / f"logs_{rid}.zip", logs_dir / f"{rid}.zip", logs_dir / rid):
        if candidate.exists():
            return candidate
    return None


def build(
    results: list[RunResult], incidents: list[Incident], logs_dir: str | Path | None
) -> list[RunReport]:
    out: list[RunReport] = []
    for res in results:
        scan = None
        status = res.status
        notes: list[str] = []
        if logs_dir is not None:
            p = find_run_logs(Path(logs_dir), res.run_id)
            if p is not None:
                scan = scan_logs(p, incidents)
        if scan is not None and scan.findings and status is not RunStatus.EXPOSED:
            notes.append("log evidence found although workflow analysis did not flag the run")
            status = RunStatus.EXPOSED
        if status is RunStatus.EXPOSED and scan is None:
            notes.append("no logs for this run: assume every secret the job could read was exposed")
        if scan is not None and scan.errors:
            notes.append("some log files could not be read: " + "; ".join(scan.errors[:3]))
            if status is RunStatus.NOT_EXPOSED:
                status = RunStatus.POSSIBLY_EXPOSED
        leaked: dict[str, dict] = {}
        for f in scan.findings if scan else []:
            for s in f.secrets:
                leaked.setdefault(
                    f"{s.name}:{s.fingerprint}",
                    {"name": s.name, "fingerprint": s.fingerprint, "type_hint": s.type_hint},
                )
        out.append(RunReport(res, scan, status, list(leaked.values()), notes))
    return out


def exit_code(reports: list[RunReport]) -> int:
    statuses = {r.status for r in reports}
    if RunStatus.EXPOSED in statuses:
        return EXIT_EXPOSED
    if RunStatus.POSSIBLY_EXPOSED in statuses:
        return EXIT_INCONCLUSIVE
    return EXIT_CLEAN


def rotation_list(reports: list[RunReport]) -> list[dict]:
    """Secrets to rotate: names seen in leaked blobs, plus every secret an exposed run referenced."""
    rows: dict[str, dict] = {}
    for r in reports:
        if r.status not in (RunStatus.EXPOSED, RunStatus.POSSIBLY_EXPOSED):
            continue
        for item in r.leaked:
            row = rows.setdefault(item["name"], {"name": item["name"], "evidence": set(), "runs": set()})
            row["evidence"].add("seen in decoded log blob")
            row["runs"].add(str(r.run.run_id))
        names = set(r.run.secret_refs) | {"GITHUB_TOKEN"}
        for name in names:
            row = rows.setdefault(name, {"name": name, "evidence": set(), "runs": set()})
            row["evidence"].add(f"referenced by a run marked {r.status.value}")
            row["runs"].add(str(r.run.run_id))
    return [
        {"name": v["name"], "evidence": sorted(v["evidence"]), "runs": sorted(v["runs"], key=int_or_str)}
        for v in sorted(rows.values(), key=lambda v: (not any("blob" in e for e in v["evidence"]), v["name"]))
    ]


def int_or_str(x: str) -> tuple[int, object]:
    return (0, int(x)) if x.isdigit() else (1, x)


def to_json(reports: list[RunReport], incidents: list[Incident]) -> dict:
    return {
        "tool": "actions-compromise-scoper",
        "incidents": [
            {
                "id": i.id,
                "ghsa": i.ghsa,
                "action": i.action,
                "window_utc": [i.start.isoformat(), i.end.isoformat()],
                "window_precision": i.precision,
            }
            for i in incidents
        ],
        "summary": {s.value: sum(1 for r in reports if r.status is s) for s in RunStatus},
        "exit_code": exit_code(reports),
        "runs": [
            {
                "id": r.run.run_id,
                "name": r.run.name,
                "path": r.run.path,
                "head_sha": r.run.head_sha,
                "started": r.run.started.isoformat() if r.run.started else None,
                "event": r.run.event,
                "status": r.status.value,
                "incidents_in_window": r.run.incidents_in_window,
                "hits": [
                    {
                        "incident": h.incident,
                        "verdict": h.verdict.value,
                        "uses": h.uses,
                        "file": h.file,
                        "line": h.line,
                        "job": h.job,
                    }
                    for h in r.run.hits
                ],
                "log_findings": [
                    {
                        "source": f.source,
                        "line": f.line,
                        "kind": f.kind,
                        "incident": f.incident,
                        "detail": f.detail,
                    }
                    for f in (r.logs.findings if r.logs else [])
                ],
                "leaked_secrets": r.leaked,
                "secret_refs": sorted(r.run.secret_refs),
                "reasons": r.run.reasons,
                "notes": r.notes,
            }
            for r in reports
        ],
        "rotate": rotation_list(reports),
    }


def to_markdown(reports: list[RunReport], incidents: list[Incident]) -> str:
    data = to_json(reports, incidents)
    lines = ["# GitHub Actions compromise scoping report", ""]
    lines.append("| Incident | Action | Window (UTC) | Precision |")
    lines.append("|---|---|---|---|")
    for i in data["incidents"]:
        start, end = i["window_utc"]
        lines.append(
            f"| {i['id']} ({i['ghsa']}) | `{i['action']}` | {start} to {end} | {i['window_precision']} |"
        )
    lines += ["", "**Runs:** " + ", ".join(f"{k}: {v}" for k, v in data["summary"].items()), ""]
    verdict = {0: "no exposure found", 1: "EXPOSED runs found", 2: "INCONCLUSIVE: evidence missing"}
    lines += [f"**Result:** {verdict[data['exit_code']]}", ""]
    flagged = [r for r in data["runs"] if r["status"] in ("exposed", "possibly-exposed")]
    if flagged:
        lines += [
            "## Runs needing action",
            "",
            "| Run | Workflow | Started | Status | Why |",
            "|---|---|---|---|---|",
        ]
        for r in flagged:
            why = [
                f"{h['incident']} {h['verdict']} `{md(h['uses'])}` ({md(h['file'])}:{h['line']})"
                for h in r["hits"]
            ]
            why += [f"log: {f['kind']} at {md(f['source'])}:{f['line']}" for f in r["log_findings"][:5]]
            why += [md(x) for x in r["reasons"] + r["notes"]]
            started = r["started"] or "?"
            lines.append(
                f"| {md(r['id'])} | {md(r['path'])} | {started} | {r['status']} | {'<br>'.join(why)} |"
            )
        lines.append("")
    rot = data["rotate"]
    if rot:
        lines += [
            "## Rotate",
            "",
            "Values are never shown. Match fingerprints (SHA-256, first 16 hex) "
            "against your secret store if you need to confirm which value leaked.",
            "",
        ]
        lines += ["| Secret | Evidence | Runs |", "|---|---|---|"]
        for row in rot:
            lines.append(
                f"| `{md(row['name'])}` | {'; '.join(row['evidence'])} | {', '.join(row['runs'][:10])} |"
            )
        lines.append("")
        fp = [s for r in data["runs"] for s in r["leaked_secrets"]]
        if fp:
            lines += ["| Leaked name | Fingerprint | Type hint |", "|---|---|---|"]
            for s in fp:
                lines.append(f"| `{md(s['name'])}` | `{s['fingerprint']}` | {s['type_hint'] or '-'} |")
            lines.append("")
    lines += [
        "## Limits",
        "",
        "- Exposure is decided from the workflow file at each run's `head_sha` and the run start time.",
        "- Remote reusable workflows and third-party composite actions are not opened; runs that use "
        "them inside a window are reported as possibly exposed.",
        "- Day-precision windows cover whole days and over-report on purpose.",
    ]
    return "\n".join(lines) + "\n"
