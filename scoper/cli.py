"""Command line: `actions-scope scope|workflows|logs`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .incidents import IncidentError, load_incidents
from .logs import scan_logs
from .report import EXIT_CLEAN, EXIT_EXPOSED, EXIT_INCONCLUSIVE, build, exit_code, to_json, to_markdown
from .runs import RunsFormatError, load_runs, scope_runs
from .workflows import EXPOSING, Verdict, classify, extract_uses

EXIT_USAGE = 3


def _write(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text, "utf-8")
    else:
        sys.stdout.write(text)


def cmd_scope(args: argparse.Namespace) -> int:
    incidents = load_incidents(args.incidents)
    runs = load_runs(args.runs)
    results = scope_runs(runs, incidents, args.repo)
    reports = build(results, incidents, args.logs)
    if args.format == "json":
        _write(json.dumps(to_json(reports, incidents), indent=2) + "\n", args.out)
    else:
        _write(to_markdown(reports, incidents), args.out)
    return exit_code(reports)


def cmd_workflows(args: argparse.Namespace) -> int:
    """Static check of workflow files as they are now (no time window)."""
    incidents = load_incidents(args.incidents)
    worst = EXIT_CLEAN
    rows = []
    files = []
    for p in args.paths:
        path = Path(p)
        files += sorted(path.rglob("*.y*ml")) if path.is_dir() else [path]
    for f in files:
        try:
            refs = extract_uses(f.read_text("utf-8"))
        except Exception as exc:  # noqa: BLE001 - report and continue
            rows.append({"file": str(f), "error": str(exc)})
            worst = max(worst, EXIT_INCONCLUSIVE)
            continue
        for ref in refs:
            for inc in incidents:
                v = classify(ref, inc)
                if v is None:
                    continue
                rows.append(
                    {
                        "file": str(f),
                        "line": ref.line,
                        "uses": ref.raw,
                        "incident": inc.id,
                        "verdict": v.value,
                    }
                )
                if v is Verdict.MALICIOUS_PIN:
                    worst = EXIT_EXPOSED
                elif v in EXPOSING and worst == EXIT_CLEAN:
                    worst = EXIT_INCONCLUSIVE
    if args.format == "json":
        _write(json.dumps(rows, indent=2) + "\n", args.out)
    else:
        text = "".join(
            f"{r['file']}:{r.get('line', '?')}: {r.get('verdict', 'error')} {r.get('incident', '')} "
            f"{r.get('uses', r.get('error', ''))}\n"
            for r in rows
        )
        _write(text or "no references to the defined incidents\n", args.out)
    return worst


def cmd_logs(args: argparse.Namespace) -> int:
    incidents = load_incidents(args.incidents)
    scan = scan_logs(args.path, incidents)
    rows = [
        {
            "source": f.source,
            "line": f.line,
            "kind": f.kind,
            "incident": f.incident,
            "detail": f.detail,
            "secrets": [
                {"name": s.name, "fingerprint": s.fingerprint, "type_hint": s.type_hint} for s in f.secrets
            ],
        }
        for f in scan.findings
    ]
    _write(
        json.dumps({"sources": len(scan.sources), "findings": rows, "errors": scan.errors}, indent=2) + "\n",
        args.out,
    )
    if scan.findings:
        return EXIT_EXPOSED
    return EXIT_INCONCLUSIVE if scan.errors or not scan.sources else EXIT_CLEAN


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="actions-scope", description=__doc__)
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("--incidents", help="incident YAML (default: bundled CVE-2025-30066, CVE-2025-30154)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scope", help="scope exported runs against the incidents")
    s.add_argument("--runs", required=True, help="runs export (gh api --paginate .../actions/runs)")
    s.add_argument("--repo", help="local clone with full history (to read workflows at head_sha)")
    s.add_argument(
        "--logs", help="directory of run-log archives: logs_<run_id>.zip, <run_id>.zip or <run_id>/"
    )
    s.add_argument("--format", choices=["md", "json"], default="md")
    s.add_argument("--out")
    s.set_defaults(func=cmd_scope)

    w = sub.add_parser("workflows", help="static check of current workflow files")
    w.add_argument("paths", nargs="+")
    w.add_argument("--format", choices=["text", "json"], default="text")
    w.add_argument("--out")
    w.set_defaults(func=cmd_workflows)

    lg = sub.add_parser("logs", help="scan a run-log archive, directory or file")
    lg.add_argument("path")
    lg.add_argument("--out")
    lg.set_defaults(func=cmd_logs)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except (IncidentError, RunsFormatError, OSError) as exc:
        print(f"actions-scope: error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
