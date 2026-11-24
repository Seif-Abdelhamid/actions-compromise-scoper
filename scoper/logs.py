"""Scan downloaded GitHub Actions run logs for signs of the published compromises.

Reads a run-log archive (.zip, as served by the "Download workflow run logs" endpoint),
a directory of .txt logs, or a single log file. Nothing is extracted to disk.

Three signals:
  ioc          an indicator string from the incident definition (e.g. the gist path)
  sha          a known-malicious commit SHA
  b64x2        a token that base64-decodes twice into mostly printable text; the
               tj-actions advisory says leaked output is recovered with
               `base64 -d | base64 -d`

Secret values recovered from a blob are NEVER returned. Only the secret's name, a short
SHA-256 fingerprint (to match against your secret inventory) and a heuristic type hint.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .incidents import Incident

TS_PREFIX = re.compile(r"^\ufeff?\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z ?")
B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
# Heuristic name/value shapes inside a decoded blob (format of the real dump is unverified):
JSON_SECRET = re.compile(
    r'"([A-Za-z_][A-Za-z0-9_.-]{0,99})"\s*:\s*\{\s*"value"\s*:\s*"((?:[^"\\]|\\.)*)"\s*,\s*"isSecret"\s*:\s*true'
)
ENV_SECRET = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]{0,99})\s*=\s*(\S.*)$", re.M)
TYPE_HINTS = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_FINDINGS = 10_000


@dataclass(frozen=True)
class LeakedSecret:
    name: str
    fingerprint: str  # first 16 hex chars of SHA-256(value)
    type_hint: str | None
    length: int


@dataclass
class LogFinding:
    source: str  # archive member / file name
    line: int
    kind: str  # ioc | sha | b64x2
    incident: str | None
    detail: str
    secrets: list[LeakedSecret] = field(default_factory=list)


@dataclass
class LogScan:
    sources: list[str] = field(default_factory=list)
    findings: list[LogFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _type_hint(value: str) -> str | None:
    for name, rx in TYPE_HINTS:
        if rx.search(value):
            return name
    return None


def _b64(token: str) -> bytes | None:
    pad = "=" * (-len(token) % 4)
    try:
        return base64.b64decode(token + pad, validate=True)
    except (binascii.Error, ValueError):
        return None


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return ok / len(data)


def decode_double_b64(token: str) -> str | None:
    """Return the text if `token` is base64(base64(text)) and text is mostly printable."""
    first = _b64(token)
    if first is None or _printable_ratio(first) < 1.0:
        return None
    inner = first.decode("ascii").strip()
    if not re.fullmatch(r"[A-Za-z0-9+/=\r\n]{12,}", inner):
        return None
    second = _b64(re.sub(r"[\r\n]+", "", inner))
    if second is None or len(second) < 8 or _printable_ratio(second) < 0.9:
        return None
    return second.decode("utf-8", errors="replace")


def extract_secrets(text: str) -> list[LeakedSecret]:
    seen: dict[str, LeakedSecret] = {}
    pairs = [(m.group(1), m.group(2)) for m in JSON_SECRET.finditer(text)]
    if not pairs:
        pairs = [(m.group(1), m.group(2).strip()) for m in ENV_SECRET.finditer(text)]
    for name, value in pairs:
        if not value:
            continue
        s = LeakedSecret(name, fingerprint(value), _type_hint(value), len(value))
        seen.setdefault(f"{name}:{s.fingerprint}", s)
    return list(seen.values())


def _iter_texts(path: Path, scan: LogScan) -> Iterator[tuple[str, str]]:
    if path.is_dir():
        for f in sorted(p for p in path.rglob("*") if p.is_file()):
            yield from _iter_texts(f, scan)
        return
    if zipfile.is_zipfile(path):
        total = 0
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                label = f"{path.name}!{info.filename}"
                if info.file_size > MAX_MEMBER_BYTES or total + info.file_size > MAX_TOTAL_BYTES:
                    scan.errors.append(f"{label}: skipped, too large ({info.file_size} bytes)")
                    continue
                total += info.file_size
                with zf.open(info) as fh:
                    data = fh.read(MAX_MEMBER_BYTES + 1)
                if len(data) > MAX_MEMBER_BYTES:
                    scan.errors.append(f"{label}: skipped, size does not match header")
                    continue
                yield label, data.decode("utf-8", errors="replace")
        return
    if path.stat().st_size > MAX_MEMBER_BYTES:
        scan.errors.append(f"{path}: skipped, too large")
        return
    yield str(path), path.read_text("utf-8", errors="replace")


def _add(scan: LogScan, finding: LogFinding) -> None:
    if len(scan.findings) >= MAX_FINDINGS:
        scan.truncated = True
        return
    scan.findings.append(finding)


def scan_text(source: str, text: str, incidents: list[Incident], scan: LogScan) -> None:
    shas = {s: inc.id for inc in incidents for s in inc.malicious_shas}
    iocs = [(ioc, inc.id) for inc in incidents for ioc in inc.iocs]
    b64_incident = next((i.id for i in incidents if i.log_encoding == "double-base64"), None)
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = TS_PREFIX.sub("", raw)
        low = line.lower()
        hit_iocs: dict[str, list[str]] = {}
        for ioc, cid in iocs:
            if ioc.lower() in low:
                hit_iocs.setdefault(cid, []).append(ioc)
        for cid, found in hit_iocs.items():
            _add(scan, LogFinding(source, lineno, "ioc", cid, "indicator(s) " + ", ".join(map(repr, found))))
        for sha, cid in shas.items():
            if sha in low:
                _add(scan, LogFinding(source, lineno, "sha", cid, f"malicious commit {sha}"))
        for m in B64_TOKEN.finditer(line):
            decoded = decode_double_b64(m.group(0))
            if decoded is None:
                continue
            secrets = extract_secrets(decoded)
            detail = f"double-base64 blob, {len(m.group(0))} chars, decodes to {len(decoded)} chars"
            _add(scan, LogFinding(source, lineno, "b64x2", b64_incident, detail, secrets))


def scan_logs(path: str | Path, incidents: list[Incident]) -> LogScan:
    scan = LogScan()
    p = Path(path)
    if not p.exists():
        scan.errors.append(f"{p}: does not exist")
        return scan
    try:
        for source, text in _iter_texts(p, scan):
            scan.sources.append(source)
            scan_text(source, text, incidents, scan)
    except (zipfile.BadZipFile, OSError) as exc:
        scan.errors.append(f"{p}: {exc}")
    return scan
