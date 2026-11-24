"""Incident definitions: which action, which commits, which time window."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path

import yaml

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ACTION_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class IncidentError(ValueError):
    """Raised when an incident definition is malformed."""


def parse_utc(value: str) -> datetime:
    """Parse an ISO-8601 timestamp and require an explicit UTC offset."""
    try:
        ts = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise IncidentError(f"bad timestamp: {value!r}") from exc
    if ts.tzinfo is None:
        raise IncidentError(f"timestamp without timezone: {value!r}")
    return ts.astimezone(UTC)


@dataclass(frozen=True)
class Incident:
    id: str
    ghsa: str
    action: str
    summary: str
    start: datetime
    end: datetime
    precision: str
    malicious_shas: tuple[str, ...]
    mutable_refs_exposed: str | tuple[str, ...]  # "all" or explicit refs
    fixed_version: str | None
    transitive_dependents: tuple[str, ...]
    iocs: tuple[str, ...]
    log_encoding: str

    def in_window(self, ts: datetime) -> bool:
        return self.start <= ts < self.end

    def matches_action(self, name: str) -> bool:
        return _same_action(self.action, name)

    def is_dependent(self, name: str) -> bool:
        return any(_same_action(dep, name) for dep in self.transitive_dependents)

    def ref_in_scope(self, ref: str) -> bool:
        if self.mutable_refs_exposed == "all":
            return True
        return ref in self.mutable_refs_exposed


def _same_action(a: str, b: str) -> bool:
    return a.lower() == b.lower()


def _incident_from_dict(raw: dict) -> Incident:
    required = ["id", "ghsa", "action", "summary", "window", "malicious_shas", "mutable_refs_exposed"]
    missing = [k for k in required if k not in raw]
    if missing:
        raise IncidentError(f"incident {raw.get('id', '?')}: missing {missing}")
    if not ACTION_RE.match(raw["action"]):
        raise IncidentError(f"incident {raw['id']}: bad action name {raw['action']!r}")
    shas = tuple(str(s).lower() for s in raw["malicious_shas"])
    bad = [s for s in shas if not SHA_RE.match(s)]
    if bad:
        raise IncidentError(f"incident {raw['id']}: malicious_shas must be full 40-hex SHAs: {bad}")
    window = raw["window"]
    start, end = parse_utc(window["start"]), parse_utc(window["end"])
    if end <= start:
        raise IncidentError(f"incident {raw['id']}: window end must be after start")
    refs = raw["mutable_refs_exposed"]
    if refs != "all":
        if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
            raise IncidentError(f"incident {raw['id']}: mutable_refs_exposed must be 'all' or a list")
        refs = tuple(refs)
    deps = tuple(raw.get("transitive_dependents") or [])
    for dep in deps:
        if not ACTION_RE.match(dep):
            raise IncidentError(f"incident {raw['id']}: bad dependent {dep!r}")
    return Incident(
        id=raw["id"],
        ghsa=raw["ghsa"],
        action=raw["action"],
        summary=raw["summary"],
        start=start,
        end=end,
        precision=window.get("precision", "unknown"),
        malicious_shas=shas,
        mutable_refs_exposed=refs,
        fixed_version=raw.get("fixed_version"),
        transitive_dependents=deps,
        iocs=tuple(raw.get("iocs") or []),
        log_encoding=raw.get("log_encoding", "unknown"),
    )


def load_incidents(path: str | Path | None = None) -> list[Incident]:
    """Load incidents from a YAML file, or the bundled definitions when path is None."""
    if path is None:
        text = resources.files("scoper.data").joinpath("incidents.yaml").read_text("utf-8")
    else:
        text = Path(path).read_text("utf-8")
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict) or not isinstance(doc.get("incidents"), list):
        raise IncidentError("incident file must have a top-level 'incidents' list")
    incidents = [_incident_from_dict(item) for item in doc["incidents"]]
    ids = [i.id for i in incidents]
    if len(ids) != len(set(ids)):
        raise IncidentError("duplicate incident ids")
    return incidents
