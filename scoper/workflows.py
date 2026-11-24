"""Extract `uses:` references from workflow / action YAML and classify them per incident."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

import yaml

from .incidents import Incident

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SHORT_SHA = re.compile(r"^[0-9a-f]{7,39}$")
VERSIONISH = re.compile(r"^v?\d+(\.\d+){0,2}([.-][0-9A-Za-z.-]+)?$")


class PinKind(StrEnum):
    FULL_SHA = "full-sha"
    SHORT_SHA = "short-sha"
    TAG = "tag"  # looks like a version; still mutable
    BRANCH = "branch"  # anything else; mutable
    LOCAL = "local"  # ./path
    DOCKER = "docker"  # docker://image
    NO_REF = "no-ref"


@dataclass(frozen=True)
class UsesRef:
    raw: str
    action: str | None  # owner/repo, None for local/docker
    subpath: str | None  # owner/repo/<subpath>
    ref: str | None
    kind: PinKind
    job: str | None = None
    step: int | None = None  # None => job-level reusable workflow
    line: int | None = None  # 1-based line in the YAML file

    @property
    def mutable(self) -> bool:
        return self.kind in (PinKind.TAG, PinKind.BRANCH, PinKind.SHORT_SHA, PinKind.NO_REF)


def parse_uses(raw: str) -> UsesRef:
    """Parse one `uses:` value. Never raises for odd input; classifies it instead."""
    value = raw.strip()
    if value.startswith("./") or value == ".":
        return UsesRef(raw, None, value, None, PinKind.LOCAL)
    if value.startswith("docker://"):
        return UsesRef(raw, None, None, None, PinKind.DOCKER)
    name, sep, ref = value.partition("@")
    parts = name.split("/")
    action = "/".join(parts[:2]) if len(parts) >= 2 else name
    subpath = "/".join(parts[2:]) or None
    if not sep or not ref:
        return UsesRef(raw, action, subpath, None, PinKind.NO_REF)
    low = ref.lower()
    if FULL_SHA.match(low):
        kind = PinKind.FULL_SHA
        ref = low
    elif SHORT_SHA.match(low) and not VERSIONISH.match(low):
        kind = PinKind.SHORT_SHA
    elif VERSIONISH.match(ref):
        kind = PinKind.TAG
    else:
        kind = PinKind.BRANCH
    return UsesRef(raw, action, subpath, ref, kind)


def _with_location(ref: UsesRef, job: str | None, step: int | None, line: int) -> UsesRef:
    return UsesRef(ref.raw, ref.action, ref.subpath, ref.ref, ref.kind, job, step, line)


def _mapping_get(node: yaml.Node, key: str) -> yaml.Node | None:
    if not isinstance(node, yaml.MappingNode):
        return None
    for k, v in node.value:
        if isinstance(k, yaml.ScalarNode) and k.value == key:
            return v
    return None


def _steps_uses(steps: yaml.Node | None, job: str | None) -> list[UsesRef]:
    out: list[UsesRef] = []
    if not isinstance(steps, yaml.SequenceNode):
        return out
    for idx, step in enumerate(steps.value):
        uses = _mapping_get(step, "uses")
        if isinstance(uses, yaml.ScalarNode) and uses.value:
            out.append(_with_location(parse_uses(uses.value), job, idx, uses.start_mark.line + 1))
    return out


def extract_uses(text: str) -> list[UsesRef]:
    """Return every `uses:` in a workflow (jobs.*.steps, jobs.*.uses) or composite action."""
    root = yaml.compose(text, Loader=yaml.SafeLoader)
    if root is None:
        return []
    out: list[UsesRef] = []
    jobs = _mapping_get(root, "jobs")
    if isinstance(jobs, yaml.MappingNode):
        for key, job in jobs.value:
            job_id = key.value if isinstance(key, yaml.ScalarNode) else None
            reusable = _mapping_get(job, "uses")
            if isinstance(reusable, yaml.ScalarNode) and reusable.value:
                out.append(
                    _with_location(parse_uses(reusable.value), job_id, None, reusable.start_mark.line + 1)
                )
            out.extend(_steps_uses(_mapping_get(job, "steps"), job_id))
    runs = _mapping_get(root, "runs")  # composite action.yml
    if runs is not None:
        out.extend(_steps_uses(_mapping_get(runs, "steps"), None))
    return out


class Verdict(StrEnum):
    MALICIOUS_PIN = "malicious-pin"  # pinned to a known-malicious commit: exposed whenever it runs
    MUTABLE_IN_SCOPE = "mutable-in-scope"  # tag/branch that was repointed: exposed inside the window
    DEPENDENT = "dependent"  # action that pulls the compromised one internally: exposed inside the window
    MUTABLE_OUT_OF_SCOPE = "mutable-out-of-scope"  # e.g. reviewdog/action-setup@v2
    SAFE_PIN = "safe-pin"  # full SHA that is not a malicious commit


EXPOSING = {Verdict.MALICIOUS_PIN, Verdict.MUTABLE_IN_SCOPE, Verdict.DEPENDENT}


def classify(ref: UsesRef, incident: Incident) -> Verdict | None:
    """Classify a reference against one incident; None when it is unrelated."""
    if ref.action is None:
        return None
    if incident.is_dependent(ref.action):
        return Verdict.DEPENDENT
    if not incident.matches_action(ref.action):
        return None
    if ref.kind is PinKind.FULL_SHA:
        return Verdict.MALICIOUS_PIN if ref.ref in incident.malicious_shas else Verdict.SAFE_PIN
    if ref.kind is PinKind.SHORT_SHA and any(s.startswith(ref.ref.lower()) for s in incident.malicious_shas):
        return Verdict.MALICIOUS_PIN
    if ref.kind is PinKind.NO_REF or ref.kind is PinKind.SHORT_SHA:
        # Cannot tell what it resolved to: fail closed.
        return Verdict.MUTABLE_IN_SCOPE
    return Verdict.MUTABLE_IN_SCOPE if incident.ref_in_scope(ref.ref) else Verdict.MUTABLE_OUT_OF_SCOPE
