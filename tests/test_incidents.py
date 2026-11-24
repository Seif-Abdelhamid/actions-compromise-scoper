from datetime import UTC, datetime

import pytest

from scoper.incidents import IncidentError, load_incidents, parse_utc

from .conftest import RD_BAD, TJ_BAD


def test_bundled_incidents_match_sources(incidents):
    by_id = {i.id: i for i in incidents}
    tj = by_id["CVE-2025-30066"]
    assert tj.ghsa == "GHSA-mrrh-fwg8-r2c3"
    assert tj.action == "tj-actions/changed-files"
    assert tj.malicious_shas == (TJ_BAD,)
    assert tj.mutable_refs_exposed == "all"
    assert tj.fixed_version == "46.0.1"
    assert tj.log_encoding == "double-base64"
    rd = by_id["CVE-2025-30154"]
    assert rd.malicious_shas == (RD_BAD,)
    assert rd.start == datetime(2025, 3, 11, 18, 42, tzinfo=UTC)
    assert rd.end == datetime(2025, 3, 11, 20, 31, tzinfo=UTC)
    assert "reviewdog/action-shellcheck" in rd.transitive_dependents


def test_window_is_half_open(incidents):
    rd = {i.id: i for i in incidents}["CVE-2025-30154"]
    assert rd.in_window(parse_utc("2025-03-11T18:42:00Z"))
    assert rd.in_window(parse_utc("2025-03-11T20:30:59Z"))
    assert not rd.in_window(parse_utc("2025-03-11T20:31:00Z"))
    assert not rd.in_window(parse_utc("2025-03-11T18:41:59Z"))


def test_day_precision_window_covers_both_days(incidents):
    tj = {i.id: i for i in incidents}["CVE-2025-30066"]
    assert tj.precision == "day"
    assert tj.in_window(parse_utc("2025-03-14T00:00:00Z"))
    assert tj.in_window(parse_utc("2025-03-15T23:59:59Z"))
    assert not tj.in_window(parse_utc("2025-03-16T00:00:00Z"))
    assert tj.in_window(parse_utc("2025-03-15T08:00:00-05:00"))  # offsets normalised to UTC


def test_naive_timestamp_rejected():
    with pytest.raises(IncidentError):
        parse_utc("2025-03-14T10:00:00")


@pytest.mark.parametrize(
    "body, msg",
    [
        ("incidents: [{id: X}]", "missing"),
        (
            "incidents: [{id: X, ghsa: G, action: 'bad name', summary: s, malicious_shas: [], "
            "mutable_refs_exposed: all, window: {start: '2025-01-01T00:00:00Z', end: '2025-01-02T00:00:00Z'}}]",
            "bad action",
        ),
        (
            "incidents: [{id: X, ghsa: G, action: a/b, summary: s, malicious_shas: [abc123], "
            "mutable_refs_exposed: all, window: {start: '2025-01-01T00:00:00Z', end: '2025-01-02T00:00:00Z'}}]",
            "full 40-hex",
        ),
        (
            "incidents: [{id: X, ghsa: G, action: a/b, summary: s, malicious_shas: [], "
            "mutable_refs_exposed: all, window: {start: '2025-01-02T00:00:00Z', end: '2025-01-01T00:00:00Z'}}]",
            "after start",
        ),
        ("nope: 1", "top-level"),
    ],
)
def test_invalid_definitions_rejected(tmp_path, body, msg):
    f = tmp_path / "inc.yaml"
    f.write_text(body)
    with pytest.raises(IncidentError, match=msg):
        load_incidents(f)
