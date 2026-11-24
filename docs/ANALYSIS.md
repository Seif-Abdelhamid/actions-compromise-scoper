# Analysis: tj-actions/changed-files (CVE-2025-30066) and reviewdog/action-setup (CVE-2025-30154)

Every fact below is from the sources in [SOURCES.md](SOURCES.md) (S#). Anything only seen in
secondary write-ups is marked **unverified**. This project discovered neither incident: the
tj-actions compromise was detected by StepSecurity and the reviewdog one reported by Wiz Research
(per S1 and S2).

## Timeline (UTC)
| Date | Event | Source |
|---|---|---|
| 2025-03-11 18:42–20:31 | `reviewdog/action-setup@v1` compromised; malicious code dumped exposed secrets to workflow logs | S2 |
| 2025-03-14 to 2025-03-15 | Tags of `tj-actions/changed-files` repointed to malicious commit `0e58ed8671d6b60d0890c21b07f8835ace038e67` | S1 |
| after the incident | Maintainer removed the malicious commit "from all tags and branches"; fixed in 46.0.1 | S1, S3 |
| 2025-03-18 | CVE-2025-30066 added to CISA KEV | S4 |
| 2025-03-24 | CVE-2025-30154 added to CISA KEV | S4 |

Exact hour-level start/end of the tj-actions window: **unverified** (secondary sources only); the tool uses whole days.
A causal link between the two compromises: **unverified**, not claimed.

## Mechanism
1. **Mutable references.** A workflow that says `uses: tj-actions/changed-files@v44` follows
   whatever commit the tag points to at run time. Whoever can push to the action repo can move it.
2. **Repointing.** Existing version tags were moved to one malicious commit (S1), so every
   tag-pinned workflow ran it on its next run.
3. **Payload.** The malicious commit fetched a script (the advisory lists the gist path and
   `memdump.py`) that dumped the runner's memory and printed secrets into the job log,
   double base64-encoded; the advisory's recovery is `base64 -d | base64 -d` (S1).
4. **Why logs matter.** On public repositories, job logs are readable by anyone, so printed secrets were exposed beyond the runner (S1).
5. **Why today's files look clean.** After cleanup the tags point to good commits again (S3, S7),
   so scoping must use each run's `head_sha` and start time, not HEAD.

The lab in `lab/` reproduces steps 1–3 with local git and canary values (no fetch, no memory dump).

## Remediation
- **Scope:** find runs that executed an affected ref inside the window (this tool), and read their logs.
- **Rotate:** every secret printed in a log or readable by an exposed run (`GITHUB_TOKEN` included for the run's lifetime); the report lists names and fingerprints.
- **Pin:** use full 40-hex commit SHAs for third-party actions; review updates deliberately.
- **Restrict:** least-privilege `permissions:` on workflows; avoid `secrets: inherit`.
- **Detect:** the Sigma rules in `detections/` for runner egress and process telemetry.
