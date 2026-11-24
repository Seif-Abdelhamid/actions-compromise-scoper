# actions-compromise-scoper

Offline incident scoping for compromised GitHub Actions. Given your exported workflow runs, a
local clone and the run logs, it answers: **which runs executed the compromised action during
the exposure window, and which secrets did those runs print?** It ships definitions for two
published incidents:

| CVE | Advisory | Action | Exposure window (UTC) |
|---|---|---|---|
| CVE-2025-30066 | [GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3) | `tj-actions/changed-files` | 2025-03-14 to 2025-03-15 (advisory gives dates only; whole days used) |
| CVE-2025-30154 | [GHSA-qmg3-hpqr-gqvc](https://github.com/advisories/GHSA-qmg3-hpqr-gqvc) | `reviewdog/action-setup@v1` (+ 5 reviewdog actions that use it) | 2025-03-11 18:42 to 20:31 |

Both are in the CISA Known Exploited Vulnerabilities catalog. The tj-actions compromise was
detected by StepSecurity and the reviewdog one reported by Wiz Research (per the advisories).
This project credits them and reproduces the mechanism locally; it discovered neither.

## Intended users
- SOC / incident responders scoping a CI/CD supply-chain incident.
- Platform / DevSecOps engineers deciding which secrets to rotate, with evidence instead of guesses.

## Problem
The malicious commit dumped the runner's memory and printed secrets into the job log,
double base64-encoded (the advisory's recovery step is `base64 -d | base64 -d`). The
maintainer then removed the commit "from all tags and branches", so **today's workflow
files look clean**. To scope the incident you need the workflow *as it was at the commit
that ran*, the run's start time, and the log contents. Doing that by hand for every run is
slow and easy to get wrong.

## Usage
```bash
pip install -e .
# Evidence you export yourself from your own repository (read-only):
gh api --paginate "repos/OWNER/REPO/actions/runs?created=2025-03-10..2025-03-17" > runs.json
# For each run of interest, save its log archive as logs/logs_RUN_ID.zip
# (REST "Download workflow run logs": GET /repos/OWNER/REPO/actions/runs/RUN_ID/logs,
#  which answers with a short-lived redirect to the zip).
git clone https://github.com/OWNER/REPO repo   # full history, so old head_sha commits resolve

actions-scope scope --runs runs.json --repo repo --logs logs            # Markdown report
actions-scope scope --runs runs.json --repo repo --logs logs --format json --out report.json
actions-scope workflows repo/.github/workflows                          # static check of current files
actions-scope logs logs/logs_RUN_ID.zip                                 # scan one archive
```
Exit codes: `0` no exposure, `1` exposed runs found, `2` inconclusive (evidence missing:
treat as exposed until proven otherwise), `3` usage error.

## How a run is judged
| Workflow reference at `head_sha` | Run inside window | Run outside window |
|---|---|---|
| pinned to a known-malicious commit SHA | exposed | exposed |
| tag / branch / short SHA / no ref of the affected action | exposed | out of window |
| an action that uses the compromised one internally (reviewdog list) | exposed | out of window |
| full SHA of a different commit | not exposed | out of window |
| workflow, local action or reusable workflow unreadable, or remote reusable workflow | possibly exposed | out of window |

Decoded log blobs always mark a run exposed. Secret values are never printed: the report
shows the secret's name, a 16-hex SHA-256 fingerprint and a type hint.

## Sources
See [docs/SOURCES.md](docs/SOURCES.md) for every fact used and what could not be verified.

## Local lab: reproduce tag repointing (no network, canaries only)

`scripts/demo.sh` builds everything with local git and synthetic files, then scopes it:

1. **Mechanism.** A stand-in action repo publishes tag `v44` on a benign commit; the tag is then
   force-moved (`git tag -f`) to a commit whose only "payload" echoes a pre-encoded blob of
   **canary** values (no memory dump, no real secrets). The lab checks that a tag pin resolves
   to the new commit and a full-SHA pin still resolves to the old one.
2. **Corpus.** A consumer repo whose history uses `tj-actions/changed-files@v44` (tag), a full-SHA
   pin, and `reviewdog/action-shellcheck@v1`; a REST-shaped runs export; run logs, one carrying
   the double-base64 canary dump.

```
$ ./scripts/demo.sh
tag v44 before: f819354b469c -> after: 77a7072a87e6 | tag pin followed move: True | SHA pin unchanged: True
Runs: exposed: 2, possibly-exposed: 1, not-exposed: 1, out-of-window: 1   (exit 1)
OK: no canary value appears in the report
```
(SHAs differ per run.)

## Detection content

`detections/` ships two Sigma rules built only from the advisory's published indicators (S1):

| Rule | Log source | Matches |
|---|---|---|
| `tj_actions_payload_fetch_proxy.yml` | proxy / egress | requests for the payload gist path |
| `tj_actions_memdump_exec_linux.yml` | Linux process creation | `memdump.py` executed, or a command line fetching the payload gist |

Both parse with zero errors and zero findings under pySigma 2.1.0's built-in validators, and
`tests/test_detections.py` checks them against labeled **synthetic** samples in
`detections/samples/` (positives match, negatives don't).

## Results (synthetic lab corpus)

Measured with `scripts/demo.sh` and `tests/test_lab.py` on the generated lab corpus (5 runs,
3 log archives, 3 canary secrets). Synthetic data: this shows the logic is correct, not how often
real incidents look like this.

| Run | Situation | Expected | Scoper verdict |
|---|---|---|---|
| 1001 | tag pin, inside the CVE-2025-30066 window, log has the double-base64 dump | exposed | exposed; 3/3 secret names recovered from the blob, 0 values printed |
| 1002 | full-SHA pin of a different commit, inside the window | not exposed | not exposed |
| 1003 | tag pin, after the window | out of window | out of window |
| 1004 | `head_sha` missing from the clone, inside the window | possibly exposed | possibly exposed (fail closed) |
| 1005 | `reviewdog/action-shellcheck@v1` inside the CVE-2025-30154 window, no logs | exposed | exposed; every referenced secret listed for rotation |

5/5 runs classified as expected; the rotation list names `AWS_ACCESS_KEY_ID`, `GH_PAT`,
`NPM_TOKEN` and `GITHUB_TOKEN` with evidence per run.

## Existing tools reviewed

| Tool | What it does | Gap this project fills |
|---|---|---|
| [zizmor](https://github.com/zizmorcore/zizmor/blob/main/docs/audits.md) | Static audits of workflow files as they are now (`unpinned-uses`, `known-vulnerable-actions`, `impostor-commit`) | No run history, time window or log analysis |
| GitHub advisory / Dependabot | Flags the dependency by version range | Same current-state view |
| Vendor runtime tools (e.g. Harden-Runner) | Runtime monitoring that must already be running | Not usable after the fact; vendor docs were not reachable from the build environment, so not compared in detail |

## Limitations
- Remote reusable workflows and third-party composite actions are not opened; runs that use
  them inside a window are reported as possibly exposed.
- The tj-actions window is day-level (the advisory gives dates only), so it over-reports by design.
- Secret name/value extraction from decoded blobs is a heuristic: the exact dump format is
  unverified (see docs/SOURCES.md). Names referenced by the workflow are listed regardless.
- Works only on evidence you export from your own repositories; it never calls GitHub itself.

## Adopting or extending it
- Add an incident: append to `scoper/data/incidents.yaml` (window, malicious SHAs, IOCs,
  transitive dependents) with a source for every field.
- Wire the JSON report into a ticket or SOAR flow; exit code 2 means "collect more evidence".
- Pin third-party actions to full SHAs (this repo's CI does) and use `actions-scope workflows`
  in CI to flag mutable refs to affected actions.

MIT licensed. Analysis of the two incidents: [docs/ANALYSIS.md](docs/ANALYSIS.md).
