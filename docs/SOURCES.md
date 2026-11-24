# Sources

Checked 2026-11-23. "Verified" means read in the primary source named; "unverified" means
seen only in secondary material or not checkable from the build environment.

## Primary sources read
| # | Source | URL | Used for |
|---|---|---|---|
| S1 | GitHub Advisory GHSA-mrrh-fwg8-r2c3 (JSON from github/advisory-database) | https://github.com/advisories/GHSA-mrrh-fwg8-r2c3 (raw: https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2025/03/GHSA-mrrh-fwg8-r2c3/GHSA-mrrh-fwg8-r2c3.json) | CVE alias, window (March 14–15, 2025), malicious SHA, example repointed tags, double base64 decode, gist IOC, fixed 46.0.1, CWE-506, CVSS vector, detection credited to StepSecurity |
| S2 | GitHub Advisory GHSA-qmg3-hpqr-gqvc (JSON) | https://github.com/advisories/GHSA-qmg3-hpqr-gqvc | reviewdog window 2025-03-11 18:42–20:31 UTC, malicious commit f0d342d, list of dependent reviewdog actions, Wiz Research report credit |
| S3 | tj-actions/changed-files README at fix commit 45fb12d (linked from S1 and KEV) | https://github.com/tj-actions/changed-files/blob/45fb12d7a8bedb4da42342e52fe054c6c2c3fd73/README.md?plain=1#L20-L28 | "removed from all tags and branches"; SHA-pinned users of the malicious commit must update |
| S4 | CISA Known Exploited Vulnerabilities catalog (JSON from cisagov/kev-data) | https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json | KEV dates (CVE-2025-30066 added 2025-03-18; CVE-2025-30154 added 2025-03-24); leaked secret types "AWS access keys, GitHub personal access tokens (PATs), npm tokens, and private RSA keys" |
| S5 | GitHub REST API description (OpenAPI, github/rest-api-description) | https://github.com/github/rest-api-description | `workflow-run` fields (`id`, `path`, `head_sha` = "the version of the workflow being run", `run_started_at`, `created_at`, `run_attempt`, `event`); run-log archive endpoint |
| S6 | zizmor audit documentation | https://github.com/zizmorcore/zizmor/blob/main/docs/audits.md | Gap check: unpinned-uses, known-vulnerable-actions, impostor-commit, ref-version-mismatch are static checks of current workflow files |
| S7 | `git ls-remote https://github.com/tj-actions/changed-files` (run 2026-11-23) | — | Current tags v1.0.0, v35.7.7-sec, v44.5.1, v45.0.7 do not point to 0e58ed8; v46.0.1 exists |

## Not reachable from the build sandbox (labeled, not relied on)
- NVD CVE-2025-30066 / CVE-2025-30154 pages and the CISA alert of 2025-03-18 (DNS blocked). KEV JSON (S4) was used instead.
- Wiz, StepSecurity, Semgrep, Sysdig, GitGuardian, Checkmarx write-ups. Exact hour-level start/end of the tj-actions window appears in these; **unverified** here, so the tool uses the day-level window from S1.
- Reported link between the reviewdog compromise and the tj-actions compromise: **unverified** here; not claimed.
- The exact in-memory format of the dumped secrets: **unverified**. The decoder uses the double-base64 behavior from S1 and treats name/value extraction as a heuristic.

## Field-by-field (scoper/data/incidents.yaml)
| Field | CVE-2025-30066 | CVE-2025-30154 |
|---|---|---|
| window | S1, day precision (whole days used) | S2, minute precision |
| malicious_shas | S1 (full SHA) | S2 (full SHA in the commit link) |
| mutable_refs_exposed | `all`, from S3 | `v1`, from S2 (affected versions: ["1"]) |
| transitive_dependents | none | S2 list |
| iocs | S1 (gist path, memdump.py) | none in S2 |
| log_encoding | S1 (`base64 -d \| base64 -d`) | not stated in S2 |
