# Final Repository Attestation

**Full Name:** R Mohammed Adil

**Email:** [rmdadil25@gmail.com](mailto:rmdadil25@gmail.com)

**Assignment Title:** AI-Assisted Software Engineering System — Audit Log Service

**Assignment Start Date:** 23 November 2026

**Original Submission Date:** 26 November 2026, 12:30 PM IST (UTC+05:30)

**Resubmission Date:** 27 November 2026

## Declaration

I, R Mohammed Adil, attest that this submission is my own individual work, completed on my own machine and accounts, and that it honestly reflects my development process and use of AI.

## Repository and Implementation Scope

- **Repository:** https://github.com/rmohammedadil/audit-log-service.git
  (private; submitted to the panel with read access)
- **Branch:** `main`
- **Validated application revision:**
  `78a19710a9bcd21b9fa5624ea93b83a8bf79116f`
- **Final submission revision:** annotated tag `submission-final`
  (resolve with `git rev-list -n1 submission-final`). This attestation is
  committed in that revision, a documentation-only descendant of the validated
  application revision.
- **Scope:** Scenario A (core audit log and chain verification), Scenario B
  (retention, redaction, independently verifiable export), and Scenario C
  (recorded client-account access reporting). The supported runtime is the
  tenant-aware V4 application (`app.main:app` → `app.v4_main`); legacy V3
  routes are not mounted.

The application, test, dependency, and CI inputs are byte-identical between
`3b0eb5d6601e3c74f938ad8afedabf4f99140c2b` (where the Task 51 validation ran)
and `78a19710a9bcd21b9fa5624ea93b83a8bf79116f`:

```text
git diff --stat 3b0eb5d..78a1971 -- app/ scripts/ requirements.txt pytest.ini .coveragerc .github/
# (no output)
```

Submission is via the private repository; no archive is used. If an archive is
also supplied, its SHA-256 must be recorded here before submission.

## Engineering Evidence

Material engineering claims are mapped to implementation references, automated
tests, validation evidence, and limitations in
[docs/claim-evidence-mapping.md](docs/claim-evidence-mapping.md). Supporting
development and validation records are available in
[docs/ai-usage-log.md](docs/ai-usage-log.md),
[docs/testing.md](docs/testing.md), and
[ENGINEERING_SUMMARY.md](ENGINEERING_SUMMARY.md).

## AI Assistance and Reuse Disclosure

ChatGPT and Codex assisted with prompts, planning, code and test generation or
revision, documentation, review support, and validation assistance. The
candidate retained responsibility for implementation decisions, local
execution, review, approval, and commit authorization. The detailed record is
in [docs/ai-usage-log.md](docs/ai-usage-log.md).

The candidate confirms that no third-party source code, templates, or another
candidate's assessment implementation were reused or used as a design
reference, apart from disclosed AI assistance and standard project
dependencies.

## Verified Validation Evidence

- **Validation revision:** `78a19710a9bcd21b9fa5624ea93b83a8bf79116f`
  (application inputs identical to `3b0eb5d`, where Task 51 ran).
- **Command:** `python -m pytest -q -p no:cacheprovider`
- **Environment:** Python 3.12.7, 27 November 2026, exit code 0.
- **Regression:** 475 passed, 0 failed, 1 existing Starlette/TestClient
  deprecation warning.
- **Coverage:** 90.14% line (1930/2141) and 79.12% branch (538/680).
  Independent gate
  `python scripts/check_coverage.py .coverage-reports/coverage.json`
  exited 0, including every per-module line and branch threshold.
- **Live validation:** 25 successful local live HTTP checks using a fresh V4
  database and disposable credentials.
- **Remote CI (green):** all three jobs passed — regression (475 tests plus the
  independent coverage gate), dependency vulnerability scan
  (`pip-audit --strict`), and Docker runtime smoke test — and the
  regression-evidence artifact was published.
- **GitHub Actions run:**
  https://github.com/rmohammedadil/audit-log-service/actions/runs/45934437700
- **Evidence artifact:**
  https://github.com/rmohammedadil/audit-log-service/actions/runs/45934437700/artifacts/15169658552

## Limitations

Known limitations include SQLite deployment constraints, privileged database
access risks, and redaction and offline-export verification boundaries. Detailed
limitations and validation status are documented in
[ENGINEERING_SUMMARY.md](ENGINEERING_SUMMARY.md) and
[docs/testing.md](docs/testing.md).

## Candidate Signature

**Signature:** R Mohammed Adil

**Signature date:** 27 November 2026