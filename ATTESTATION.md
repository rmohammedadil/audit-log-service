# Attestation

**Full Name:** R Mohammed Adil

**Email:** [rmdadil25@gmail.com](mailto:rmdadil25@gmail.com)

**Assignment Title:** AI-Assisted Software Engineering System — Audit Log Service

**Assignment Start Date:** 23 November 2026

**Original Submission Date:** 26 November 2026

**Original Submission Time:** 12:30 PM IST (UTC+05:30)

## Declaration

I, R Mohammed Adil, attest that this submission is my own individual work, completed on my own machine and accounts, and that it honestly reflects my development process and use of AI.

## Reviewed Revision and Finalization

- **Repository:** https://github.com/rmohammedadil/audit-log-service.git
- **Branch:** `main`
- **Tested application revision:**
  `3b0eb5d6601e3c74f938ad8afedabf4f99140c2b`

The tested application revision is distinct from the final remediation
submission commit. A separate final submission manifest will record the final
commit SHA, archive SHA-256, actual submission timestamp, and candidate
signature after repository finalization. This document does not claim that the
final remediation submission has already occurred.

## Submitted Implementation Scope

The work covers Scenario A: core audit logging and integrity verification;
Scenario B: logical retention, redaction, and exports; and Scenario C: recorded
client-account access reporting. The supported runtime is the tenant-aware V4
application with tenant-specific integrity chains, JWT authentication, active
membership checks, and explicit resource or tenant permissions.

Material engineering claims, their source references, automated tests,
validation evidence, and limitations are mapped in
[docs/claim-evidence-mapping.md](docs/claim-evidence-mapping.md).

## AI Assistance and Reused Material

The development record in [docs/ai-usage-log.md](docs/ai-usage-log.md)
discloses the use of ChatGPT and Codex for prompts, planning, code and test
generation or revision, documentation, review support, and validation
assistance. The candidate retained responsibility for task approvals, local
execution, review decisions, and commit authorization.

The AI usage log records AI-assisted generated and revised material. Candidate
confirmation is required before final submission that any reused third-party
code, template, assessment material, or other material requiring attribution
has been accurately disclosed. This attestation does not invent a claim of no
reuse.

## Validation and Limitations

At the tested application revision, Task 51 recorded 475 passing tests in
85.09 seconds, Python 3.12.7, 90.14% line coverage, 79.12% branch coverage,
all project-defined coverage gates passing, and 25 successful live HTTP checks.
Supporting validation details are in [docs/testing.md](docs/testing.md) and
[ENGINEERING_SUMMARY.md](ENGINEERING_SUMMARY.md).

Known limitations include SQLite deployment constraints, privileged database access risks, and redaction and offline-export verification boundaries. Detailed limitations and validation status are documented in ENGINEERING_SUMMARY.md and docs/testing.md.
