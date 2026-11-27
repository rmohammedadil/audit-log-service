"""Independently enforce line and branch coverage from coverage.py JSON."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


OVERALL_LINE_THRESHOLD = 90
OVERALL_BRANCH_THRESHOLD = 78
CRITICAL_LINE_THRESHOLD = 85
CRITICAL_BRANCH_THRESHOLD = 70
LEGACY_LINE_THRESHOLD = 80
LEGACY_BRANCH_THRESHOLD = 60

CRITICAL_MODULES = (
    "app/auth.py",
    "app/authorization_models.py",
    "app/authorization_service.py",
    "app/permissions.py",
    "app/api/v4_audit_routes.py",
    "app/services/v4_audit_service.py",
    "app/services/v4_export_service.py",
    "app/v4_database.py",
    "app/v4_database_dependency.py",
    "app/v4_main.py",
    "app/v4_models.py",
    "app/v4_schemas.py",
    "app/verify_v4_export.py",
    "app/export_signing.py",
    "app/manage_grants.py",
)
LEGACY_VERIFIER = "app/verify_export.py"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


class CoverageEvidenceError(ValueError):
    """Raised when coverage evidence cannot safely support a gate decision."""


@dataclass(frozen=True)
class Counts:
    covered_lines: int
    lines: int
    covered_branches: int
    branches: int


def _normal_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./")


def _nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise CoverageEvidenceError(f"{field} must be a nonnegative integer")
    return value


def _counts(summary: object, label: str) -> Counts:
    if not isinstance(summary, Mapping):
        raise CoverageEvidenceError(f"{label} has no valid summary")
    lines = _nonnegative_int(summary.get("num_statements"), f"{label}.num_statements")
    covered_lines = _nonnegative_int(summary.get("covered_lines"), f"{label}.covered_lines")
    missing_lines = _nonnegative_int(summary.get("missing_lines"), f"{label}.missing_lines")
    branches = _nonnegative_int(summary.get("num_branches"), f"{label}.num_branches")
    covered_branches = _nonnegative_int(summary.get("covered_branches"), f"{label}.covered_branches")
    missing_branches = _nonnegative_int(summary.get("missing_branches"), f"{label}.missing_branches")
    partial_branches = _nonnegative_int(
        summary.get("num_partial_branches", 0), f"{label}.num_partial_branches"
    )
    if covered_lines + missing_lines != lines:
        raise CoverageEvidenceError(f"{label} has inconsistent line counts")
    if covered_branches + missing_branches != branches:
        raise CoverageEvidenceError(f"{label} has inconsistent branch counts")
    if partial_branches > missing_branches:
        raise CoverageEvidenceError(f"{label} has impossible partial branch counts")
    return Counts(covered_lines, lines, covered_branches, branches)


def _passes(covered: int, total: int, threshold: int) -> bool:
    return total == 0 or covered * 100 >= threshold * total


def _percentage(covered: int, total: int) -> str:
    return "N/A" if total == 0 else f"{covered * 100 / total:.2f}%"


def _source_modules(source_root: Path) -> set[str]:
    if not source_root.is_dir():
        raise CoverageEvidenceError(f"application source directory is missing: {source_root}")
    return {
        f"app/{path.relative_to(source_root).as_posix()}"
        for path in source_root.rglob("*.py")
    }


def _load_report(report_path: Path) -> Mapping[str, Any]:
    try:
        decoded = json.loads(report_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise CoverageEvidenceError(f"coverage report is missing: {report_path}") from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CoverageEvidenceError(f"coverage report is unreadable or malformed: {report_path}") from error
    if not isinstance(decoded, Mapping):
        raise CoverageEvidenceError("coverage report root must be an object")
    return decoded


def evaluate_report(report_path: Path, *, source_root: Path | None = None) -> tuple[bool, list[str]]:
    """Validate evidence and return the gate result plus readable output lines."""

    report = _load_report(report_path)
    meta = report.get("meta")
    files = report.get("files")
    if not isinstance(meta, Mapping) or meta.get("branch_coverage") is not True:
        raise CoverageEvidenceError("branch coverage is not enabled")
    if not isinstance(files, Mapping) or not files:
        raise CoverageEvidenceError("coverage report has no file summaries")

    summaries: dict[str, Counts] = {}
    for path, entry in files.items():
        if not isinstance(path, str) or not isinstance(entry, Mapping):
            raise CoverageEvidenceError("coverage report contains an invalid file entry")
        normalized = _normal_path(path)
        if normalized in summaries:
            raise CoverageEvidenceError(f"duplicate normalized coverage path: {normalized}")
        if not normalized.startswith("app/"):
            raise CoverageEvidenceError(f"coverage report includes non-application source: {normalized}")
        summaries[normalized] = _counts(entry.get("summary"), normalized)

    source_modules = _source_modules(source_root or PROJECT_ROOT / "app")
    missing_source = sorted(source_modules - set(summaries))
    if missing_source:
        raise CoverageEvidenceError("application source missing from coverage: " + ", ".join(missing_source))
    required = set(CRITICAL_MODULES) | {LEGACY_VERIFIER}
    missing_required = sorted(required - set(summaries))
    if missing_required:
        raise CoverageEvidenceError("required module missing from coverage: " + ", ".join(missing_required))

    calculated = Counts(
        sum(item.covered_lines for item in summaries.values()),
        sum(item.lines for item in summaries.values()),
        sum(item.covered_branches for item in summaries.values()),
        sum(item.branches for item in summaries.values()),
    )
    reported = _counts(report.get("totals"), "totals")
    if calculated != reported:
        raise CoverageEvidenceError("overall totals do not match file-level summaries")

    lines: list[str] = []
    passed = True

    def record(label: str, counts: Counts, line_threshold: int, branch_threshold: int) -> None:
        nonlocal passed
        line_pass = _passes(counts.covered_lines, counts.lines, line_threshold)
        branch_pass = _passes(counts.covered_branches, counts.branches, branch_threshold)
        passed = passed and line_pass and branch_pass
        lines.append(
            f"{'PASS' if line_pass else 'FAIL'} {label} lines "
            f"{counts.covered_lines}/{counts.lines} ({_percentage(counts.covered_lines, counts.lines)}; "
            f"threshold {line_threshold}%)"
        )
        branch_display = "N/A" if counts.branches == 0 else _percentage(counts.covered_branches, counts.branches)
        lines.append(
            f"{'PASS' if branch_pass else 'FAIL'} {label} branches "
            f"{counts.covered_branches}/{counts.branches} ({branch_display}; "
            f"threshold {branch_threshold}%{' / N/A accepted' if counts.branches == 0 else ''})"
        )

    record("overall", calculated, OVERALL_LINE_THRESHOLD, OVERALL_BRANCH_THRESHOLD)
    for module in CRITICAL_MODULES:
        record(module, summaries[module], CRITICAL_LINE_THRESHOLD, CRITICAL_BRANCH_THRESHOLD)
    record(LEGACY_VERIFIER, summaries[LEGACY_VERIFIER], LEGACY_LINE_THRESHOLD, LEGACY_BRANCH_THRESHOLD)
    return passed, lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enforce independent coverage thresholds")
    parser.add_argument(
        "report",
        nargs="?",
        default=PROJECT_ROOT / ".coverage-reports" / "coverage.json",
        type=Path,
        help="path to coverage.py JSON evidence",
    )
    args = parser.parse_args(argv)
    try:
        passed, lines = evaluate_report(args.report)
    except CoverageEvidenceError as error:
        print(f"FAIL invalid coverage evidence: {error}", file=sys.stderr)
        return 2
    for line in lines:
        print(line)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
