"""Synthetic-evidence tests for the independent coverage threshold gate."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_coverage.py"


@pytest.fixture(scope="module")
def gate_module():
    spec = importlib.util.spec_from_file_location("coverage_gate", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _summary(lines: int = 100, covered_lines: int = 95, branches: int = 100, covered_branches: int = 80) -> dict[str, int]:
    return {
        "num_statements": lines,
        "covered_lines": covered_lines,
        "missing_lines": lines - covered_lines,
        "num_branches": branches,
        "covered_branches": covered_branches,
        "missing_branches": branches - covered_branches,
        "num_partial_branches": 0,
    }


def _report(gate_module, summaries: dict[str, dict[str, int]] | None = None, *, branch_coverage: bool = True) -> dict[str, object]:
    if summaries is None:
        summaries = {
            module: _summary(covered_lines=95, covered_branches=80)
            for module in gate_module.CRITICAL_MODULES
        }
        summaries[gate_module.LEGACY_VERIFIER] = _summary(covered_lines=90, covered_branches=80)
    totals = {
        key: sum(summary[key] for summary in summaries.values())
        for key in (
            "num_statements", "covered_lines", "missing_lines", "num_branches",
            "covered_branches", "missing_branches", "num_partial_branches",
        )
    }
    return {
        "meta": {"branch_coverage": branch_coverage},
        "files": {path: {"summary": summary} for path, summary in summaries.items()},
        "totals": totals,
    }


def _write(tmp_path: Path, report: object) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _source_root(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _evaluate(gate_module, tmp_path: Path, report: object):
    return gate_module.evaluate_report(_write(tmp_path, report), source_root=_source_root(tmp_path))


def test_valid_report_passes_all_thresholds(gate_module, tmp_path: Path) -> None:
    passed, output = _evaluate(gate_module, tmp_path, _report(gate_module))
    assert passed and all(line.startswith("PASS") for line in output)


def test_overall_line_failure_is_independent(gate_module, tmp_path: Path) -> None:
    report = _report(gate_module)
    report["files"]["app/low_lines.py"] = {"summary": _summary(10_000, 0, 100, 100)}
    report["totals"] = _report(gate_module, {key: value["summary"] for key, value in report["files"].items()})["totals"]
    passed, output = _evaluate(gate_module, tmp_path, report)
    assert not passed and output[0].startswith("FAIL overall lines") and output[1].startswith("PASS overall branches")


def test_overall_branch_failure_is_independent(gate_module, tmp_path: Path) -> None:
    report = _report(gate_module)
    report["files"]["app/low_branches.py"] = {"summary": _summary(100, 100, 10_000, 0)}
    report["totals"] = _report(gate_module, {key: value["summary"] for key, value in report["files"].items()})["totals"]
    passed, output = _evaluate(gate_module, tmp_path, report)
    assert not passed and output[0].startswith("PASS overall lines") and output[1].startswith("FAIL overall branches")


def test_critical_module_line_and_branch_failures(gate_module, tmp_path: Path) -> None:
    report = _report(gate_module)
    report["files"]["app/auth.py"]["summary"] = _summary(covered_lines=84, covered_branches=69)
    report["totals"] = _report(gate_module, {key: value["summary"] for key, value in report["files"].items()})["totals"]
    passed, output = _evaluate(gate_module, tmp_path, report)
    auth_lines = [line for line in output if line.startswith("FAIL app/auth.py")]
    assert not passed and len(auth_lines) == 2


def test_legacy_verifier_threshold_failure(gate_module, tmp_path: Path) -> None:
    report = _report(gate_module)
    report["files"][gate_module.LEGACY_VERIFIER]["summary"] = _summary(covered_lines=79, covered_branches=59)
    report["totals"] = _report(gate_module, {key: value["summary"] for key, value in report["files"].items()})["totals"]
    passed, output = _evaluate(gate_module, tmp_path, report)
    assert not passed and sum(line.startswith("FAIL app/verify_export.py") for line in output) == 2


def test_missing_required_module_and_missing_source_file_fail(gate_module, tmp_path: Path) -> None:
    report = _report(gate_module)
    report["files"].pop("app/auth.py")
    with pytest.raises(gate_module.CoverageEvidenceError, match="required module"):
        _evaluate(gate_module, tmp_path, report)

    source_root = _source_root(tmp_path / "source")
    (source_root / "uncovered.py").write_text("value = 1\n", encoding="utf-8")
    with pytest.raises(gate_module.CoverageEvidenceError, match="application source missing"):
        gate_module.evaluate_report(_write(tmp_path / "source", _report(gate_module)), source_root=source_root)


@pytest.mark.parametrize(
    "report",
    [
        None,
        "{not json",
        {"meta": {"branch_coverage": False}, "files": {}, "totals": {}},
    ],
)
def test_missing_malformed_and_branch_disabled_evidence_fails(gate_module, tmp_path: Path, report: object) -> None:
    path = tmp_path / "coverage.json"
    if report is None:
        with pytest.raises(gate_module.CoverageEvidenceError, match="missing"):
            gate_module.evaluate_report(path, source_root=_source_root(tmp_path))
        return
    if isinstance(report, str):
        path.write_text(report, encoding="utf-8")
    else:
        path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(gate_module.CoverageEvidenceError, match="branch coverage|malformed"):
        gate_module.evaluate_report(path, source_root=_source_root(tmp_path))


@pytest.mark.parametrize("field,value", [("covered_lines", 101), ("missing_branches", -1)])
def test_invalid_counts_fail(gate_module, tmp_path: Path, field: str, value: int) -> None:
    report = _report(gate_module)
    report["files"]["app/auth.py"]["summary"][field] = value
    with pytest.raises(gate_module.CoverageEvidenceError, match="inconsistent|nonnegative"):
        _evaluate(gate_module, tmp_path, report)


def test_totals_must_match_file_level_summaries(gate_module, tmp_path: Path) -> None:
    report = _report(gate_module)
    report["totals"]["covered_lines"] -= 1
    with pytest.raises(gate_module.CoverageEvidenceError, match="totals"):
        _evaluate(gate_module, tmp_path, report)


def test_zero_branch_modules_report_na(gate_module, tmp_path: Path) -> None:
    report = _report(gate_module)
    report["files"]["app/authorization_models.py"]["summary"] = _summary(100, 100, 0, 0)
    report["totals"] = _report(gate_module, {key: value["summary"] for key, value in report["files"].items()})["totals"]
    passed, output = _evaluate(gate_module, tmp_path, report)
    assert passed and any("app/authorization_models.py branches 0/0 (N/A" in line for line in output)


def test_exact_boundaries_pass_and_rounding_does_not_hide_failure(gate_module, tmp_path: Path) -> None:
    report = _report(gate_module)
    report["files"]["app/auth.py"]["summary"] = _summary(100, 85, 100, 70)
    report["files"][gate_module.LEGACY_VERIFIER]["summary"] = _summary(100, 80, 100, 60)
    report["totals"] = _report(gate_module, {key: value["summary"] for key, value in report["files"].items()})["totals"]
    assert _evaluate(gate_module, tmp_path, report)[0]

    rounded = {
        module: _summary(99_999, 89_996, 100, 100)
        for module in (*gate_module.CRITICAL_MODULES, gate_module.LEGACY_VERIFIER)
    }
    report = _report(gate_module, rounded)
    passed, output = _evaluate(gate_module, tmp_path, report)
    assert not passed and "90.00%" in output[0] and output[0].startswith("FAIL overall lines")


def test_main_returns_documented_exit_codes(gate_module, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source_root = _source_root(tmp_path)
    monkeypatch.setattr(gate_module, "PROJECT_ROOT", tmp_path)
    valid = _write(tmp_path, _report(gate_module))
    assert gate_module.main([str(valid)]) == 0

    failing = _report(gate_module)
    failing["files"]["app/auth.py"]["summary"] = _summary(covered_lines=84)
    failing["totals"] = _report(gate_module, {key: value["summary"] for key, value in failing["files"].items()})["totals"]
    assert gate_module.main([str(_write(tmp_path / "failing", failing))]) == 1

    assert gate_module.main([str(tmp_path / "missing.json")]) == 2
    assert source_root.is_dir()
