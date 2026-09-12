from __future__ import annotations

import json

from polymorph.memory_advisor import (
    MIB,
    BatchProfile,
    calibration_contract_mismatches,
    discover_latest_matrix,
    matrix_minimum_authoritative_runs,
    recommend_batch,
)

PROFILES = (
    BatchProfile(100, 375.11, int(92.31 * MIB), 3),
    BatchProfile(250, 397.61, int(96.98 * MIB), 3),
    BatchProfile(500, 409.10, int(104.75 * MIB), 3),
    BatchProfile(1000, 413.11, int(121.02 * MIB), 3),
)


def test_recommends_500_for_128_mib_budget() -> None:
    result = recommend_batch(PROFILES, max_ram_bytes=128 * MIB)

    assert result["status"] == "recommended"
    assert result["recommended_batch_size"] == 500
    assert result["hard_limit_enforced"] is False


def test_recommends_250_when_500_lacks_headroom() -> None:
    result = recommend_batch(PROFILES, max_ram_bytes=115 * MIB)

    assert result["status"] == "recommended"
    assert result["recommended_batch_size"] == 250


def test_blocks_budget_below_smallest_measured_profile() -> None:
    result = recommend_batch(PROFILES, max_ram_bytes=100 * MIB)

    assert result["status"] == "blocked"
    assert result["reason_code"] == "memory_budget_below_measured_minimum"
    assert result["recommended_batch_size"] is None


def test_prefers_lower_memory_profile_inside_speed_band() -> None:
    result = recommend_batch(PROFILES, max_ram_bytes=512 * MIB)

    assert result["recommended_batch_size"] == 500
    assert result["fastest_eligible_batch_size"] == 1000
    assert float(result["speed_gap_to_fastest_eligible_percent"]) < 2.0


def test_zero_speed_tolerance_selects_fastest_profile() -> None:
    result = recommend_batch(
        PROFILES,
        max_ram_bytes=512 * MIB,
        near_optimal_percent=0.0,
    )

    assert result["recommended_batch_size"] == 1000


def test_matrix_discovery_prefers_publishable_evidence(tmp_path) -> None:
    root = tmp_path / ".polymorph" / "performance-matrix"
    publishable = root / "older" / "matrix.json"
    preliminary = root / "newer" / "matrix.json"
    publishable.parent.mkdir(parents=True)
    preliminary.parent.mkdir(parents=True)

    def matrix(runs: int) -> dict[str, object]:
        return {
            "summaries": [
                {
                    "batch_size": 100,
                    "runs": runs,
                    "throughput_rows_per_second_median": 375.0,
                    "peak_rss_bytes_max": 96 * MIB,
                }
            ]
        }

    publishable.write_text(json.dumps(matrix(3)), encoding="utf-8")
    preliminary.write_text(json.dumps(matrix(1)), encoding="utf-8")

    assert discover_latest_matrix(tmp_path) == publishable


def test_matrix_discovery_prefers_exact_preliminary_over_stale_publishable(tmp_path) -> None:
    root = tmp_path / ".polymorph" / "performance-matrix"
    stale = root / "stale" / "matrix.json"
    exact = root / "exact" / "matrix.json"
    stale.parent.mkdir(parents=True)
    exact.parent.mkdir(parents=True)
    expected = {"schema_version": 2, "runtime_tree_sha256": "a" * 64}

    def matrix(runs: int, contract: dict[str, object]) -> dict[str, object]:
        return {
            "calibration_contract": contract,
            "summaries": [
                {
                    "batch_size": 100,
                    "runs": runs,
                    "throughput_rows_per_second_median": 375.0,
                    "peak_rss_bytes_max": 96 * MIB,
                }
            ],
        }

    stale.write_text(
        json.dumps(matrix(3, {**expected, "runtime_tree_sha256": "b" * 64})),
        encoding="utf-8",
    )
    exact.write_text(json.dumps(matrix(1, expected)), encoding="utf-8")

    assert discover_latest_matrix(tmp_path, expected_contract=expected) == exact


def test_calibration_contract_reports_missing_and_mismatched_authority() -> None:
    expected = {"schema_version": 2, "python_version": "3.11.9"}

    assert calibration_contract_mismatches(
        {"schema_version": 1},
        expected,
    ) == ("missing:python_version", "mismatch:schema_version")


def test_rejected_probe_does_not_downgrade_authoritative_run_count() -> None:
    profiles = [
        BatchProfile(100, 380.0, 90 * MIB, 3),
        BatchProfile(250, 410.0, 98 * MIB, 3),
        BatchProfile(1000, 420.0, 130 * MIB, 1),
    ]
    document = {"measurement_policy": {"admitted_batch_sizes": [100, 250]}}

    assert matrix_minimum_authoritative_runs(document, profiles) == 3
