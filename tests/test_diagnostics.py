from __future__ import annotations

import pytest

from polymorph.diagnostics import explain_reason


@pytest.mark.parametrize(
    "code",
    [
        "source_schema_id_mismatch",
        "target_schema_id_mismatch",
        "source_schema_drift",
        "target_schema_drift",
        "unknown_source_field",
        "unknown_target_field",
        "duplicate_target",
        "unknown_transform",
        "policy_violation",
        "type_mismatch",
        "required_target_unmapped",
        "record_schema_mismatch",
        "required_source_missing",
        "required_target_null",
        "source_transform_failed",
        "transformed_type_mismatch",
        "foreign_key_lookup_not_exercised",
        "foreign_key_lookup_invalid",
        "foreign_key_lookup_failed",
        "foreign_key_resolved_null",
        "source_iteration_failed",
        "empty_source",
        "sampled_scan",
        "spreadsheet_formula_cache",
        "preflight_not_promotable",
        "preflight_promotable",
        "no_auto_approved_mapping_rules",
        "recipe_rebind_failed",
        "recipe_auto_reuse_suspended",
        "delivery_claim_in_progress",
        "delivery_claim_lost",
        "previous_write_started_ambiguous",
        "previous_delivery_ambiguous",
        "write_outcome_unknown",
        "delivery_outcome_record_failed",
        "write_not_committed",
        "transport_verification_failed",
        "destination_contract_failed",
        "destination_resolution_failed",
        "relay_wire_invalid",
        "relay_source_authentication_failed",
        "relay_transfer_expired",
        "relay_policy_rejected",
        "relay_digest_mismatch",
    ],
)
def test_internal_reason_codes_have_specific_operator_guidance(code: str) -> None:
    diagnostic = explain_reason(code)

    assert diagnostic.category != "unknown"
    assert diagnostic.next_action
    assert diagnostic.retry_policy


def test_unknown_reason_code_fails_to_generic_inspection_guidance() -> None:
    diagnostic = explain_reason("future_component_reason")

    assert diagnostic.category == "unknown"
    assert diagnostic.retry_policy == "inspect_before_retry"
