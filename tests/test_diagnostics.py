from __future__ import annotations

import pytest

from polymorph.diagnostics import explain_reason
from polymorph.isolation import SandboxErrorCode


@pytest.mark.parametrize(
    "code",
    [
        "observability_append_failed",
        "observability_stream_invalid",
        "observability_lifecycle_invalid",
        "observability_event_contract_invalid",
        "observability_event_count_mismatch",
        "destination_operational_event_status_unexpected",
        "destination_operational_event_context_missing",
        "containment_too_weak",
        "backend_unavailable",
        "worker_timeout",
        "worker_output_limit",
        "input_snapshot_changed",
        "protocol_error",
        "operational_run_not_found",
        "operational_failure_status_present",
        "operational_run_not_closed",
        "operational_event_contract_invalid",
        "operational_workflow_count_mismatch",
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
        "nullable_source_to_required_target",
        "source_type_unknown",
        "required_target_unmapped",
        "record_schema_mismatch",
        "required_source_missing",
        "required_target_null",
        "source_transform_failed",
        "transformed_type_mismatch",
        "foreign_key_lookup_not_exercised",
        "foreign_key_lookup_invalid",
        "foreign_key_lookup_contract_invalid",
        "foreign_key_lookup_source_type_unknown",
        "foreign_key_lookup_type_unknown",
        "foreign_key_lookup_type_mismatch",
        "foreign_key_lookup_input_type_mismatch",
        "foreign_key_lookup_failed",
        "foreign_key_resolved_null",
        "foreign_key_resolved_type_mismatch",
        "source_iteration_failed",
        "source_content_unsafe",
        "source_content_not_delimited_text",
        "mapping_not_fully_automatic",
        "mapping_fixture_mismatch",
        "mapping_plan_incomplete",
        "source_record_not_signed",
        "outbox_pending_count_mismatch",
        "relay_lease_count_mismatch",
        "destination_delivery_not_delivered",
        "destination_audit_status_unexpected",
        "source_outbox_ack_missing",
        "verification_query_returned_no_row",
        "audit_public_key_missing",
        "destination_row_count_mismatch",
        "destination_content_mismatch",
        "ledger_commit_count_mismatch",
        "source_outbox_not_empty",
        "relay_not_empty",
        "quarantine_not_empty",
        "audit_event_count_mismatch",
        "known_plaintext_canary_found_in_blind_state",
        "source_record_count_mismatch",
        "workflow_stage_failed",
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
        "atomic_batch_write_outcome_unknown",
        "atomic_batch_capability_changed",
        "destination_capability_changed",
        "replay_capability_changed",
        "delivery_outcome_record_failed",
        "sealed_spool_cleanup_failed",
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


@pytest.mark.parametrize("code", [item.value for item in SandboxErrorCode])
def test_parser_worker_failures_have_specific_operator_guidance(code: str) -> None:
    diagnostic = explain_reason(code)

    assert diagnostic.category == "parser_containment"
    assert diagnostic.next_action
    assert diagnostic.retry_policy
