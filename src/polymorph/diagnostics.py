from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ReasonDiagnostic:
    code: str
    category: str
    summary: str
    next_action: str
    retry_policy: str

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "category": self.category,
            "summary": self.summary,
            "next_action": self.next_action,
            "retry_policy": self.retry_policy,
        }


def _reason(
    code: str,
    category: str,
    summary: str,
    next_action: str,
    retry_policy: str = "inspect_before_retry",
) -> ReasonDiagnostic:
    return ReasonDiagnostic(code, category, summary, next_action, retry_policy)


_REASONS = {
    item.code: item
    for item in (
        _reason(
            "delivery_claim_in_progress",
            "coordination",
            "Another worker owns an unexpired pre-write claim.",
            "Wait for the claim lease or inspect the delivery ledger.",
            "wait",
        ),
        _reason(
            "delivery_claim_lost",
            "coordination",
            "This worker lost its fenced claim before the destination write boundary.",
            "Let the current claim owner continue; inspect the ledger if the item stalls.",
            "safe_after_current_claim",
        ),
        _reason(
            "previous_write_started_ambiguous",
            "write_ambiguity",
            "A previous worker crossed the write boundary and did not record a final outcome.",
            "Reconcile the destination by business or idempotency key before force replay.",
            "never_blind_retry",
        ),
        _reason(
            "previous_delivery_ambiguous",
            "write_ambiguity",
            "A previous delivery ended in a state where commit status is not proven.",
            "Reconcile the destination before replay unless it has a proven idempotency contract.",
            "never_blind_retry",
        ),
        _reason(
            "write_outcome_unknown",
            "write_ambiguity",
            "The connector could not prove whether the destination committed the write.",
            "Reconcile the destination, then use the authorized replay path if required.",
            "never_blind_retry",
        ),
        _reason(
            "delivery_outcome_record_failed",
            "local_durability",
            "The destination acknowledged the write, but the local ledger could not record it.",
            "Treat the write as potentially committed and repair or inspect the ledger.",
            "never_blind_retry",
        ),
        _reason(
            "write_not_committed",
            "destination_write",
            "The connector proved that the destination write did not commit.",
            "Fix the destination or connector error, then retry the quarantined item.",
            "safe_to_retry",
        ),
        _reason(
            "transport_verification_failed",
            "transport_integrity",
            "Authenticated transport data could not be opened or decoded safely.",
            "Check source trust, keys, protocol versions and wire integrity.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "destination_contract_failed",
            "destination_contract",
            "The decrypted record does not satisfy the runtime's exact plan or target contract.",
            "Compare the active plan, target schema and producer version before retrying.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "destination_resolution_failed",
            "destination_lookup",
            "A destination-side lookup failed before the write boundary.",
            "Check lookup configuration, uniqueness and destination availability.",
            "safe_after_fix",
        ),
        _reason(
            "relay_wire_invalid",
            "relay_intake",
            "The relay could not parse the bounded wire record.",
            "Check protocol compatibility and source serialization.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "relay_source_authentication_failed",
            "source_trust",
            "The relay could not authenticate the source identity and signature.",
            "Check the source trust bundle, connector identity and key rotation state.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "relay_transfer_expired",
            "transfer_policy",
            "The authenticated transfer is outside its validity window.",
            "Create a new authorized transfer instead of replaying expired wire bytes.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "relay_policy_rejected",
            "transfer_policy",
            "Relay policy rejected the authenticated route metadata.",
            "Compare tenant, connector and plan digest with the active relay policy.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "relay_digest_mismatch",
            "transport_integrity",
            "Stored relay bytes no longer match their authenticated digest.",
            "Quarantine the store and investigate corruption or tampering.",
            "never_retry",
        ),
        _reason(
            "recipe_rebind_failed",
            "recipe_drift",
            "A structurally matching recipe failed current validation during exact rebind.",
            "Review schema or policy drift and approve a new recipe version if appropriate.",
            "fresh_mapping_only",
        ),
        _reason(
            "recipe_auto_reuse_suspended",
            "recipe_health",
            "Automatic reuse stopped after repeated rejected recipe executions.",
            "Inspect recipe health and approve a corrected recipe version.",
            "fresh_mapping_only",
        ),
        _reason(
            "preflight_promotable",
            "preflight",
            "A complete no-write preflight passed without review findings.",
            "The plan may proceed through the separately authorized delivery workflow.",
            "not_applicable",
        ),
        _reason(
            "preflight_not_promotable",
            "preflight",
            "Preflight did not meet the strict automatic-promotion gate.",
            "Inspect findings and run a complete scan after fixing or reviewing them.",
            "do_not_auto_promote",
        ),
        _reason(
            "no_auto_approved_mapping_rules",
            "mapping",
            "The matcher found no rules with enough deterministic evidence for automatic use.",
            "Review the suggestions, add explicit aliases or approve a manual plan.",
            "manual_review",
        ),
        _reason(
            "sampled_scan",
            "preflight",
            "Only a bounded sample was checked, so automatic promotion is disabled.",
            "Run preflight without a record limit before remembering the route.",
            "do_not_auto_promote",
        ),
        _reason(
            "empty_source",
            "source_data",
            "Preflight observed no records.",
            "Confirm the source selection and provide a non-empty input.",
            "do_not_auto_promote",
        ),
        _reason(
            "spreadsheet_formula_cache",
            "spreadsheet_freshness",
            "Spreadsheet formula values came from an unverified workbook cache.",
            "Recalculate in a trusted spreadsheet engine or review the cached values.",
            "manual_review",
        ),
        _reason(
            "record_schema_mismatch",
            "source_contract",
            "A record contains fields absent from the inspected source schema.",
            "Inspect source drift and regenerate the plan against the current schema.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "source_schema_id_mismatch",
            "plan_binding",
            "The plan is bound to a different source schema identity.",
            "Regenerate or rebind the plan against the current source schema.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "target_schema_id_mismatch",
            "plan_binding",
            "The plan is bound to a different target schema identity.",
            "Regenerate or rebind the plan against the current target schema.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "source_schema_drift",
            "plan_binding",
            "The current source schema fingerprint differs from the plan.",
            "Inspect source drift and create a newly reviewed plan.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "target_schema_drift",
            "plan_binding",
            "The current target schema fingerprint differs from the plan.",
            "Inspect destination drift and create a newly reviewed plan.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "unknown_source_field",
            "plan_contract",
            "A mapping rule references a source field that is not in the current schema.",
            "Regenerate the plan against the current source schema.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "unknown_target_field",
            "plan_contract",
            "A mapping rule references a target field that is not in the current schema.",
            "Regenerate the plan against the current target schema.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "duplicate_target",
            "plan_contract",
            "More than one mapping rule writes the same target field.",
            "Resolve the collision and approve a plan with one writer per target field.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "unknown_transform",
            "transform",
            "A mapping rule references a transform not registered in this build.",
            "Install or implement the transform, or revise the plan.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "policy_violation",
            "information_flow",
            "A mapping route violates the current information-flow policy.",
            "Review field sensitivity and use an explicitly permitted transform or route.",
            "manual_review",
        ),
        _reason(
            "type_mismatch",
            "plan_contract",
            "A direct mapping has incompatible source and target types.",
            "Choose a reviewed transform or correct the schema types.",
            "manual_review",
        ),
        _reason(
            "required_target_unmapped",
            "destination_contract",
            "The plan leaves a required destination field without a value.",
            "Map the field or mark a proven destination-generated default in the schema.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "required_source_missing",
            "source_contract",
            "A required source field is absent from at least one record.",
            "Fix the source export or explicitly revise the source contract.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "required_target_null",
            "destination_contract",
            "The mapping produces null for a required destination field.",
            "Fix the source data or mapping before delivery.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "source_transform_failed",
            "transform",
            "A source-side transform rejected at least one record.",
            "Inspect the transform contract and the referenced source field.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "transformed_type_mismatch",
            "transform",
            "A transformed value does not satisfy the target type contract.",
            "Correct the transform or target field type before delivery.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "foreign_key_lookup_not_exercised",
            "destination_lookup",
            "Preflight could not test a destination-side foreign-key lookup.",
            "Provide a read-only destination resolver and rerun preflight.",
            "manual_review",
        ),
        _reason(
            "foreign_key_lookup_invalid",
            "destination_lookup",
            "A foreign-key rule lacks a valid unique match column.",
            "Correct the mapping rule and prove destination uniqueness.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "foreign_key_lookup_failed",
            "destination_lookup",
            "The read-only foreign-key lookup failed during preflight.",
            "Check destination access, lookup data and uniqueness.",
            "safe_after_fix",
        ),
        _reason(
            "foreign_key_resolved_null",
            "destination_lookup",
            "A required foreign key could not be resolved.",
            "Create or correct the referenced destination row before delivery.",
            "do_not_retry_unchanged",
        ),
        _reason(
            "source_iteration_failed",
            "source_read",
            "The source connector failed while preflight was reading records.",
            "Check file stability, parser limits and connector diagnostics.",
            "safe_after_fix",
        ),
    )
}


def explain_reason(code: str) -> ReasonDiagnostic:
    known = _REASONS.get(code)
    if known is not None:
        return known
    return _reason(
        code,
        "unknown",
        "This build does not have a specific explanation for the reason code.",
        "Keep the code and surrounding metadata, then inspect the emitting component.",
        "inspect_before_retry",
    )
