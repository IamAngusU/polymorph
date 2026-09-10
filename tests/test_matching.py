import pytest

from polymorph.errors import PolicyViolation
from polymorph.matching.deterministic import automatic_mapping_contract_safe
from polymorph.matching.hybrid import HybridMatcher
from polymorph.models.mapping import MappingDecision, MappingStatus
from polymorph.models.schema import (
    FieldDescriptor,
    LookupKeyDescriptor,
    RelationDescriptor,
    SchemaDescriptor,
)
from polymorph.models.types import DataType, FieldRole, Sensitivity
from polymorph.planning import build_plan
from polymorph.validation import PlanValidator


def test_german_customer_number_maps_to_customer_number():
    source = SchemaDescriptor(
        "source",
        (
            FieldDescriptor("c1", "Debitor Nr", DataType.STRING),
            FieldDescriptor("c2", "Netto Betrag", DataType.DECIMAL),
        ),
    )
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor("customer_number", "customer number", DataType.STRING),
            FieldDescriptor("net_amount", "net amount", DataType.DECIMAL),
        ),
    )

    decisions = HybridMatcher(
        auto_threshold=0.74,
        minimum_margin=0.05,
        deterministic_auto_floor=0.74,
    ).propose(source, target)

    assert decisions[0].target_field_id == "customer_number"
    assert decisions[1].target_field_id == "net_amount"
    assert all(item.status is MappingStatus.AUTO for item in decisions)


def test_conflicting_target_is_not_silently_auto_accepted():
    source = SchemaDescriptor(
        "source",
        (
            FieldDescriptor("a", "customer id", DataType.STRING),
            FieldDescriptor("b", "client id", DataType.STRING),
        ),
    )
    target = SchemaDescriptor("target", (FieldDescriptor("x", "customer id", DataType.STRING),))

    decisions = HybridMatcher(auto_threshold=0.7, minimum_margin=0.0).propose(source, target)
    assert all(item.status is MappingStatus.REVIEW for item in decisions)


class _FakeEncoder:
    def similarities(self, query: str, candidates):
        return [0.82, 0.81][: len(candidates)]

    def similarity(self, left: str, right: str) -> float:
        return self.similarities(left, [right])[0]


class _FakeReranker:
    def __init__(self) -> None:
        self.calls = 0

    def scores(self, query: str, candidates):
        self.calls += 1
        return [0.2, 0.98][: len(candidates)]


def test_reranker_only_runs_for_ambiguous_top_candidates() -> None:
    source = FieldDescriptor("s", "customer ref", DataType.STRING)
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor("a", "customer code", DataType.STRING),
            FieldDescriptor("b", "customer reference", DataType.STRING),
        ),
    )
    reranker = _FakeReranker()
    matcher = HybridMatcher(
        semantic=_FakeEncoder(),
        reranker=reranker,
        auto_threshold=0.70,
        minimum_margin=0.0,
        rerank_trigger_margin=1.0,
    )

    candidates = matcher.candidates_for(source, target)

    assert reranker.calls == 1
    assert candidates[0].reranker_score is not None


def test_model_evidence_cannot_auto_promote_weak_deterministic_match() -> None:
    class StrongModel:
        def similarities(self, query: str, candidates):
            return [1.0 for _ in candidates]

        def similarity(self, left: str, right: str) -> float:
            return 1.0

    source = FieldDescriptor("s", "totally unrelated alpha", DataType.STRING)
    target = SchemaDescriptor("target", (FieldDescriptor("t", "zeta omega", DataType.STRING),))
    decision = HybridMatcher(
        semantic=StrongModel(),
        semantic_weight=0.9,
        auto_threshold=0.5,
        minimum_margin=0.0,
        deterministic_auto_floor=0.75,
    ).decide(source, target)

    assert decision.status is MappingStatus.REVIEW
    assert "independently strong deterministic evidence" in decision.reasons[-1]


def test_reranker_cannot_flip_an_automatic_mapping() -> None:
    class Encoder:
        def similarities(self, query: str, candidates):
            return [0.9, 0.9][: len(candidates)]

        def similarity(self, left: str, right: str) -> float:
            return 0.9

    class FlippingReranker:
        def scores(self, query: str, candidates):
            return [0.0, 1.0][: len(candidates)]

    source = FieldDescriptor("s", "customer id", DataType.STRING)
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor("a", "customer id", DataType.STRING),
            FieldDescriptor("b", "customer identifier", DataType.STRING),
        ),
    )
    decision = HybridMatcher(
        semantic=Encoder(),
        reranker=FlippingReranker(),
        reranker_weight=0.8,
        rerank_trigger_margin=1.0,
        auto_threshold=0.5,
        minimum_margin=0.0,
    ).decide(source, target)

    assert decision.status is MappingStatus.REVIEW
    assert "independently strong deterministic evidence" in decision.reasons[-1]


def test_exact_deterministic_match_can_still_auto_promote() -> None:
    source = FieldDescriptor("s", "customer id", DataType.STRING)
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor("customer_id", "customer id", DataType.STRING),
            FieldDescriptor("invoice_id", "invoice id", DataType.STRING),
        ),
    )

    decision = HybridMatcher().decide(source, target)

    assert decision.status is MappingStatus.AUTO
    assert decision.target_field_id == "customer_id"


def test_decisive_deterministic_match_does_not_pay_model_cost() -> None:
    class CountingEncoder:
        def __init__(self) -> None:
            self.calls = 0

        def similarities(self, query: str, candidates):
            self.calls += 1
            return [0.9 for _ in candidates]

        def similarity(self, left: str, right: str) -> float:
            return self.similarities(left, [right])[0]

    class CountingReranker:
        def __init__(self) -> None:
            self.calls = 0

        def scores(self, query: str, candidates):
            self.calls += 1
            return [0.9 for _ in candidates]

    encoder = CountingEncoder()
    reranker = CountingReranker()
    source = FieldDescriptor("s", "customer id", DataType.STRING)
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor("customer_id", "customer id", DataType.STRING),
            FieldDescriptor("invoice_id", "invoice id", DataType.STRING),
        ),
    )

    decision = HybridMatcher(semantic=encoder, reranker=reranker).decide(source, target)

    assert decision.status is MappingStatus.AUTO
    assert encoder.calls == 0
    assert reranker.calls == 0


def test_exact_cyrillic_name_can_auto_promote_without_being_erased() -> None:
    source = FieldDescriptor("s", "Клиент", DataType.STRING)
    target = SchemaDescriptor("target", (FieldDescriptor("t", "Клиент", DataType.STRING),))

    decision = HybridMatcher().decide(source, target)

    assert decision.status is MappingStatus.AUTO
    assert decision.target_field_id == "t"


def test_unrelated_non_latin_names_are_not_deterministically_equal() -> None:
    source = FieldDescriptor("s", "Клиент", DataType.STRING)
    target = SchemaDescriptor("target", (FieldDescriptor("t", "顧客番号", DataType.STRING),))

    decision = HybridMatcher().decide(source, target)

    assert decision.status is not MappingStatus.AUTO


def test_account_number_does_not_auto_map_to_customer_number() -> None:
    source = FieldDescriptor("s", "account number", DataType.STRING)
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("customer_number", "customer number", DataType.STRING),),
    )

    decision = HybridMatcher().decide(source, target)

    assert decision.status is not MappingStatus.AUTO


def test_exact_name_does_not_auto_promote_across_incompatible_roles() -> None:
    source = FieldDescriptor(
        "secret",
        "api token",
        DataType.STRING,
        sensitivity=Sensitivity.SECRET,
        role=FieldRole.CREDENTIAL,
    )
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor(
                "value",
                "api token",
                DataType.STRING,
                sensitivity=Sensitivity.SECRET,
                role=FieldRole.VALUE,
            ),
        ),
    )

    decision = HybridMatcher().decide(source, target)

    assert decision.status is MappingStatus.REVIEW
    assert "automatic approval requires compatible field roles" in decision.reasons


def test_exact_name_does_not_auto_promote_without_declared_type_evidence() -> None:
    source = FieldDescriptor("source", "customer id", DataType.UNKNOWN)
    target = SchemaDescriptor(
        "target", (FieldDescriptor("target", "customer id", DataType.UNKNOWN),)
    )

    decision = HybridMatcher().decide(source, target)

    assert decision.status is MappingStatus.REVIEW
    assert "automatic approval requires compatible declared types" in decision.reasons


@pytest.mark.parametrize(
    ("source_type", "target_type"),
    [
        (DataType.DECIMAL, DataType.INTEGER),
        (DataType.DATE, DataType.DATETIME),
        (DataType.DATETIME, DataType.DATE),
    ],
)
def test_exact_name_does_not_auto_promote_across_runtime_unsafe_type_direction(
    source_type: DataType,
    target_type: DataType,
) -> None:
    source = FieldDescriptor("source", "created value", source_type)
    target = SchemaDescriptor("target", (FieldDescriptor("target", "created value", target_type),))

    decision = HybridMatcher().decide(source, target)

    assert decision.status is MappingStatus.REVIEW
    assert "automatic approval requires compatible declared types" in decision.reasons


def test_integer_to_decimal_remains_runtime_safe_for_automatic_copy() -> None:
    source = FieldDescriptor("source", "quantity", DataType.INTEGER)
    target = SchemaDescriptor("target", (FieldDescriptor("target", "quantity", DataType.DECIMAL),))

    decision = HybridMatcher().decide(source, target)

    assert decision.status is MappingStatus.AUTO


def test_foreign_key_alias_without_relation_evidence_requires_review() -> None:
    source = FieldDescriptor(
        "source",
        "customer number",
        DataType.STRING,
        role=FieldRole.NATURAL_KEY,
    )
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor(
                "customer_id",
                "customer id",
                DataType.INTEGER,
                role=FieldRole.FOREIGN_KEY,
                aliases=("client number",),
            ),
        ),
    )

    decision = HybridMatcher().decide(source, target)

    assert decision.status is MappingStatus.REVIEW
    assert "automatic approval requires compatible declared types" in decision.reasons


def test_relation_backed_foreign_key_auto_uses_the_same_lookup_evidence_as_planning() -> None:
    source_schema = SchemaDescriptor(
        "source",
        (
            FieldDescriptor(
                "source_customer",
                "customer number",
                DataType.STRING,
                role=FieldRole.NATURAL_KEY,
            ),
        ),
    )
    target_schema = SchemaDescriptor(
        "target",
        (
            FieldDescriptor(
                "customer_id",
                "customer id",
                DataType.INTEGER,
                role=FieldRole.FOREIGN_KEY,
                aliases=("customer number",),
            ),
        ),
        (
            RelationDescriptor(
                "customer_id",
                "customers",
                "id",
                lookup_keys=(LookupKeyDescriptor("customer number", DataType.STRING),),
            ),
        ),
    )

    decision = HybridMatcher().decide(source_schema.fields[0], target_schema)
    plan = build_plan(source_schema, target_schema, [decision])

    assert decision.status is MappingStatus.AUTO
    assert len(plan.rules) == 1
    assert plan.rules[0].transform == "lookup_foreign_key"
    assert plan.rules[0].parameters == {"match_column": "customer number"}


def test_relation_backed_foreign_key_with_unknown_source_type_requires_review() -> None:
    source = FieldDescriptor(
        "source_customer",
        "customer number",
        DataType.UNKNOWN,
        role=FieldRole.NATURAL_KEY,
    )
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor(
                "customer_id",
                "customer id",
                DataType.INTEGER,
                role=FieldRole.FOREIGN_KEY,
                aliases=("customer number",),
            ),
        ),
        (
            RelationDescriptor(
                "customer_id",
                "customers",
                "id",
                lookup_keys=(LookupKeyDescriptor("customer number", DataType.STRING),),
            ),
        ),
    )

    decision = HybridMatcher().decide(source, target)

    assert decision.status is MappingStatus.REVIEW
    assert "automatic approval requires compatible declared types" in decision.reasons


def test_relation_lookup_with_incompatible_declared_key_type_never_auto_plans() -> None:
    source = SchemaDescriptor(
        "source",
        (
            FieldDescriptor(
                "customer_number",
                "customer number",
                DataType.JSON,
                role=FieldRole.NATURAL_KEY,
            ),
        ),
    )
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor(
                "customer_id",
                "customer id",
                DataType.INTEGER,
                role=FieldRole.FOREIGN_KEY,
                aliases=("customer number",),
            ),
        ),
        (
            RelationDescriptor(
                "customer_id",
                "customers",
                "id",
                lookup_keys=(LookupKeyDescriptor("customer number", DataType.INTEGER),),
            ),
        ),
    )

    decision = HybridMatcher().decide(source.fields[0], target)

    assert decision.status is MappingStatus.REVIEW
    assert "automatic approval requires compatible declared types" in decision.reasons
    unsafe_auto = MappingDecision(
        source.fields[0].id,
        "customer_id",
        MappingStatus.AUTO,
        1.0,
        1.0,
    )
    with pytest.raises(PolicyViolation, match="executable contract"):
        build_plan(source, target, [unsafe_auto])


def test_untyped_legacy_lookup_is_reviewable_but_never_automatic() -> None:
    source = SchemaDescriptor(
        "source",
        (
            FieldDescriptor(
                "customer_number",
                "customer number",
                DataType.STRING,
                role=FieldRole.NATURAL_KEY,
            ),
        ),
    )
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor(
                "customer_id",
                "customer id",
                DataType.INTEGER,
                role=FieldRole.FOREIGN_KEY,
                aliases=("customer number",),
            ),
        ),
        (RelationDescriptor("customer_id", "customers", "id", lookup_keys=("customer number",)),),
    )

    decision = HybridMatcher().decide(source.fields[0], target)
    plan = build_plan(source, target, [decision], allow_review=True)
    report = PlanValidator().validate(plan, source, target)

    assert decision.status is MappingStatus.REVIEW
    assert plan.rules[0].transform == "lookup_foreign_key"
    assert report.valid
    assert report.requires_review
    assert {item.code for item in report.findings} == {"foreign_key_lookup_type_unknown"}


def test_internal_source_does_not_auto_promote_to_opaque_destination() -> None:
    source = FieldDescriptor("source", "payload", DataType.STRING)
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor(
                "target",
                "payload",
                DataType.STRING,
                sensitivity=Sensitivity.OPAQUE,
            ),
        ),
    )

    decision = HybridMatcher().decide(source, target)

    assert decision.status is MappingStatus.REVIEW
    assert "automatic approval requires an executable policy route" in decision.reasons


def test_nullable_source_does_not_auto_map_to_required_target() -> None:
    source = FieldDescriptor("source", "email", DataType.STRING, nullable=True)
    target = SchemaDescriptor(
        "target", (FieldDescriptor("target", "email", DataType.STRING, nullable=False),)
    )

    decision = HybridMatcher().decide(source, target)

    assert decision.status is MappingStatus.REVIEW
    assert not automatic_mapping_contract_safe(source, target.fields[0], target)


def test_required_source_can_auto_map_to_nullable_target() -> None:
    source = FieldDescriptor("source", "email", DataType.STRING, nullable=False)
    target = SchemaDescriptor(
        "target", (FieldDescriptor("target", "email", DataType.STRING, nullable=True),)
    )

    assert HybridMatcher().decide(source, target).status is MappingStatus.AUTO


@pytest.mark.parametrize(
    ("source_sensitivity", "target_sensitivity"),
    [
        (Sensitivity.PERSONAL, Sensitivity.PUBLIC),
        (Sensitivity.CONFIDENTIAL, Sensitivity.INTERNAL),
        (Sensitivity.INTERNAL, Sensitivity.PUBLIC),
    ],
)
def test_sensitivity_downgrades_never_auto(
    source_sensitivity: Sensitivity,
    target_sensitivity: Sensitivity,
) -> None:
    source = FieldDescriptor("source", "email", DataType.STRING, sensitivity=source_sensitivity)
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("target", "email", DataType.STRING, sensitivity=target_sensitivity),),
    )

    decision = HybridMatcher().decide(source, target)

    assert decision.status is not MappingStatus.AUTO
    assert not automatic_mapping_contract_safe(source, target.fields[0], target)


def test_sensitivity_upgrade_is_reviewable_but_not_automatic() -> None:
    source = FieldDescriptor("source", "email", DataType.STRING, sensitivity=Sensitivity.INTERNAL)
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("target", "email", DataType.STRING, sensitivity=Sensitivity.PERSONAL),),
    )

    decision = HybridMatcher().decide(source, target)

    assert decision.status is MappingStatus.REVIEW
    assert not automatic_mapping_contract_safe(source, target.fields[0], target)


def test_contract_unsafe_deterministic_winner_does_not_suppress_model_ranking() -> None:
    class SafeTargetEncoder:
        def __init__(self) -> None:
            self.calls = 0

        def similarities(self, query: str, candidates):
            del query, candidates
            self.calls += 1
            return [0.0, 1.0]

        def similarity(self, left: str, right: str) -> float:
            del left, right
            return 1.0

    source = FieldDescriptor(
        "source",
        "api token",
        DataType.STRING,
        sensitivity=Sensitivity.SECRET,
        role=FieldRole.CREDENTIAL,
    )
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor(
                "unsafe_value",
                "api token",
                DataType.STRING,
                sensitivity=Sensitivity.SECRET,
                role=FieldRole.VALUE,
            ),
            FieldDescriptor(
                "safe_credential",
                "access credential",
                DataType.STRING,
                sensitivity=Sensitivity.SECRET,
                role=FieldRole.CREDENTIAL,
            ),
        ),
    )
    encoder = SafeTargetEncoder()

    decision = HybridMatcher(semantic=encoder, semantic_weight=0.9).decide(source, target)

    assert encoder.calls == 1
    assert decision.target_field_id == "safe_credential"
    assert decision.status is MappingStatus.REVIEW
