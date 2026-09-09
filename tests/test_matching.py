from polymorph.matching.hybrid import HybridMatcher
from polymorph.models.mapping import MappingStatus
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType


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
