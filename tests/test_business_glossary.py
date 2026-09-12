from polymorph.matching.hybrid import HybridMatcher
from polymorph.models.mapping import MappingStatus
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType


def _schema(identity: str, *fields: FieldDescriptor) -> SchemaDescriptor:
    return SchemaDescriptor(identity, fields)


def test_german_finance_glossary_improves_review_without_granting_auto() -> None:
    source = _schema(
        "source",
        FieldDescriptor("amount", "Bruttobetrag", DataType.DECIMAL),
    )
    target = _schema(
        "target",
        FieldDescriptor("net", "net amount", DataType.DECIMAL),
        FieldDescriptor("gross", "gross amount", DataType.DECIMAL),
    )

    decision = HybridMatcher().propose(source, target)[0]

    assert decision.target_field_id == "gross"
    assert decision.status is MappingStatus.REVIEW
    assert "business glossary advisory match" in decision.reasons


def test_french_company_glossary_is_advisory_only() -> None:
    source = _schema(
        "source",
        FieldDescriptor("name", "denominationUniteLegale", DataType.STRING),
    )
    target = _schema(
        "target",
        FieldDescriptor("legal", "legal name", DataType.STRING),
        FieldDescriptor("customer", "customer name", DataType.STRING),
    )

    decision = HybridMatcher().propose(source, target)[0]

    assert decision.target_field_id == "legal"
    assert decision.status is MappingStatus.REVIEW
