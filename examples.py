"""Small executable examples for local development."""

from polymorph.matching.hybrid import HybridMatcher
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType

source = SchemaDescriptor(
    "excel:orders",
    (
        FieldDescriptor("c1", "Debitor Nr", DataType.STRING),
        FieldDescriptor("c2", "Netto Betrag", DataType.DECIMAL),
    ),
)

target = SchemaDescriptor(
    "db:orders",
    (
        FieldDescriptor("customer_number", "customer number", DataType.STRING),
        FieldDescriptor("net_amount", "net amount", DataType.DECIMAL),
    ),
)

for decision in HybridMatcher(auto_threshold=0.74).propose(source, target):
    print(decision)
