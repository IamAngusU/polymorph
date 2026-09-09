from __future__ import annotations

from typing import Protocol, Sequence


class SemanticEncoder(Protocol):
    def similarity(self, left: str, right: str) -> float: ...

    def similarities(self, query: str, candidates: Sequence[str]) -> list[float]: ...


class Reranker(Protocol):
    def scores(self, query: str, candidates: Sequence[str]) -> list[float]: ...
