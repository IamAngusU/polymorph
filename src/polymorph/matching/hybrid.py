from __future__ import annotations

from dataclasses import dataclass, replace

from polymorph.models.mapping import MappingCandidate, MappingDecision, MappingStatus
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import automatic_copy_type_safe

from .base import Reranker, SemanticEncoder
from .deterministic import (
    automatic_mapping_contract_safe,
    deterministic_score,
    foreign_key_lookup_key,
    role_compatible_for_automatic,
)
from .glossary import advisory_glossary_target


@dataclass(slots=True)
class HybridMatcher:
    semantic: SemanticEncoder | None = None
    reranker: Reranker | None = None
    semantic_weight: float = 0.24
    reranker_weight: float = 0.18
    rerank_top_k: int = 4
    rerank_trigger_margin: float = 0.16
    rerank_min_score: float = 0.50
    deterministic_auto_floor: float = 0.90
    deterministic_minimum_margin: float = 0.08
    auto_threshold: float = 0.86
    minimum_margin: float = 0.08

    def _initial_candidates(
        self,
        source: FieldDescriptor,
        target_schema: SchemaDescriptor,
    ) -> list[MappingCandidate]:
        deterministic_evidence = [
            deterministic_score(source, target, target_schema) for target in target_schema.fields
        ]
        deterministic_ranking = sorted((score for score, _ in deterministic_evidence), reverse=True)
        deterministic_margin = (
            deterministic_ranking[0] - deterministic_ranking[1]
            if len(deterministic_ranking) > 1
            else deterministic_ranking[0]
            if deterministic_ranking
            else 0.0
        )
        deterministic_top_index = (
            max(
                range(len(deterministic_evidence)),
                key=lambda index: deterministic_evidence[index][0],
            )
            if deterministic_evidence
            else None
        )
        deterministic_is_decisive = (
            deterministic_top_index is not None
            and deterministic_ranking[0] >= self.deterministic_auto_floor
            and deterministic_margin >= self.deterministic_minimum_margin
            and automatic_mapping_contract_safe(
                source,
                target_schema.fields[deterministic_top_index],
                target_schema,
            )
        )

        semantic_scores: list[float | None] = [None] * len(target_schema.fields)
        if self.semantic is not None and not deterministic_is_decisive:
            scores = self.semantic.similarities(
                source.semantic_text(),
                [field.semantic_text() for field in target_schema.fields],
            )
            semantic_scores = list(scores)

        candidates: list[MappingCandidate] = []
        evidence = zip(
            target_schema.fields,
            semantic_scores,
            deterministic_evidence,
            strict=True,
        )
        for target, semantic_score, (deterministic, reasons) in evidence:
            if semantic_score is None:
                final = deterministic
            else:
                final = (1.0 - self.semantic_weight) * deterministic + self.semantic_weight * max(
                    0.0, min(semantic_score, 1.0)
                )
            candidates.append(
                MappingCandidate(
                    source_field_id=source.id,
                    target_field_id=target.id,
                    score=final,
                    deterministic_score=deterministic,
                    semantic_score=semantic_score,
                    reasons=reasons,
                )
            )
        return sorted(candidates, key=lambda item: item.score, reverse=True)

    def candidates_for(
        self,
        source: FieldDescriptor,
        target_schema: SchemaDescriptor,
    ) -> list[MappingCandidate]:
        candidates = self._initial_candidates(source, target_schema)
        if self.reranker is None or len(candidates) < 2:
            return candidates

        deterministic_candidates = sorted(
            candidates,
            key=lambda candidate: candidate.deterministic_score,
            reverse=True,
        )
        deterministic = [candidate.deterministic_score for candidate in deterministic_candidates]
        deterministic_margin = deterministic[0] - deterministic[1]
        deterministic_target = target_schema.by_id()[deterministic_candidates[0].target_field_id]
        if (
            deterministic[0] >= self.deterministic_auto_floor
            and deterministic_margin >= self.deterministic_minimum_margin
            and automatic_mapping_contract_safe(source, deterministic_target, target_schema)
        ):
            return candidates

        initial_margin = candidates[0].score - candidates[1].score
        if (
            candidates[0].score < self.rerank_min_score
            or initial_margin > self.rerank_trigger_margin
        ):
            return candidates

        count = min(max(2, self.rerank_top_k), len(candidates))
        top = candidates[:count]
        target_by_id = target_schema.by_id()
        scores = self.reranker.scores(
            source.semantic_text(),
            [target_by_id[item.target_field_id].semantic_text() for item in top],
        )
        if len(scores) != len(top):
            return candidates

        reranked: list[MappingCandidate] = []
        for candidate, raw_score in zip(top, scores, strict=True):
            reranker_score = max(0.0, min(float(raw_score), 1.0))
            reranked.append(
                replace(
                    candidate,
                    score=(1.0 - self.reranker_weight) * candidate.score
                    + self.reranker_weight * reranker_score,
                    reranker_score=reranker_score,
                    reasons=(*candidate.reasons, "reranker evidence"),
                )
            )
        return sorted([*reranked, *candidates[count:]], key=lambda item: item.score, reverse=True)

    def decide(self, source: FieldDescriptor, target_schema: SchemaDescriptor) -> MappingDecision:
        candidates = self.candidates_for(source, target_schema)
        if not candidates:
            return MappingDecision(
                source.id,
                None,
                MappingStatus.BLOCKED,
                0.0,
                0.0,
                ("no target fields",),
            )

        top = candidates[0]
        second_score = candidates[1].score if len(candidates) > 1 else 0.0
        margin = top.score - second_score

        # Models are ranking evidence, never authorization. Automatic promotion is grounded
        # entirely in the deterministic ranking and must select the same target with its own
        # strong separation. This prevents an embedding or reranker from turning an otherwise
        # ambiguous mapping into a live write decision.
        deterministic = sorted(
            candidates,
            key=lambda item: item.deterministic_score,
            reverse=True,
        )
        deterministic_top = deterministic[0]
        deterministic_second = (
            deterministic[1].deterministic_score if len(deterministic) > 1 else 0.0
        )
        deterministic_margin = deterministic_top.deterministic_score - deterministic_second
        target_by_id = target_schema.by_id()
        deterministic_target = target_by_id[deterministic_top.target_field_id]
        verified_relation_lookup = (
            foreign_key_lookup_key(source, deterministic_target, target_schema) is not None
        )
        type_ok = (
            automatic_copy_type_safe(source.data_type, deterministic_target.data_type)
            or verified_relation_lookup
        )
        role_ok = (
            role_compatible_for_automatic(source.role, deterministic_target.role)
            or verified_relation_lookup
        )
        contract_safe = automatic_mapping_contract_safe(source, deterministic_target, target_schema)
        deterministic_ok = (
            deterministic_top.target_field_id == top.target_field_id
            and deterministic_top.deterministic_score >= self.deterministic_auto_floor
            and deterministic_margin >= self.deterministic_minimum_margin
            and type_ok
            and role_ok
            and contract_safe
        )

        if top.score >= self.auto_threshold and margin >= self.minimum_margin and deterministic_ok:
            status = MappingStatus.AUTO
        elif top.score >= 0.55 or deterministic_top.deterministic_score >= 0.55:
            status = MappingStatus.REVIEW
        else:
            status = MappingStatus.BLOCKED

        reasons = top.reasons
        if not type_ok:
            reasons = (*reasons, "automatic approval requires compatible declared types")
        if not role_ok:
            reasons = (*reasons, "automatic approval requires compatible field roles")
        if not contract_safe:
            reasons = (*reasons, "automatic approval requires an executable policy route")
        if not deterministic_ok:
            reasons = (
                *reasons,
                "automatic approval requires independently strong deterministic evidence",
            )
        elif top.semantic_score is not None or top.reranker_score is not None:
            reasons = (*reasons, "model evidence is advisory; automatic approval is deterministic")

        return MappingDecision(
            source_field_id=source.id,
            target_field_id=top.target_field_id if status is not MappingStatus.BLOCKED else None,
            status=status,
            score=top.score,
            margin=margin,
            reasons=reasons,
        )

    def propose(
        self, source_schema: SchemaDescriptor, target_schema: SchemaDescriptor
    ) -> list[MappingDecision]:
        decisions = [self.decide(source, target_schema) for source in source_schema.fields]

        paired = zip(source_schema.fields, decisions, strict=True)
        for index, (source, decision) in enumerate(paired):
            if decision.status is MappingStatus.AUTO:
                continue
            glossary_target = advisory_glossary_target(source, target_schema)
            if glossary_target is None or glossary_target.id == decision.target_field_id:
                continue
            decisions[index] = MappingDecision(
                source_field_id=source.id,
                target_field_id=glossary_target.id,
                status=MappingStatus.REVIEW,
                score=max(0.55, decision.score),
                margin=0.0,
                reasons=(*decision.reasons, "business glossary advisory match"),
            )

        # Any two plausible source fields claiming the same target make automatic approval
        # unsafe. Review candidates participate in this conflict check too, otherwise one
        # exact-looking source could be auto-approved while a second plausible source is
        # silently left for later review.
        target_to_sources: dict[str, list[int]] = {}
        for idx, decision in enumerate(decisions):
            if decision.status is not MappingStatus.BLOCKED and decision.target_field_id:
                target_to_sources.setdefault(decision.target_field_id, []).append(idx)

        for indexes in target_to_sources.values():
            if len(indexes) <= 1:
                continue
            for idx in indexes:
                decision = decisions[idx]
                decisions[idx] = MappingDecision(
                    source_field_id=decision.source_field_id,
                    target_field_id=decision.target_field_id,
                    status=MappingStatus.REVIEW,
                    score=decision.score,
                    margin=decision.margin,
                    reasons=(*decision.reasons, "target conflict"),
                )
        return decisions
