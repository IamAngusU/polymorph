from __future__ import annotations

import json
import random

import json5

from polymorph.content import ContentInspector

_SCALAR_STRINGS = (
    "plain",
    "brackets [inside] {a:string}",
    'escaped quote: " and slash: \\',
    "comment-looking // text /* still a string */",
    "unicode: Grüße 世界",
    "",
)


def _json_value(rng: random.Random, remaining_depth: int) -> object:
    if remaining_depth <= 0 or rng.random() < 0.38:
        return rng.choice(
            (
                None,
                True,
                False,
                rng.randint(-10_000, 10_000),
                rng.random() * 100,
                rng.choice(_SCALAR_STRINGS),
            )
        )
    if rng.random() < 0.5:
        return [_json_value(rng, remaining_depth - 1) for _ in range(rng.randint(0, 4))]
    return {
        f"key_{index}_{rng.randrange(1_000_000)}": _json_value(rng, remaining_depth - 1)
        for index in range(rng.randint(0, 4))
    }


def _container_depth(value: object) -> int:
    if isinstance(value, dict):
        return 1 + max((_container_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_container_depth(item) for item in value), default=0)
    return 0


def _container_items(value: object) -> int:
    if isinstance(value, dict):
        return len(value) + sum(_container_items(item) for item in value.values())
    if isinstance(value, list):
        return len(value) + sum(_container_items(item) for item in value)
    return 0


def test_json_limit_scanner_matches_generated_standard_json_structures() -> None:
    rng = random.Random(0x5645595241)

    for case_number in range(10_000):
        value = _json_value(rng, remaining_depth=6)
        if not isinstance(value, (dict, list)):
            value = [value]
        text = json.dumps(
            value,
            ensure_ascii=False,
            indent=2 if case_number % 2 else None,
        )

        # The standard parser is the independent syntax oracle. The expected limits are
        # calculated from its materialized structure, not from scanner tokens.
        parsed = json.loads(text)
        expected_depth = _container_depth(parsed)
        expected_items = _container_items(parsed)

        assert ContentInspector._json_like_limits_exceeded(
            text,
            max_depth=expected_depth,
            max_items=expected_items,
        ) == (False, False)

        if expected_depth > 0:
            assert ContentInspector._json_like_limits_exceeded(
                text,
                max_depth=expected_depth - 1,
                max_items=expected_items,
            ) == (True, False)
        if expected_items > 0:
            assert ContentInspector._json_like_limits_exceeded(
                text,
                max_depth=expected_depth,
                max_items=expected_items - 1,
            ) == (False, True)


def test_json_limit_scanner_matches_representative_json5_structures() -> None:
    cases = (
        "/* leading comment */ {unquoted: 'single quoted', trailing: [1, 2,],}",
        "{hex: 0x2a, signed: +3, nested: {enabled: true,}, empty: [],}",
        "[// line comment\n{value: 'brackets [inside]'}, /* block */ {value: null},]",
        "{// unicode line separator\u2028first: [1], // paragraph separator\u2029second: {x: 2}}",
        "{escaped: 'quote: \\' and slash: \\\\', comments: '// not a comment /* either */'}",
    )

    for text in cases:
        parsed = json5.loads(text)
        assert isinstance(parsed, (dict, list))
        expected_depth = _container_depth(parsed)
        expected_items = _container_items(parsed)

        assert ContentInspector._json_like_limits_exceeded(
            text,
            max_depth=expected_depth,
            max_items=expected_items,
        ) == (False, False)
        assert ContentInspector._json_like_limits_exceeded(
            text,
            max_depth=expected_depth - 1,
            max_items=expected_items,
        ) == (True, False)
        assert ContentInspector._json_like_limits_exceeded(
            text,
            max_depth=expected_depth,
            max_items=expected_items - 1,
        ) == (False, True)
