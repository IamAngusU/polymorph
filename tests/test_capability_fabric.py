from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from openpyxl import Workbook

from polymorph.capability_fabric import (
    PLAN_SCHEMA,
    build_account_inventory_plan,
    canonical_json,
    parse_field_overrides,
    write_account_inventory_plan,
)
from polymorph.cli import build_parser
from polymorph.errors import PolymorphError


def _csv(path: Path, rows: list[str]) -> Path:
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def test_builds_canonical_secret_free_fabric_plan_from_csv(tmp_path: Path) -> None:
    source = _csv(
        tmp_path / "accounts.csv",
        [
            "Website,Konto,Email,Password Policy,Risk Tier,Mutation Approval",
            "https://EXAMPLE.com:443/login,Example,alice@example.com,maximum,sensitive,trusted-user",
            "http://localhost:80/sign-in,Local,bob,strong,normal,manual-only",
        ],
    )

    plan = build_account_inventory_plan(source)

    assert plan["schema"] == PLAN_SCHEMA
    assert plan["entries"] == [
        {
            "entry": 1,
            "label": "Example",
            "mutation_approval": "trusted-user",
            "origin": "https://example.com",
            "password_policy": "maximum",
            "risk_tier": "sensitive",
            "username": "alice@example.com",
        },
        {
            "entry": 2,
            "label": "Local",
            "mutation_approval": "manual-only",
            "origin": "http://localhost",
            "password_policy": "strong",
            "risk_tier": "normal",
            "username": "bob",
        },
    ]
    source_info = plan["source"]
    assert isinstance(source_info, dict)
    assert source_info["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert set(plan) == {"entries", "mapping", "plan_digest", "schema", "source"}
    assert all(
        set(entry)
        <= {
            "entry",
            "label",
            "mutation_approval",
            "origin",
            "password_policy",
            "risk_tier",
            "username",
        }
        for entry in plan["entries"]
    )
    body = {key: value for key, value in plan.items() if key != "plan_digest"}
    assert plan["plan_digest"] == hashlib.sha256(canonical_json(body).encode()).hexdigest()

    output = tmp_path / "plan.json"
    write_account_inventory_plan(output, plan)
    wire = output.read_text(encoding="utf-8")
    assert wire == canonical_json(plan) + "\n"


def test_explicit_reviewed_mapping_supports_nonstandard_json_inventory(tmp_path: Path) -> None:
    source = tmp_path / "inventory.json"
    source.write_text(
        json.dumps([{"portal_location": "https://one.example/login", "handle": "alice"}]),
        encoding="utf-8",
    )

    plan = build_account_inventory_plan(
        source,
        field_overrides={"origin": "portal_location", "username": "handle"},
    )

    assert plan["entries"] == [
        {
            "entry": 1,
            "label": "one.example",
            "mutation_approval": "trusted-user",
            "origin": "https://one.example",
            "password_policy": "maximum",
            "risk_tier": "normal",
            "username": "alice",
        }
    ]
    mapping = plan["mapping"]
    assert isinstance(mapping, list)
    assert {item["authority"] for item in mapping} == {"operator"}


def test_rejects_secret_columns_ambiguous_origins_duplicates_and_formula_values(
    tmp_path: Path,
) -> None:
    secret = _csv(
        tmp_path / "secret.csv",
        ["url,username,password", "https://example.com,alice,do-not-read"],
    )
    with pytest.raises(PolymorphError, match="secret-bearing columns"):
        build_account_inventory_plan(secret)

    policy_as_label = _csv(
        tmp_path / "policy-as-label.csv",
        ["url,Password Policy", "https://example.com,maximum"],
    )
    with pytest.raises(PolymorphError, match="secret-classified source fields"):
        build_account_inventory_plan(
            policy_as_label,
            field_overrides={"origin": "url", "label": "Password Policy"},
        )

    ambiguous = _csv(
        tmp_path / "ambiguous.csv",
        ["url,website", "https://one.example,https://two.example"],
    )
    with pytest.raises(PolymorphError, match="automatic mapping for origin is ambiguous"):
        build_account_inventory_plan(ambiguous)

    duplicate = _csv(
        tmp_path / "duplicate.csv",
        [
            "url,username",
            "https://same.example/one,alice",
            "https://same.example/two,alice",
        ],
    )
    with pytest.raises(PolymorphError, match="duplicate origin/username pair"):
        build_account_inventory_plan(duplicate)

    formula = _csv(
        tmp_path / "formula.csv",
        ["url,label", 'https://example.com,=HYPERLINK("https://evil.example")'],
    )
    with pytest.raises(PolymorphError, match="formula-like value"):
        build_account_inventory_plan(formula)


def test_rejects_excel_formula_cache_for_inventory_authority(tmp_path: Path) -> None:
    source = tmp_path / "accounts.xlsx"
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["url", "label"])
    sheet.append(["https://example.com", '=CONCAT("Exam","ple")'])
    workbook.save(source)
    workbook.close()

    with pytest.raises(PolymorphError, match="spreadsheet formulas"):
        build_account_inventory_plan(source)


def test_explicit_mapping_parser_is_narrow_and_rejects_duplicates() -> None:
    assert parse_field_overrides(["origin=portal", "username=handle"]) == {
        "origin": "portal",
        "username": "handle",
    }
    with pytest.raises(PolymorphError, match="TARGET=SOURCE"):
        parse_field_overrides(["password=secret"])
    with pytest.raises(PolymorphError, match="duplicate explicit mapping"):
        parse_field_overrides(["origin=url", "origin=website"])


def test_fabric_inventory_cli_writes_plan_but_prints_only_sanitized_summary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _csv(
        tmp_path / "accounts.csv",
        ["url,username", "https://example.com/login,private-user@example.com"],
    )
    output = tmp_path / "plan.json"
    args = build_parser().parse_args(
        ["fabric", "inventory-plan", str(source), "--output", str(output)]
    )

    args.func(args)

    summary = capsys.readouterr().out
    assert "private-user@example.com" not in summary
    assert '"secret_material": false' in summary
    assert (
        output.read_text(encoding="utf-8")
        == canonical_json(json.loads(output.read_text(encoding="utf-8"))) + "\n"
    )
