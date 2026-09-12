from __future__ import annotations

import pytest

from polymorph.work_budget import WorkBudget, WorkBudgetExceeded, WorkMeter


def test_work_meter_enforces_records_bytes_depth_nodes_and_values() -> None:
    budget = WorkBudget(
        max_total_records=2,
        max_total_bytes=4,
        max_structure_depth=2,
        max_structure_nodes=3,
        max_value_bytes=3,
    )
    meter = WorkMeter(budget)
    meter.consume_records(2)
    meter.consume_bytes(4)

    with pytest.raises(WorkBudgetExceeded, match="max_total_records"):
        meter.consume_records()
    with pytest.raises(WorkBudgetExceeded, match="max_total_bytes"):
        meter.consume_bytes(1)
    with pytest.raises(WorkBudgetExceeded, match="max_structure_depth"):
        WorkMeter(budget).validate_structure([[1]])
    with pytest.raises(WorkBudgetExceeded, match="max_structure_nodes"):
        WorkMeter(budget).validate_structure([1, 2, 3])
    with pytest.raises(WorkBudgetExceeded, match="max_value_bytes"):
        WorkMeter(budget).validate_structure("four")
