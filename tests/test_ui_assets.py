from __future__ import annotations

import pytest

from polymorph.ui_assets import UiExportError, export_review_ui


def test_review_ui_exports_offline_dependency_free_assets(tmp_path) -> None:
    paths = export_review_ui(tmp_path / "ui")
    script = (tmp_path / "ui" / "polymorph-review.js").read_text(encoding="utf-8")
    assert len(paths) == 3
    assert "customElements.define" in script
    assert "polymorph-review-submit" in script
    assert "https://" not in script
    assert "row_values" not in script
    assert "Evidence class" in script
    assert "linear-gradient" not in script
    assert "radial-gradient" not in script


def test_review_ui_does_not_overwrite_by_default(tmp_path) -> None:
    output = tmp_path / "ui"
    export_review_ui(output)
    with pytest.raises(UiExportError, match="contains"):
        export_review_ui(output)
