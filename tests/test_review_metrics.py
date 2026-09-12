import json

from polymorph.review_metrics import main


def test_review_session_records_metadata_only(tmp_path, capsys) -> None:
    assert (
        main(
            [
                "--store",
                str(tmp_path),
                "start",
                "--fields",
                "3",
                "--suggestions",
                "2",
                "--corpus",
                "test",
            ]
        )
        == 0
    )
    started = json.loads(capsys.readouterr().out)
    assert (
        main(
            [
                "--store",
                str(tmp_path),
                "finish",
                started["session_id"],
                "--accepted",
                "1",
                "--corrected",
                "1",
                "--abstained",
                "1",
            ]
        )
        == 0
    )
    completed = json.loads(capsys.readouterr().out)

    assert completed["privacy"] == "metadata_only_no_field_names_or_values"
    assert completed["suggestion_acceptance_rate"] == 0.5
    assert "field_names" not in completed
    assert "row_values" not in completed
    assert "source_path" not in completed


def test_review_summary_is_empty_for_new_store(tmp_path, capsys) -> None:
    assert main(["--store", str(tmp_path), "summary"]) == 0
    assert json.loads(capsys.readouterr().out)["sessions"] == 0
