from __future__ import annotations

import sys

from polymorph.review_artifacts import ReviewArtifact, apply_review_artifact


def apply_review(session: object, artifact_path: str) -> object:
    artifact = ReviewArtifact.load(artifact_path)
    return apply_review_artifact(session, artifact)  # type: ignore[arg-type]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: import apply_review from this recipe inside your host session")
    raise SystemExit("this recipe requires a live MoveSession from the embedding application")
