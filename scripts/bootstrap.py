from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV = ROOT / ".venv"
DEFAULT_HOME = ROOT / ".polymorph"
BASE_EXTRAS = ("dev", "fileid", "csv-detection", "benchmark")
RESEARCH_ENCODER_PROFILE = "multilingual-cpu"
RESEARCH_RERANKER_PROFILE = "reranker-multilingual-cpu"
MODEL_ARCHITECTURES = {"amd64", "x86_64", "aarch64", "arm64"}


@dataclass(frozen=True, slots=True)
class PythonDetails:
    version: tuple[int, int]
    architecture: str
    interpreter_platform: str
    pointer_bits: int

    def display(self) -> str:
        version = ".".join(str(item) for item in self.version)
        return (
            f"Python {version} ({self.architecture}, {self.interpreter_platform}, "
            f"{self.pointer_bits}-bit)"
        )


def _venv_executable(name: str) -> Path:
    directory = "Scripts" if os.name == "nt" else "bin"
    suffix = ".exe" if os.name == "nt" else ""
    return VENV / directory / f"{name}{suffix}"


def _run(command: list[str | Path], *, env: dict[str, str]) -> None:
    rendered = [str(item) for item in command]
    print(f"+ {' '.join(rendered)}", flush=True)
    subprocess.run(rendered, cwd=ROOT, env=env, check=True)


def _python_details(executable: str | Path) -> PythonDetails:
    probe = (
        "import platform,struct,sys,sysconfig;"
        "print('{}.{}|{}|{}|{}'.format(sys.version_info.major,sys.version_info.minor,"
        "platform.machine(),sysconfig.get_platform(),struct.calcsize('P')*8))"
    )
    try:
        completed = subprocess.run(
            [str(executable), "-c", probe],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        version_text, architecture, interpreter_platform, pointer_bits_text = (
            completed.stdout.strip().split("|", 3)
        )
        major_text, minor_text = version_text.split(".", 1)
        version = (int(major_text), int(minor_text))
        pointer_bits = int(pointer_bits_text)
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        raise SystemExit(f"Cannot run the requested Python interpreter: {executable}") from exc
    if version < (3, 11):
        raise SystemExit(
            f"Polymorph requires Python 3.11 or newer; {executable} is Python {version_text}"
        )
    return PythonDetails(
        version=version,
        architecture=architecture.lower(),
        interpreter_platform=interpreter_platform.lower(),
        pointer_bits=pointer_bits,
    )


def _require_matching_venv(requested: PythonDetails, existing: PythonDetails) -> None:
    if requested == existing:
        return
    raise SystemExit(
        "Existing .venv does not match --python: "
        f"requested {requested.display()}, found {existing.display()}. "
        "Remove .venv or select its interpreter explicitly."
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create a complete local Polymorph dev setup.")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--home", type=Path, default=DEFAULT_HOME)
    parser.add_argument(
        "--skip-models",
        action="store_true",
        help="retain the model-free default explicitly (compatibility option)",
    )
    parser.add_argument(
        "--include-research-encoder",
        action="store_true",
        help="install the MiniLM encoder after reviewing its training-data provenance",
    )
    parser.add_argument(
        "--include-research-reranker",
        action="store_true",
        help="install the mMARCO reranker after reviewing its training-data terms",
    )
    parser.add_argument("--skip-checks", action="store_true")
    return parser


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = _build_parser()
    args = parser.parse_args(argv)
    include_models = args.include_research_encoder or args.include_research_reranker
    if args.skip_models and include_models:
        parser.error("--skip-models cannot be combined with research-model options")
    return args


def _research_profiles(args: argparse.Namespace) -> tuple[str, ...]:
    profiles: list[str] = []
    if args.include_research_encoder:
        profiles.append(RESEARCH_ENCODER_PROFILE)
    if args.include_research_reranker:
        profiles.append(RESEARCH_RERANKER_PROFILE)
    return tuple(profiles)


def main() -> int:
    args = _parse_args()
    profiles = _research_profiles(args)
    include_models = bool(profiles)

    requested_python = _python_details(args.python)
    home = args.home.expanduser().resolve()
    env = os.environ.copy()
    env["POLYMORPH_HOME"] = str(home)

    if not _venv_executable("python").exists():
        _run([args.python, "-m", "venv", VENV], env=env)

    python = _venv_executable("python")
    venv_python = _python_details(python)
    _require_matching_venv(requested_python, venv_python)
    architecture = venv_python.architecture
    if include_models and architecture not in MODEL_ARCHITECTURES:
        supported = ", ".join(sorted(MODEL_ARCHITECTURES))
        raise SystemExit(
            f"Pinned model bootstrap does not support architecture {architecture!r}; "
            f"supported values: {supported}. Use the model-free core runtime."
        )
    polymorph = _venv_executable("polymorph")
    ruff = _venv_executable("ruff")
    extras = [*BASE_EXTRAS]
    if include_models:
        extras.append("semantic")
    editable_target = f".[{','.join(extras)}]"
    _run([python, "-m", "pip", "install", "--upgrade", "pip"], env=env)
    _run([python, "-m", "pip", "install", "-e", editable_target], env=env)

    if include_models:
        for profile in profiles:
            destination = home / "models" / profile
            _run(
                [
                    polymorph,
                    "model",
                    "install",
                    "--profile",
                    profile,
                    "--destination",
                    destination,
                ],
                env=env,
            )

        if args.include_research_encoder:
            encoder_smoke = (
                "from polymorph.matching.semantic import MULTILINGUAL_CPU,load_profile_encoder;"
                "from polymorph.paths import model_home;"
                "e=load_profile_encoder(MULTILINGUAL_CPU,model_home(MULTILINGUAL_CPU.name));"
                "assert len(e.similarities('customer id',['customer number','invoice date']))==2"
            )
            _run([python, "-c", encoder_smoke], env=env)
        if args.include_research_reranker:
            reranker_smoke = (
                "from polymorph.matching.semantic import ("
                "RERANKER_MULTILINGUAL_CPU,load_profile_reranker);"
                "from polymorph.paths import model_home;"
                "r=load_profile_reranker(RERANKER_MULTILINGUAL_CPU,"
                "model_home(RERANKER_MULTILINGUAL_CPU.name));"
                "assert len(r.scores('customer id',['customer number','invoice date']))==2"
            )
            _run([python, "-c", reranker_smoke], env=env)

    if not args.skip_checks:
        _run([python, "-m", "compileall", "-q", "src", "tests", "scripts", "examples.py"], env=env)
        _run([ruff, "check", "src", "tests", "scripts", "examples.py"], env=env)
        _run(
            [ruff, "format", "--check", "src", "tests", "scripts", "examples.py"],
            env=env,
        )
        _run([python, "-m", "mypy"], env=env)
        _run([python, "examples.py"], env=env)
        _run(
            [python, "-W", "error", "-m", "pytest", "--strict-config", "--strict-markers"],
            env=env,
        )
        _run(
            [
                polymorph,
                "benchmark",
                "mapping",
                "benchmarks/safety-regression.json",
                "--require-auto-precision",
                "1.0",
                "--require-automation-coverage",
                "0.70",
                "--max-unsafe-auto",
                "0",
            ],
            env=env,
        )
        _run([python, "-m", "pip", "check"], env=env)

    _run([polymorph, "doctor"], env=env)
    print(f"Ready. Local state and any explicitly installed models live in {home}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
