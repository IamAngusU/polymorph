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
PROFILES = ("multilingual-cpu", "reranker-multilingual-cpu")
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a complete local Polymorph dev setup.")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--home", type=Path, default=DEFAULT_HOME)
    parser.add_argument("--skip-models", action="store_true")
    parser.add_argument("--skip-checks", action="store_true")
    args = parser.parse_args()

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
    if not args.skip_models and architecture not in MODEL_ARCHITECTURES:
        supported = ", ".join(sorted(MODEL_ARCHITECTURES))
        raise SystemExit(
            f"Pinned model bootstrap does not support architecture {architecture!r}; "
            f"supported values: {supported}. Use --skip-models for the core runtime."
        )
    polymorph = _venv_executable("polymorph")
    ruff = _venv_executable("ruff")
    extras = [*BASE_EXTRAS]
    if not args.skip_models:
        extras.append("semantic")
    editable_target = f".[{','.join(extras)}]"
    _run([python, "-m", "pip", "install", "--upgrade", "pip"], env=env)
    _run([python, "-m", "pip", "install", "-e", editable_target], env=env)

    if not args.skip_models:
        for profile in PROFILES:
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

        smoke = (
            "from polymorph.matching.semantic import ("
            "MULTILINGUAL_CPU,RERANKER_MULTILINGUAL_CPU,load_profile_encoder,"
            "load_profile_reranker);"
            "from polymorph.paths import model_home;"
            "e=load_profile_encoder(MULTILINGUAL_CPU,model_home(MULTILINGUAL_CPU.name));"
            "r=load_profile_reranker(RERANKER_MULTILINGUAL_CPU,"
            "model_home(RERANKER_MULTILINGUAL_CPU.name));"
            "assert len(e.similarities('customer id',['customer number','invoice date']))==2;"
            "assert len(r.scores('customer id',['customer number','invoice date']))==2"
        )
        _run([python, "-c", smoke], env=env)

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
    print(f"Ready. Data and models live in {home}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
