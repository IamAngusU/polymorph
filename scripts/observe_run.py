"""Run one explicit command and retain process/resource evidence as JSON.

This is opt-in instrumentation. It does not upload data, modify the command, or run during normal
Polymorph operation. NVIDIA process memory is best-effort because WDDM and some driver modes do
not expose per-process compute memory through nvidia-smi.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MIB = 1024 * 1024
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _run_quiet(command: list[str], timeout: float = 3.0) -> str | None:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _nvidia_inventory(executable: str | None) -> list[dict[str, Any]]:
    if executable is None:
        return []
    output = _run_quiet(
        [
            executable,
            "--query-gpu=index,name,uuid,memory.total,driver_version",
            "--format=csv,noheader,nounits",
        ]
    )
    if not output:
        return []
    inventory: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = [part.strip() for part in line.split(",", 4)]
        if len(parts) != 5:
            continue
        try:
            total_mib: float | None = float(parts[3])
        except ValueError:
            total_mib = None
        inventory.append(
            {
                "index": parts[0],
                "name": parts[1],
                "uuid": parts[2],
                "memory_total_mib": total_mib,
                "driver_version": parts[4],
            }
        )
    return inventory


def _nvidia_sample(executable: str | None, pids: set[int]) -> tuple[float, dict[str, Any]]:
    if executable is None:
        return 0.0, {}
    process_output = _run_quiet(
        [
            executable,
            "--query-compute-apps=pid,gpu_uuid,used_memory",
            "--format=csv,noheader,nounits",
        ]
    )
    attributed_mib = 0.0
    if process_output:
        for line in process_output.splitlines():
            parts = [part.strip() for part in line.split(",", 2)]
            if len(parts) != 3:
                continue
            try:
                pid = int(parts[0])
                used_mib = float(parts[2])
            except ValueError:
                continue
            if pid in pids:
                attributed_mib += used_mib

    device_output = _run_quiet(
        [
            executable,
            "--query-gpu=uuid,memory.used,utilization.gpu",
            "--format=csv,noheader,nounits",
        ]
    )
    devices: dict[str, Any] = {}
    if device_output:
        for line in device_output.splitlines():
            parts = [part.strip() for part in line.split(",", 2)]
            if len(parts) != 3:
                continue
            try:
                used_mib = float(parts[1])
                utilization_percent = float(parts[2])
            except ValueError:
                continue
            devices[parts[0]] = {
                "memory_used_mib": used_mib,
                "utilization_percent": utilization_percent,
            }
    return attributed_mib, devices


def _machine_payload(psutil_module: Any | None) -> dict[str, Any]:
    total_memory: int | None = None
    physical_cores: int | None = None
    if psutil_module is not None:
        try:
            total_memory = int(psutil_module.virtual_memory().total)
            physical_cores = psutil_module.cpu_count(logical=False)
        except Exception:
            pass
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "architecture": platform.machine(),
        "processor": platform.processor() or None,
        "logical_cores": os.cpu_count(),
        "physical_cores": physical_cores,
        "memory_total_bytes": total_memory,
    }


def _process_sample(root: Any | None, known: dict[int, Any]) -> tuple[set[int], int, float]:
    if root is None:
        return set(), 0, 0.0
    try:
        processes = [root, *root.children(recursive=True)]
    except Exception:
        processes = list(known.values())
    for process in processes:
        known[process.pid] = process
    pids: set[int] = set()
    rss_bytes = 0
    cpu_percent = 0.0
    for pid, process in list(known.items()):
        try:
            if not process.is_running():
                continue
            pids.add(pid)
            rss_bytes += int(process.memory_info().rss)
            cpu_percent += float(process.cpu_percent(interval=None))
        except Exception:
            continue
    return pids, rss_bytes, cpu_percent


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--history", type=Path)
    parser.add_argument("--label", default="observed-command")
    parser.add_argument("--interval", type=float, default=0.25)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.interval < 0.05 or args.interval > 10:
        parser.error("--interval must be between 0.05 and 10 seconds")
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        import psutil
    except ImportError:
        psutil = None

    nvidia_smi = shutil.which("nvidia-smi")
    inventory = _nvidia_inventory(nvidia_smi)
    started_at = _utc_now()
    wall_started = time.perf_counter()
    process = subprocess.Popen(args.command)
    root = psutil.Process(process.pid) if psutil is not None else None
    known: dict[int, Any] = {}
    if root is not None:
        root.cpu_percent(interval=None)

    samples = 0
    peak_rss_bytes = 0
    peak_cpu_percent = 0.0
    peak_process_vram_mib = 0.0
    peak_device_memory: dict[str, float] = {}
    peak_device_utilization: dict[str, float] = {}
    interrupted = False
    try:
        while process.poll() is None:
            pids, rss_bytes, cpu_percent = _process_sample(root, known)
            process_vram_mib, devices = _nvidia_sample(nvidia_smi, pids)
            peak_rss_bytes = max(peak_rss_bytes, rss_bytes)
            peak_cpu_percent = max(peak_cpu_percent, cpu_percent)
            peak_process_vram_mib = max(peak_process_vram_mib, process_vram_mib)
            for uuid, device in devices.items():
                peak_device_memory[uuid] = max(
                    peak_device_memory.get(uuid, 0.0), float(device["memory_used_mib"])
                )
                peak_device_utilization[uuid] = max(
                    peak_device_utilization.get(uuid, 0.0),
                    float(device["utilization_percent"]),
                )
            samples += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        interrupted = True
        process.terminate()
    return_code = process.wait()
    _, final_rss, final_cpu = _process_sample(root, known)
    peak_rss_bytes = max(peak_rss_bytes, final_rss)
    peak_cpu_percent = max(peak_cpu_percent, final_cpu)

    ended_at = _utc_now()
    payload: dict[str, Any] = {
        "schema": "polymorph.observed-run",
        "version": 1,
        "label": args.label,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": round(time.perf_counter() - wall_started, 6),
        "exit_code": return_code,
        "interrupted": interrupted,
        "command": [str(part) for part in args.command],
        "pid": process.pid,
        "machine": _machine_payload(psutil),
        "observer": {
            "sample_interval_seconds": args.interval,
            "sample_count": samples,
            "process_tree_available": psutil is not None,
            "nvidia_smi_available": nvidia_smi is not None,
        },
        "resources": {
            "peak_process_tree_rss_bytes": peak_rss_bytes if psutil is not None else None,
            "peak_process_tree_rss_mib": (
                round(peak_rss_bytes / MIB, 3) if psutil is not None else None
            ),
            "peak_process_tree_cpu_percent": (
                round(peak_cpu_percent, 3) if psutil is not None else None
            ),
            "peak_nvidia_process_vram_mib": (
                round(peak_process_vram_mib, 3) if nvidia_smi is not None else None
            ),
            "peak_nvidia_device_memory_mib": peak_device_memory,
            "peak_nvidia_device_utilization_percent": peak_device_utilization,
        },
        "gpu_inventory": inventory,
        "caveats": [
            "RSS and CPU are sampled and may miss peaks between samples.",
            "Device-wide GPU values include unrelated applications.",
            "NVIDIA process VRAM may be unavailable under WDDM or non-compute workloads.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if args.history is not None:
        _append_jsonl(args.history, payload)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
