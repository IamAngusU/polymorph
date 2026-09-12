from __future__ import annotations

import os
from typing import NoReturn


class WindowsJobError(OSError):
    """Raised when mandatory Windows Job Object enforcement cannot be installed."""


_JOB_HANDLES: list[int] = []


def available() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        return all(
            hasattr(kernel32, name)
            for name in (
                "AssignProcessToJobObject",
                "CreateJobObjectW",
                "GetCurrentProcess",
                "SetInformationJobObject",
            )
        )
    except (AttributeError, OSError):
        return False


def enforce_current_process_limits(
    *,
    cpu_seconds: int,
    max_memory_bytes: int,
    max_processes: int,
) -> None:
    """Put this worker and every descendant in one fail-closed resource job."""

    if os.name != "nt":
        raise WindowsJobError("Windows Job Objects are unavailable on this platform")

    import ctypes
    from ctypes import wintypes

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)

    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        raise WindowsJobError(ctypes.get_last_error(), "could not create Windows Job Object")

    job_time = 0x00000004
    active_process = 0x00000008
    process_memory = 0x00000100
    job_memory = 0x00000200
    kill_on_close = 0x00002000
    limits = ExtendedLimitInformation()
    limits.BasicLimitInformation.PerJobUserTimeLimit = int(cpu_seconds) * 10_000_000
    limits.BasicLimitInformation.ActiveProcessLimit = int(max_processes)
    limits.BasicLimitInformation.LimitFlags = (
        job_time | active_process | process_memory | job_memory | kill_on_close
    )
    limits.ProcessMemoryLimit = int(max_memory_bytes)
    limits.JobMemoryLimit = int(max_memory_bytes)

    try:
        if not kernel32.SetInformationJobObject(
            handle,
            9,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise WindowsJobError(
                ctypes.get_last_error(), "could not configure Windows Job Object limits"
            )
        if not kernel32.AssignProcessToJobObject(handle, kernel32.GetCurrentProcess()):
            raise WindowsJobError(
                ctypes.get_last_error(), "could not assign parser worker to Windows Job Object"
            )
    except Exception:
        kernel32.CloseHandle(handle)
        raise
    _JOB_HANDLES.append(int(handle))


def run_parser_worker(
    *,
    cpu_seconds: int,
    max_memory_bytes: int,
    max_processes: int,
) -> int:
    enforce_current_process_limits(
        cpu_seconds=cpu_seconds,
        max_memory_bytes=max_memory_bytes,
        max_processes=max_processes,
    )
    from .parser_worker import main

    return main()


def fail(message: str) -> NoReturn:
    raise WindowsJobError(message)
