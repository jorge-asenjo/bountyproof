"""Detect what this machine can hunt with: hardware, tools and phones plugged in over USB."""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# command -> what it unlocks
TOOLS = {
    "claude": "runs the agents",
    "node": "runs the scope guard",
    "git": "local history for each workspace",
    "npx": "starts the browser the agents drive",
    "docker": "local labs for source-available targets",
    "adb": "talks to an Android phone over USB",
    "jadx": "decompiles Android apps",
    "apktool": "unpacks Android apps",
    "idevice_id": "talks to an iPhone over USB (libimobiledevice)",
    "mitmproxy": "intercepts app traffic",
    "gh": "sets up your private Radar repo",
    "gemini": "optional second model for discovery",
    "codex": "optional second model for validation",
}


@dataclass
class Machine:
    os: str = ""
    cpus: int = 1
    ram_gb: float = 0.0
    disk_free_gb: float = 0.0
    tools: list[str] = field(default_factory=list)
    docker_running: bool = False
    android_connected: int = 0
    iphone_connected: int = 0

    def has(self, tool: str) -> bool:
        return tool in self.tools

    @property
    def is_mac(self) -> bool:
        return self.os.startswith("macOS")

    def parallel_slots(self) -> int:
        """Browser sessions or lab containers that fit at once. The agents themselves run in the cloud."""
        by_ram = int((self.ram_gb - 4) // 3) if self.ram_gb else 1
        return max(1, min(by_ram, max(1, self.cpus // 2), 8))

    def describe(self) -> str:
        parts = [self.os or "unknown OS", f"{self.cpus} cores"]
        if self.ram_gb:
            parts.append(f"{self.ram_gb:.0f} GB RAM")
        if self.disk_free_gb:
            parts.append(f"{self.disk_free_gb:.0f} GB free")
        return ", ".join(parts)


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return out.stdout if out.returncode == 0 else ""


def _os_name() -> str:
    if sys.platform == "darwin":
        return f"macOS {platform.mac_ver()[0]}".strip()
    if sys.platform == "win32":
        build = sys.getwindowsversion().build
        return "Windows 11" if build >= 22000 else f"Windows {platform.release()}"
    return f"{platform.system()} {platform.release()}"


def _ram_gb() -> float:
    try:
        if sys.platform == "win32":

            class _MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = _MemoryStatus()
            status.dwLength = ctypes.sizeof(_MemoryStatus)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return status.ullTotalPhys / 2**30
        elif sys.platform == "darwin":
            return int(_run(["sysctl", "-n", "hw.memsize"]) or 0) / 2**30
        else:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) / 2**20
    except (OSError, ValueError, AttributeError):
        pass
    return 0.0


def _android_devices() -> int:
    lines = _run(["adb", "devices"]).splitlines()[1:]
    return sum(1 for line in lines if line.split()[1:2] == ["device"])  # "<serial>\tdevice"


def _iphones() -> int:
    return len([line for line in _run(["idevice_id", "-l"]).splitlines() if line.strip()])


def detect() -> Machine:
    tools = [name for name in TOOLS if shutil.which(name)]
    try:
        free = shutil.disk_usage(Path.home()).free / 2**30
    except OSError:
        free = 0.0
    return Machine(
        os=_os_name(),
        cpus=os.cpu_count() or 1,
        ram_gb=round(_ram_gb(), 1),
        disk_free_gb=round(free, 1),
        tools=tools,
        docker_running="docker" in tools and bool(_run(["docker", "info", "--format", "{{.ServerVersion}}"]).strip()),
        android_connected=_android_devices() if "adb" in tools else 0,
        iphone_connected=_iphones() if "idevice_id" in tools else 0,
    )
