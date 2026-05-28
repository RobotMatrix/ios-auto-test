#!/usr/bin/env python3
"""
iOS App Automation Test Tool

Fully automated iOS app lifecycle testing:
  1. Device detection
  2. IPA installation (or use existing installed app)
  3. App launch with real-time monitoring
  4. Status classification:
     - SUCCESS: App launched and ran normally
     - LAUNCH_CRASH: App crashed during launch (< LAUNCH_WINDOW seconds)
     - LAUNCH_TIMEOUT: App killed by system watchdog during launch
     - RUNTIME_CRASH: App crashed after running successfully
     - LAUNCH_FAILURE: App failed to start (signing, entitlements, missing deps)
  5. Log collection: runtime syslog, crash reports, logarchive (freeze/hang logs)

Requirements:
  brew install libimobiledevice ios-deploy

Usage:
  python3 ios_auto_test.py --ipa /path/to/app.ipa
  python3 ios_auto_test.py --ipa /path/to/app.ipa --bundle-id com.example.app
  python3 ios_auto_test.py --bundle-id com.example.app --no-install
  python3 ios_auto_test.py --ipa /path/to/app.ipa --monitor-time 60 --launch-timeout 30
"""

import argparse
import json
import os
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from ios_utils import (auto_sign_ipa, symbolicate_all_reports,
                        generate_lldb_symbol_script, DEFAULT_EXTRA_ENTITLEMENTS)


# ---------------------------------------------------------------------------
# Tool paths (configurable)
# ---------------------------------------------------------------------------

IDEVICE_ID = shutil.which("idevice_id") or "idevice_id"
IDEVICEINSTALLER = shutil.which("ideviceinstaller") or "ideviceinstaller"
IDEVICESYSLOG = shutil.which("idevicesyslog") or "idevicesyslog"
IDEVICEDEBUG = shutil.which("idevicedebug") or "idevicedebug"
IDEVICECRASHREPORT = shutil.which("idevicecrashreport") or "idevicecrashreport"
IOS_DEPLOY = shutil.which("ios-deploy") or "ios-deploy"
IDEVICEIMAGEMOUNTER = shutil.which("ideviceimagemounter") or "ideviceimagemounter"
IDEVICEINFO = shutil.which("ideviceinfo") or "ideviceinfo"
DEVICECTL = shutil.which("xcrun") or "xcrun"
LLDB = shutil.which("xcrun") and "xcrun lldb" or "lldb"

DEBUGSERVER_FAIL_PATTERNS = [
    (re.compile(r"Could not start com\.apple\.debugserver"), "debugserver_not_started"),
    (re.compile(r"mount the developer disk image", re.IGNORECASE), "developer_disk_not_mounted"),
    (re.compile(r"DeveloperDiskImage", re.IGNORECASE), "developer_disk_error"),
    (re.compile(r"Unable to launch", re.IGNORECASE), "unable_to_launch"),
    (re.compile(r"lockdownd.*error", re.IGNORECASE), "lockdown_error"),
]

CODESIGNING_KILL_PATTERNS = [
    (re.compile(r"CODESIGNING", re.IGNORECASE), "codesigning_kill"),
    (re.compile(r"Invalid Page", re.IGNORECASE), "invalid_page"),
    (re.compile(r"KERN_PROTECTION_FAILURE", re.IGNORECASE), "kern_protection_failure"),
    (re.compile(r"KERN_INVALID_ADDRESS", re.IGNORECASE), "kern_invalid_address"),
]


# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------

class AppStatus(Enum):
    SUCCESS = "SUCCESS"
    LAUNCH_CRASH = "LAUNCH_CRASH"
    LAUNCH_TIMEOUT = "LAUNCH_TIMEOUT"
    RUNTIME_CRASH = "RUNTIME_CRASH"
    LAUNCH_FAILURE = "LAUNCH_FAILURE"
    INSTALL_FAILURE = "INSTALL_FAILURE"
    UNKNOWN = "UNKNOWN"


@dataclass
class TestResult:
    """Complete test result report."""
    status: str = AppStatus.UNKNOWN.value
    device_udid: str = ""
    device_name: str = ""
    bundle_id: str = ""
    ipa_path: str = ""
    start_time: str = ""
    end_time: str = ""
    launch_duration_ms: int = 0
    runtime_duration_ms: int = 0
    exit_code: int = 0
    exit_signal: str = ""
    summary: str = ""
    details: list[str] = field(default_factory=list)
    crash_reports: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    log_files: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Syslog pattern matching for status classification
# ---------------------------------------------------------------------------

# iOS exception codes (known patterns from crash reports)
WATCHDOG_CODE = re.compile(r"0x8badf00d", re.IGNORECASE)     # ate bad food
USER_FORCE_QUIT = re.compile(r"0xdeadfa11", re.IGNORECASE)   # deadfall
THERMAL = re.compile(r"0xc00010ff", re.IGNORECASE)           # cool off
VOIP_RESTART = re.compile(r"0xbad22222", re.IGNORECASE)      # excessive VoIP restart
DEADLOCK = re.compile(r"0xdead10cc", re.IGNORECASE)          # held lock during suspend
STACKSHOT = re.compile(r"0xbaaaaaad", re.IGNORECASE)         # not a real crash

CRASH_PATTERNS = [
    (re.compile(r"Application.*crash", re.IGNORECASE), "application_crash"),
    (re.compile(r"assertion failed", re.IGNORECASE), "assertion_failed"),
    (re.compile(r"Exception Type:\s*(.+)"), "exception_type"),
    (re.compile(r"EXC_CRASH"), "exc_crash"),
    (re.compile(r"EXC_BAD_ACCESS"), "exc_bad_access"),
    (re.compile(r"SIGABRT"), "sigabrt"),
    (re.compile(r"SIGSEGV"), "sigsegv"),
    (re.compile(r"SIGBUS"), "sigbus"),
    (re.compile(r"SIGILL"), "sigill"),
    (re.compile(r"SIGTRAP"), "sigtrap"),
    (re.compile(r"NSInternalInconsistencyException"), "ns_inconsistency"),
    (re.compile(r"NSInvalidArgumentException"), "ns_invalid_arg"),
    (re.compile(r"NSRangeException"), "ns_range"),
    (re.compile(r"fatal error", re.IGNORECASE), "fatal_error"),
    (re.compile(r"Termination Reason:\s*(.+)"), "termination_reason"),
    (re.compile(r"Termination Signal:\s*(.+)"), "termination_signal"),
]

WATCHDOG_PATTERNS = [
    (re.compile(r"watchdog\s+timeout", re.IGNORECASE), "watchdog_timeout"),
    (re.compile(r"has active assertions beyond permitted time", re.IGNORECASE), "active_assertions_timeout"),
    (re.compile(r"scene-update watchdog", re.IGNORECASE), "scene_update_watchdog"),
    (re.compile(r"process launch watchdog", re.IGNORECASE), "launch_watchdog"),
    (re.compile(r"terminated.*timeout", re.IGNORECASE), "terminated_timeout"),
    (re.compile(r"0x8badf00d"), "exception_ate_bad_food"),
]

SIGNING_PATTERNS = [
    (re.compile(r"AMFI\s", re.IGNORECASE), "amfi"),
    (re.compile(r"code sign", re.IGNORECASE), "code_sign"),
    (re.compile(r"missing.*entitlement|required entitlement|entitlement.*missing|entitlement.*not.*granted|entitlement.*not.*allowed", re.IGNORECASE), "entitlement_error"),
    (re.compile(r"no matching provisioning profile", re.IGNORECASE), "no_profile"),
    (re.compile(r"provisioning profile.*invalid|provisioning.*expir", re.IGNORECASE), "provisioning_error"),
    (re.compile(r"could not be verified", re.IGNORECASE), "not_verified"),
    (re.compile(r"Failed to verify code signature", re.IGNORECASE), "verify_failed"),
    (re.compile(r"application is missing", re.IGNORECASE), "app_missing"),
]

JETSAM_PATTERNS = [
    (re.compile(r"Jetsam", re.IGNORECASE), "jetsam"),
    (re.compile(r"memorystatus", re.IGNORECASE), "memorystatus"),
    (re.compile(r"killed due to memory", re.IGNORECASE), "killed_memory"),
    (re.compile(r"low memory", re.IGNORECASE), "low_memory"),
]

FREEZE_HANG_PATTERNS = [
    (re.compile(r"hang", re.IGNORECASE), "hang"),
    (re.compile(r"unresponsive", re.IGNORECASE), "unresponsive"),
    (re.compile(r"took too long", re.IGNORECASE), "took_too_long"),
    (re.compile(r"0xdead10cc"), "deadlock"),
]


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def run_cmd(args: list[str], timeout: int = 30, capture: bool = True,
            env: Optional[dict] = None) -> subprocess.CompletedProcess:
    """Run a command with timeout and return CompletedProcess."""
    kwargs = {}
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    if env:
        full_env = os.environ.copy()
        full_env.update(env)
        kwargs["env"] = full_env
    return subprocess.run(args, timeout=timeout, text=True, **kwargs)


def run_cmd_stream(args: list[str], timeout: int = 30,
                   output_file: Optional[str] = None) -> subprocess.Popen:
    """Run a command with streaming output to file."""
    if output_file:
        fh = open(output_file, "w")
        return subprocess.Popen(args, stdout=fh, stderr=subprocess.STDOUT, text=True)
    return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def strip_color_codes(text: str) -> str:
    """Remove ANSI color codes from text."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


# ---------------------------------------------------------------------------
# Device detection
# ---------------------------------------------------------------------------

def detect_device(udid: Optional[str] = None) -> tuple[str, str]:
    """Detect connected iOS device. Returns (udid, device_name)."""
    result = run_cmd([IDEVICE_ID, "-ln"], timeout=10)
    if result.returncode != 0:
        raise RuntimeError(f"No iOS device detected. {result.stderr.strip()}")

    devices = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        match = re.match(r"^([\w-]+)\s*\(.*\)\s*(\S.*)?", line)
        if match:
            device_udid = match.group(1)
            device_name = match.group(2) or "Unknown"
            devices.append((device_udid, device_name))

    if not devices:
        raise RuntimeError("No iOS device detected. Please connect a device.")

    if udid:
        for d_udid, d_name in devices:
            if d_udid == udid:
                return d_udid, d_name
        raise RuntimeError(f"Device with UDID {udid} not found. Available: {devices}")

    if len(devices) == 1:
        return devices[0]

    # Multiple devices - use the first one
    print(f"[WARN] Multiple devices detected, using first: {devices[0]}")
    return devices[0]


# ---------------------------------------------------------------------------
# IPA / Bundle ID extraction
# ---------------------------------------------------------------------------

def extract_bundle_id_from_ipa(ipa_path: str) -> str:
    """Extract bundle identifier from an IPA file's Info.plist."""
    ipa_path = os.path.abspath(ipa_path)
    if not os.path.isfile(ipa_path):
        raise FileNotFoundError(f"IPA file not found: {ipa_path}")

    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(ipa_path, "r") as zf:
            # Find Info.plist in Payload/*.app/
            info_plist_paths = [
                name for name in zf.namelist()
                if re.match(r"Payload/[^/]+\.app/Info\.plist$", name)
            ]
            if not info_plist_paths:
                raise ValueError(f"Cannot find Info.plist in {ipa_path}")
            zf.extract(info_plist_paths[0], tmpdir)

        plist_path = os.path.join(tmpdir, info_plist_paths[0])
        with open(plist_path, "rb") as f:
            info = plistlib.load(f)

    bundle_id = info.get("CFBundleIdentifier", "")
    if not bundle_id:
        raise ValueError("CFBundleIdentifier not found in Info.plist")
    return bundle_id


def check_app_installed(bundle_id: str, udid: str) -> bool:
    """Check if an app with the given bundle ID is installed on device."""
    result = run_cmd(
        [IDEVICEINSTALLER, "-u", udid, "list", "--user", "--xml"],
        timeout=15,
    )
    if result.returncode != 0:
        return False
    try:
        plist = plistlib.loads(result.stdout.encode())
        for app in plist:
            if app.get("CFBundleIdentifier") == bundle_id:
                return True
    except Exception:
        # Fallback: parse text output
        result2 = run_cmd(
            [IDEVICEINSTALLER, "-u", udid, "list", "--user"],
            timeout=15,
        )
        return bundle_id in result2.stdout
    return False


# ---------------------------------------------------------------------------
# App installation
# ---------------------------------------------------------------------------

def install_app(ipa_path: str, udid: str, reinstall: bool = False) -> tuple[bool, str]:
    """Install IPA on device. Returns (success, message)."""
    ipa_path = os.path.abspath(ipa_path)
    if not os.path.isfile(ipa_path):
        return False, f"IPA file not found: {ipa_path}"

    try:
        bundle_id = extract_bundle_id_from_ipa(ipa_path)
    except Exception as e:
        return False, f"Failed to extract bundle ID from IPA: {e}"

    # Check if already installed
    if check_app_installed(bundle_id, udid):
        if reinstall:
            print(f"[INFO] App {bundle_id} already installed, reinstalling...")
            uninstall_result = run_cmd(
                [IDEVICEINSTALLER, "-u", udid, "uninstall", bundle_id],
                timeout=60,
            )
            if uninstall_result.returncode != 0:
                print(f"[WARN] Failed to uninstall: {uninstall_result.stderr.strip()}")
        else:
            return True, f"App {bundle_id} already installed, skipping installation"

    # Install
    print(f"[INFO] Installing {ipa_path} -> {udid} ...")
    result = run_cmd(
        [IDEVICEINSTALLER, "-u", udid, "install", ipa_path],
        timeout=120,
    )

    output = strip_color_codes(result.stdout + result.stderr)
    output_lower = output.lower()

    if result.returncode == 0 and "complete" in output_lower:
        return True, f"Installation successful: {bundle_id}"
    elif result.returncode != 0:
        # Classify failure type
        for pattern, fail_type in SIGNING_PATTERNS:
            if pattern.search(output):
                return False, f"Signing/entitlement error ({fail_type}): {output[:500]}"
        return False, f"Installation failed (exit={result.returncode}): {output[:500]}"
    else:
        return True, f"Installation completed: {output[:300]}"


# ---------------------------------------------------------------------------
# Syslog capture
# ---------------------------------------------------------------------------

class SyslogCapturer:
    """Captures device syslog in a background thread."""

    def __init__(self, udid: str, process_name: Optional[str] = None,
                 output_path: Optional[str] = None):
        self.udid = udid
        self.process_name = process_name
        self.output_path = output_path
        self.process: Optional[subprocess.Popen] = None
        self.start_time: float = 0
        self._lines: list[str] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start syslog capture in background."""
        cmd = [IDEVICESYSLOG, "-u", self.udid, "-x"]
        if self.process_name:
            cmd.extend(["-p", self.process_name])

        self.start_time = time.time()

        if self.output_path:
            os.makedirs(os.path.dirname(self.output_path) or ".", exist_ok=True)
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            self._running = True
            self._thread = threading.Thread(target=self._read_to_file_and_mem, daemon=True)
            self._thread.start()
        else:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            self._running = True
            self._thread = threading.Thread(target=self._read_to_mem, daemon=True)
            self._thread.start()

    def _read_to_mem(self) -> None:
        """Read process output into memory."""
        assert self.process and self.process.stdout
        for line in iter(self.process.stdout.readline, ""):
            if not self._running:
                break
            with self._lock:
                self._lines.append(line)

    def _read_to_file_and_mem(self) -> None:
        """Read process output into both file and memory buffer."""
        assert self.process and self.process.stdout
        fh = open(self.output_path, "w")  # type: ignore
        try:
            for line in iter(self.process.stdout.readline, ""):
                if not self._running:
                    break
                fh.write(line)
                fh.flush()
                with self._lock:
                    self._lines.append(line)
        finally:
            fh.close()

    def get_lines(self) -> list[str]:
        """Get all captured log lines (thread-safe)."""
        with self._lock:
            return list(self._lines)

    def get_text(self) -> str:
        """Get all captured log text."""
        return "".join(self.get_lines())

    def stop(self) -> None:
        """Stop syslog capture."""
        self._running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                    self.process.wait(timeout=3)
                except Exception:
                    pass

    def dump_to_file(self, path: str) -> None:
        """Write captured log to file."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            f.write(self.get_text())


# ---------------------------------------------------------------------------
# App process monitoring
# ---------------------------------------------------------------------------

def get_app_pid(bundle_id: str, udid: str) -> Optional[int]:
    """Get PID of running app via syslog pidlist."""
    result = run_cmd([IDEVICESYSLOG, "-u", udid, "pidlist"], timeout=10)
    if result.returncode != 0:
        return None
    for line in result.stdout.strip().split("\n"):
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            pid_str, name = parts
            if bundle_id in name:
                try:
                    return int(pid_str)
                except ValueError:
                    pass
    return None


def is_app_running(bundle_id: str, udid: str) -> bool:
    """Check if the app is currently running."""
    return get_app_pid(bundle_id, udid) is not None


def wait_for_app_start(bundle_id: str, udid: str, timeout: float = 30) -> bool:
    """Wait for the app process to appear."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_app_running(bundle_id, udid):
            return True
        time.sleep(0.5)
    return False


def wait_for_app_stop(bundle_id: str, udid: str, timeout: float = 30) -> bool:
    """Wait for the app process to disappear."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not is_app_running(bundle_id, udid):
            return True
        time.sleep(0.5)
    return False


# ---------------------------------------------------------------------------
# Log analysis
# ---------------------------------------------------------------------------

def classify_from_syslog(syslog_text: str, details: list[str]) -> dict:
    """Analyze syslog text and extract failure classification data."""
    result: dict = {
        "crashes": [],
        "watchdog_events": [],
        "signing_errors": [],
        "jetsam_events": [],
        "freeze_hang_events": [],
        "exception_codes": [],
        "exception_types": [],
        "termination_reasons": [],
    }

    for pattern, name in CRASH_PATTERNS:
        for match in pattern.finditer(syslog_text):
            entry = match.group(0).strip() if match.groups() else name
            if entry not in result["crashes"]:
                result["crashes"].append(entry)

    for pattern, name in WATCHDOG_PATTERNS:
        if pattern.search(syslog_text):
            result["watchdog_events"].append(name)

    for pattern, name in SIGNING_PATTERNS:
        if pattern.search(syslog_text):
            result["signing_errors"].append(name)

    for pattern, name in JETSAM_PATTERNS:
        if pattern.search(syslog_text):
            result["jetsam_events"].append(name)

    for pattern, name in FREEZE_HANG_PATTERNS:
        if pattern.search(syslog_text):
            result["freeze_hang_events"].append(name)

    # Extract exception codes
    for code_pattern in [WATCHDOG_CODE, USER_FORCE_QUIT, THERMAL, VOIP_RESTART,
                          DEADLOCK, STACKSHOT]:
        for match in code_pattern.finditer(syslog_text):
            code = match.group(0)
            if code not in result["exception_codes"]:
                result["exception_codes"].append(code)

    return result


# ---------------------------------------------------------------------------
# App launch + monitoring
# ---------------------------------------------------------------------------

LLDB_CRASH_PATTERNS = [
    (re.compile(r"Process (\d+) stopped"), "process_stopped"),
    (re.compile(r"Process (\d+) exited with status"), "process_exited"),
    (re.compile(r"signal\s+(SIG\w+)", re.IGNORECASE), "lldb_signal"),
    (re.compile(r"stop reason\s*=\s*(.+)", re.IGNORECASE), "stop_reason"),
    (re.compile(r"thread #\d+.*\b(EXC_BAD_ACCESS|EXC_BREAKPOINT|EXC_CRASH|"
                r"EXC_RESOURCE|EXC_GUARD|SIGABRT|SIGSEGV|SIGBUS|SIGILL|"
                r"SIGTRAP|SIGKILL)\b", re.IGNORECASE), "exception_type"),
    (re.compile(r"fault address:\s*(0x[0-9a-f]+)", re.IGNORECASE), "fault_address"),
    (re.compile(r"error:\s*(.+)", re.IGNORECASE), "lldb_error"),
]


def _parse_lldb_crash(lldb_output: str) -> dict:
    """Parse lldb output to extract crash information."""
    info: dict = {
        "crash_detected": False,
        "signal_name": "",
        "stop_reason": "",
        "fault_address": "",
        "exception_type": "",
        "backtrace": "",
        "pid": "",
    }

    for pattern, key in LLDB_CRASH_PATTERNS:
        matches = list(pattern.finditer(lldb_output))
        if matches:
            m = matches[-1]
            if key == "process_stopped":
                info["pid"] = m.group(1)
            elif key == "lldb_signal":
                info["signal_name"] = m.group(1)
                info["crash_detected"] = True
            elif key == "stop_reason":
                info["stop_reason"] = m.group(1).strip()
            elif key == "fault_address":
                info["fault_address"] = m.group(1)
            elif key == "exception_type":
                info["exception_type"] = m.group(0).strip()
                info["crash_detected"] = True
            elif key == "lldb_error":
                info["stop_reason"] = m.group(1).strip()

    # Backtrace section: from first "* thread #" to "quit" or EOF
    bt_matches = list(re.finditer(r"\* thread #(\d+).*", lldb_output))
    if bt_matches:
        bt_start = bt_matches[0].start()
        quit_pos = lldb_output.find("\nquit", bt_start)
        bt_end = quit_pos if quit_pos > 0 else len(lldb_output)
        info["backtrace"] = lldb_output[bt_start:bt_end].strip()

    return info


def _launch_via_lldb(bundle_id: str, udid: str, launch_timeout: int,
                     monitor_time: int, capturer: "SyslogCapturer",
                     launch_start: float,
                     lldb_script_path: Optional[str] = None,
                     ipa_path: str = "",
                     output_dir: str = "") -> dict:
    """Launch app with lldb attached to capture crash backtrace in real time.

    Two-phase approach (--start-stopped unreliable on some apps):
      1. Start lldb with `device process attach -n MobileBank --waitfor`
      2. Launch the app normally via devicectl
      3. lldb catches the process immediately → continue → crash/exit
      4. Parse lldb output for crash info

    Returns result_data dict.
    """
    result: dict = {
        "launch_successful": False,
        "process_started": False,
        "process_ended_cleanly": False,
        "crash_detected": False,
        "watchdog_detected": False,
        "exit_code": 0,
        "crash_signal": "",
        "launch_duration_ms": 0,
        "runtime_before_crash_ms": 0,
        "debugger_output": "",
        "debugger_error": "",
        "fallback_used": False,
        "details": [],
    }

    print(f"[INFO] Launching with lldb debugger attached...")

    lldb_commands = [
        f"device select {udid}",
    ]
    if lldb_script_path and os.path.exists(lldb_script_path):
        lldb_commands.append(f"command source {lldb_script_path}")
    lldb_commands += [
        "device process attach -n MobileBank --waitfor",
        "bt all",
        "process continue",
        "bt all",
        "thread info",
        "register read",
        "frame variable",
        "quit",
    ]

    lldb_script = tempfile.NamedTemporaryFile(
        mode="w", suffix=".lldb", delete=False, prefix="lldb_auto_",
    )
    for cmd in lldb_commands:
        lldb_script.write(cmd + "\n")
    lldb_script.close()
    script_path = lldb_script.name

    lldb_output_lines: list[str] = []
    lldb_proc = subprocess.Popen(
        ["xcrun", "lldb", "-b", "-s", script_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    time.sleep(2)

    dc_cmd = [
        "xcrun", "devicectl", "device", "process", "launch",
        "--device", udid, "--timeout", "15", bundle_id,
    ]
    dc_proc = subprocess.Popen(
        dc_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        dc_output, _ = dc_proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        dc_proc.kill()
        dc_output, _ = dc_proc.communicate()
        result["details"].append("devicectl launch timed out")

    if "Launched" in (dc_output or ""):
        result["process_started"] = True
        result["details"].append("App launched, waiting for lldb crash capture...")

    deadline = time.time() + launch_timeout + monitor_time + 60
    import select
    while lldb_proc.poll() is None and time.time() < deadline:
        try:
            readable, _, _ = select.select([lldb_proc.stdout], [], [], 1.0)
            if readable:
                line = lldb_proc.stdout.readline()
                if line:
                    lldb_output_lines.append(line)
        except Exception:
            pass

    if lldb_proc.poll() is None:
        lldb_proc.terminate()
        try:
            lldb_proc.wait(timeout=3)
        except Exception:
            lldb_proc.kill()

    lldb_text = "".join(lldb_output_lines)
    result["debugger_output"] = lldb_text

    try:
        os.unlink(script_path)
    except Exception:
        pass

    crash_info = _parse_lldb_crash(lldb_text)

    elapsed_ms = int((time.time() - launch_start) * 1000)
    result["launch_duration_ms"] = elapsed_ms

    if crash_info["crash_detected"]:
        result["launch_successful"] = False
        result["crash_detected"] = True
        result["crash_signal"] = crash_info["signal_name"]
        result["details"].append(
            f"[LLDB] Signal: {crash_info['signal_name']}, "
            f"Stop: {crash_info['stop_reason']}, "
            f"Fault: {crash_info['fault_address']}, "
            f"Exception: {crash_info['exception_type']}")
        if crash_info["backtrace"]:
            result["details"].append(
                f"[BACKTRACE]\n{crash_info['backtrace'][:2000]}")
        result["runtime_before_crash_ms"] = elapsed_ms
    elif result["process_started"] and crash_info.get("pid"):
        result["launch_successful"] = True
        result["process_ended_cleanly"] = True
        result["runtime_before_crash_ms"] = elapsed_ms
    elif result["process_started"]:
        result["launch_successful"] = False
        result["details"].append(
            f"lldb session ended without clear crash signal")

    else:
        result["launch_successful"] = False
        result["debugger_error"] = (
            f"devicectl failed: {(dc_output or '')[-300:]}, "
            f"lldb output: {lldb_text[-200:] if lldb_text else '(empty)'}")
        result["details"].append(result["debugger_error"])

    syslog_text = capturer.get_text()
    for pattern, name in CRASH_PATTERNS + CODESIGNING_KILL_PATTERNS:
        if pattern.search(syslog_text):
            if not result["crash_detected"]:
                result["crash_detected"] = True
            result["details"].append(f"[SYSLOG:{name}] detected")

    return result
    result["details"].append(f"devicectl: {dc_output.strip()[-200:]}")

    if "Launched" not in dc_output:
        result["debugger_error"] = dc_output.strip()
        result["details"].append("devicectl failed to launch app in stopped state")
        result["launch_duration_ms"] = int((time.time() - launch_start) * 1000)
        return result

    process_detected = wait_for_app_start(bundle_id, udid, timeout=10)
    if not process_detected:
        result["debugger_error"] = "App process did not appear after --start-stopped launch"
        result["launch_duration_ms"] = int((time.time() - launch_start) * 1000)
        return result

    pid = get_app_pid(bundle_id, udid)
    result["process_started"] = True
    result["details"].append(f"Process detected: PID={pid}")

    lldb_commands = [
        f"device select {udid}",
    ]
    if lldb_script_path and os.path.exists(lldb_script_path):
        lldb_commands.append(f"command source {lldb_script_path}")
    lldb_commands += [
        f"device process attach -p {pid}",
        "bt all",
        "process continue",
        "bt all",
        "thread info",
        "register read",
        "frame variable",
        "quit",
    ]

    lldb_script = tempfile.NamedTemporaryFile(
        mode="w", suffix=".lldb", delete=False, prefix="lldb_auto_",
    )
    for cmd in lldb_commands:
        lldb_script.write(cmd + "\n")
    lldb_script.close()
    script_path = lldb_script.name

    print(f"[INFO] Running lldb (may take up to {launch_timeout + monitor_time + 30}s)...")
    lldb_output_lines: list[str] = []
    try:
        lldb_proc = subprocess.Popen(
            ["xcrun", "lldb", "-b", "-s", script_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )

        deadline = time.time() + launch_timeout + monitor_time + 60
        import select
        while lldb_proc.poll() is None and time.time() < deadline:
            try:
                readable, _, _ = select.select([lldb_proc.stdout], [], [], 1.0)
                if readable:
                    line = lldb_proc.stdout.readline()
                    if line:
                        lldb_output_lines.append(line)
            except Exception:
                pass

        if lldb_proc.poll() is None:
            lldb_proc.terminate()
            try:
                lldb_proc.wait(timeout=3)
            except Exception:
                lldb_proc.kill()
    except Exception as e:
        result["details"].append(f"lldb error: {e}")
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass

    lldb_text = "".join(lldb_output_lines)
    result["debugger_output"] = lldb_text

    crash_info = _parse_lldb_crash(lldb_text)

    elapsed_ms = int((time.time() - launch_start) * 1000)
    result["launch_duration_ms"] = elapsed_ms

    if crash_info["crash_detected"]:
        result["launch_successful"] = False
        result["crash_detected"] = True
        result["crash_signal"] = crash_info["signal_name"]
        result["details"].append(
            f"[LLDB] Signal: {crash_info['signal_name']}, "
            f"Stop: {crash_info['stop_reason']}, "
            f"Fault: {crash_info['fault_address']}, "
            f"Exception: {crash_info['exception_type']}")
        if crash_info["backtrace"]:
            # Store backtrace in details (first 2000 chars)
            result["details"].append(
                f"[BACKTRACE]\n{crash_info['backtrace'][:2000]}")
        result["runtime_before_crash_ms"] = elapsed_ms
    elif crash_info.get("pid") and not crash_info["crash_detected"]:
        result["launch_successful"] = True
        result["process_ended_cleanly"] = True
        result["runtime_before_crash_ms"] = elapsed_ms
    else:
        result["launch_successful"] = False
        result["details"].append(
            f"lldb session ended without clear crash signal. "
            f"Last output: {lldb_text[-300:] if lldb_text else '(empty)'}")

    # Also check syslog for crash evidence
    syslog_text = capturer.get_text()
    for pattern, name in CRASH_PATTERNS + CODESIGNING_KILL_PATTERNS:
        if pattern.search(syslog_text):
            if not result["crash_detected"]:
                result["crash_detected"] = True
            result["details"].append(f"[SYSLOG:{name}] detected")

    return result

def _launch_via_devicectl(bundle_id: str, udid: str, launch_timeout: int,
                         monitor_time: int, capturer: "SyslogCapturer",
                         launch_start: float) -> dict:
    """Launch via xcrun devicectl (Xcode 16+ CoreDevice). No debugserver needed.

    Returns result_data dict.
    """
    result: dict = {
        "launch_successful": False,
        "process_started": False,
        "process_ended_cleanly": False,
        "crash_detected": False,
        "watchdog_detected": False,
        "exit_code": 0,
        "crash_signal": "",
        "launch_duration_ms": 0,
        "runtime_before_crash_ms": 0,
        "debugger_output": "",
        "debugger_error": "",
        "fallback_used": False,
        "details": [],
    }

    total_timeout = launch_timeout + monitor_time
    cmd = [
        DEVICECTL, "devicectl", "device", "process", "launch",
        "--device", udid,
        "--timeout", "15",
        bundle_id,
    ]

    print(f"[INFO] Launching via devicectl (Xcode 16+ CoreDevice)...")
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        preexec_fn=os.setsid,
    )

    output_lines: list[str] = []
    process_detected = False
    process_start_time = 0
    crash_signal = ""
    launch_deadline = time.time() + total_timeout + 5

    import select
    while proc.poll() is None and time.time() < launch_deadline:
        try:
            readable, _, _ = select.select([proc.stdout], [], [], 1.0)
            if readable:
                line = proc.stdout.readline()
                if line:
                    output_lines.append(line)
                    if "Launched application" in line and not process_detected:
                        process_detected = True
                        process_start_time = time.time()
                        result["process_started"] = True
                        result["details"].append(
                            f"App launched at "
                            f"T+{int((process_start_time - launch_start) * 1000)}ms")
                        print(f"[INFO] App launched via devicectl")
                    signal_match = re.search(
                        r"terminated due to signal (\d+)", line
                    )
                    if signal_match:
                        crash_signal = signal_match.group(1)
                        result["details"].append(
                            f"[SIGNAL:{crash_signal}] {line.strip()}")
        except Exception:
            pass

        if not process_detected and time.time() > launch_start + 8:
            # Check if app appeared in pidlist
            if is_app_running(bundle_id, udid):
                process_detected = True
                process_start_time = time.time()
                result["process_started"] = True

        if process_detected:
            if not is_app_running(bundle_id, udid):
                syslog_text = capturer.get_text()
                for pattern, name in CRASH_PATTERNS + CODESIGNING_KILL_PATTERNS:
                    if pattern.search(syslog_text):
                        result["crash_detected"] = True
                        result["details"].append(
                            f"[CRASH:{name}] detected in syslog")
                        break
                break

    # Drain remaining output
    _drain_output(proc, output_lines)
    if proc.poll() is None:
        _kill_process_group(proc)

    result["debugger_output"] = "".join(output_lines)
    result["exit_code"] = proc.returncode or 0
    result["launch_duration_ms"] = int((time.time() - launch_start) * 1000)

    # Classify
    if crash_signal:
        result["crash_detected"] = True
        result["crash_signal"] = crash_signal
    if not process_detected:
        result["launch_successful"] = False
        output_str = result["debugger_output"]
        for pattern, name in CODESIGNING_KILL_PATTERNS:
            if pattern.search(output_str):
                result["crash_detected"] = True
                result["details"].append(f"[CODESIGNING:{name}] detected in output")
    elif result.get("crash_detected"):
        result["launch_successful"] = False
    else:
        result["launch_successful"] = True
        result["process_ended_cleanly"] = True
        result["runtime_before_crash_ms"] = int(
            (time.time() - process_start_time) * 1000)

    return result


def _launch_via_debugger(bundle_id: str, udid: str, launch_timeout: int,
                         monitor_time: int, capturer: "SyslogCapturer",
                         launch_start: float) -> dict:
    """Launch via idevicedebug and monitor. Returns result_data dict."""
    result: dict = {
        "launch_successful": False,
        "process_started": False,
        "process_ended_cleanly": False,
        "crash_detected": False,
        "watchdog_detected": False,
        "exit_code": 0,
        "launch_duration_ms": 0,
        "runtime_before_crash_ms": 0,
        "debugger_output": "",
        "debugger_error": "",
        "fallback_used": False,
        "details": [],
    }

    cmd = [IDEVICEDEBUG, "-u", udid, "run", bundle_id]
    print(f"[INFO] Launching {bundle_id} with debugger...")
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, preexec_fn=os.setsid,
    )

    debugger_lines: list[str] = []
    crashed = False
    process_detected = False
    process_start_time = 0
    process_end_time = 0
    runtime_deadline = time.time() + launch_timeout + monitor_time
    debugger_failed = False

    while proc.poll() is None and time.time() < runtime_deadline:
        try:
            import select
            readable, _, _ = select.select([proc.stdout], [], [], 1.0)
            if readable:
                line = proc.stdout.readline()
                if line:
                    debugger_lines.append(line)
                    line_lower = line.lower()

                    for pattern, name in DEBUGSERVER_FAIL_PATTERNS:
                        if pattern.search(line):
                            debugger_failed = True
                            result["details"].append(
                                f"[DEBUG:{name}] {line.strip()}")

                    if not crashed:
                        for pattern, name in CRASH_PATTERNS:
                            if pattern.search(line):
                                crashed = True
                                process_end_time = time.time()
                                result["details"].append(
                                    f"[CRASH:{name}] {match_line(line, name)}")
                                break

                    for pattern, name in WATCHDOG_PATTERNS:
                        if pattern.search(line_lower):
                            result["watchdog_detected"] = True
                            result["details"].append(
                                f"[WATCHDOG:{name}] {line.strip()}")
        except Exception:
            pass

        if not process_detected:
            if is_app_running(bundle_id, udid):
                process_detected = True
                process_start_time = time.time()
                result["process_started"] = True
                result["details"].append(
                    f"Process {bundle_id} detected at "
                    f"T+{int((process_start_time - launch_start) * 1000)}ms")
                print(f"[INFO] App process started")

    # Drain remaining output after process exit
    _drain_output(proc, debugger_lines)

    # Kill debugger if still running
    _kill_process_group(proc)

    # Kill app if still running
    process_still_alive = is_app_running(bundle_id, udid)
    if process_still_alive:
        kill_app(bundle_id, udid)

    result["debugger_output"] = "".join(debugger_lines)
    result["exit_code"] = proc.returncode or 0

    elapsed_ms = int((time.time() - launch_start) * 1000)

    if debugger_failed and not process_detected:
        result["launch_successful"] = False
        result["debugger_error"] = result["debugger_output"].strip()
        result["details"].append(
            f"Debugger failed (exit={proc.returncode}): "
            f"{result['debugger_error'][:200]}")
        result["launch_duration_ms"] = elapsed_ms
        return result

    if not process_detected:
        result["launch_successful"] = False
        result["details"].append(
            f"App process never appeared after {elapsed_ms}ms")
    elif crashed:
        result["launch_successful"] = False
        result["crash_detected"] = True
        if process_start_time > 0:
            result["runtime_before_crash_ms"] = int(
                (process_end_time - process_start_time) * 1000)
    elif process_still_alive and not crashed:
        result["launch_successful"] = True
        result["process_ended_cleanly"] = True
        result["runtime_before_crash_ms"] = int(
            (time.time() - process_start_time) * 1000)
    elif not process_still_alive and not crashed:
        result["details"].append(
            "Process disappeared without detected crash signal")
        result["runtime_before_crash_ms"] = int(
            (time.time() - process_start_time) * 1000) if process_start_time > 0 else 0

    result["launch_duration_ms"] = elapsed_ms
    return result


def _launch_via_ios_deploy(bundle_id: str, udid: str, capturer: "SyslogCapturer",
                           launch_start: float) -> dict:
    """Fallback: launch app via ios-deploy (no debugger needed).

    Returns result_data dict.
    """
    result: dict = {
        "launch_successful": False,
        "process_started": False,
        "process_ended_cleanly": False,
        "crash_detected": False,
        "watchdog_detected": False,
        "exit_code": 0,
        "launch_duration_ms": 0,
        "runtime_before_crash_ms": 0,
        "debugger_output": "",
        "debugger_error": "",
        "fallback_used": True,
        "details": [],
    }

    # ios-deploy needs a package path to install+launch.
    # With --bundle_id alone, the only way to launch is via debugserver (-N).
    # Try -N with short timeout - if debugserver works, the app will launch.
    print(f"[INFO] Fallback: launching via ios-deploy -N (debugserver only)...")
    cmd = [IOS_DEPLOY, "--id", udid, "--bundle_id", bundle_id, "-N", "-I"]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        preexec_fn=os.setsid,
    )

    # Wait for process to appear (ios-deploy -N starts debugserver, which launches app)
    deadline = time.time() + 15
    process_detected = False
    lines: list[str] = []
    while proc.poll() is None and time.time() < deadline:
        if not process_detected and is_app_running(bundle_id, udid):
            process_detected = True
        time.sleep(0.5)

    _kill_process_group(proc)
    _drain_output(proc, lines)

    result["debugger_output"] = "".join(lines)
    result["exit_code"] = proc.returncode or 0
    result["details"].append(f"ios-deploy exit code: {proc.returncode}")

    if process_detected:
        result["process_started"] = True
        result["launch_successful"] = True
        result["details"].append(
            f"App launched via ios-deploy at "
            f"T+{int((time.time() - launch_start) * 1000)}ms")
        print("[INFO] App launched via ios-deploy fallback")
    else:
        if is_app_running(bundle_id, udid):
            result["process_started"] = True
            result["launch_successful"] = True
        else:
            result["details"].append(
                "ios-deploy launch also failed (debugserver unavailable). "
                "Ensure Developer Mode is enabled on device: "
                "Settings > Privacy & Security > Developer Mode")

    result["launch_duration_ms"] = int((time.time() - launch_start) * 1000)
    return result


def _drain_output(proc: subprocess.Popen, lines: list[str]) -> None:
    """Read remaining output from a terminated process."""
    try:
        remaining = proc.stdout.read() if proc.stdout else ""
        if remaining:
            lines.append(remaining)
    except Exception:
        pass


def _kill_process_group(proc: subprocess.Popen) -> None:
    """Kill a process group if still running."""
    if proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=3)
        except Exception:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


def launch_and_monitor(bundle_id: str, udid: str, launch_timeout: int,
                       monitor_time: int, lldb_debug: bool = False,
                       lldb_script_path: Optional[str] = None) -> dict:
    """Launch the app and monitor its state.

    Strategy (priority order):
      1. lldb debug (if --lldb-debug): attach lldb, capture crash backtrace
      2. devicectl (Xcode 16+ CoreDevice) - no debugserver needed
      3. idevicedebug (debugger attached, crash signal detection)
      4. ios-deploy (last resort fallback)
      After launch, monitor process state via pidlist and syslog.
    """
    launch_start = time.time()
    result_data: dict = {
        "launch_successful": False,
        "process_started": False,
        "process_ended_cleanly": False,
        "crash_detected": False,
        "watchdog_detected": False,
        "exit_code": 0,
        "crash_signal": "",
        "launch_duration_ms": 0,
        "runtime_before_crash_ms": 0,
        "debugger_output": "",
        "debugger_error": "",
        "fallback_used": False,
        "syslog_analysis": {},
        "details": [],
    }

    capturer = SyslogCapturer(udid)
    capturer.start()
    time.sleep(1)

    if lldb_debug:
        launch_result = _launch_via_lldb(
            bundle_id, udid, launch_timeout, monitor_time,
            capturer, launch_start, lldb_script_path,
        )
    else:
        launch_result = _launch_via_devicectl(
            bundle_id, udid, launch_timeout, monitor_time, capturer, launch_start,
        )

    for key in ("launch_successful", "process_started", "process_ended_cleanly",
                "crash_detected", "watchdog_detected", "exit_code",
                "crash_signal", "runtime_before_crash_ms", "debugger_output",
                "launch_duration_ms"):
        result_data[key] = launch_result[key]
    result_data["details"].extend(launch_result["details"])

    if result_data.get("launch_successful") and result_data.get("process_started"):
        _monitor_app_alive(
            bundle_id, udid, monitor_time, capturer, launch_start, result_data,
        )

    capturer.stop()
    syslog_text = capturer.get_text()

    syslog_analysis = classify_from_syslog(syslog_text, result_data["details"])
    result_data["syslog_analysis"] = syslog_analysis

    if syslog_analysis["exception_codes"]:
        result_data["details"].append(
            f"Exception codes in syslog: {', '.join(syslog_analysis['exception_codes'])}")
    if syslog_analysis["termination_reasons"]:
        result_data["details"].append(
            f"Termination reasons: {', '.join(syslog_analysis['termination_reasons'])}")

    return result_data


def _monitor_app_alive(bundle_id: str, udid: str, monitor_time: int,
                       capturer: "SyslogCapturer", launch_start: float,
                       result_data: dict) -> None:
    """Poll for app process liveness during the monitoring period."""
    deadline = time.time() + monitor_time
    crash_detected = False
    last_alive = time.time()

    while time.time() < deadline:
        alive = is_app_running(bundle_id, udid)
        if alive:
            last_alive = time.time()
        else:
            if not crash_detected:
                # Process disappeared - check syslog for crash signs
                syslog_snapshot = capturer.get_text()
                analysis = classify_from_syslog(syslog_snapshot, [])
                if analysis["crashes"] or analysis["exception_codes"]:
                    crash_detected = True
                    result_data["crash_detected"] = True
                    result_data["details"].append(
                        f"App crashed after "
                        f"{int((time.time() - launch_start) * 1000)}ms runtime")
                    result_data["runtime_before_crash_ms"] = int(
                        (time.time() - launch_start) * 1000)
                elif analysis["watchdog_events"]:
                    result_data["watchdog_detected"] = True
                    result_data["details"].append(
                        f"Watchdog event during monitoring at "
                        f"T+{int((time.time() - launch_start) * 1000)}ms")
        time.sleep(1)

    if not crash_detected and is_app_running(bundle_id, udid):
        result_data["process_ended_cleanly"] = True
        result_data["runtime_before_crash_ms"] = int(
            (time.time() - launch_start) * 1000)


def match_line(line: str, pattern_name: str) -> str:
    """Extract a meaningful snippet from a log line."""
    return line.strip()[:200]


def kill_app(bundle_id: str, udid: str) -> None:
    """Kill the app on the device."""
    try:
        run_cmd([IDEVICEDEBUG, "-u", udid, "kill", bundle_id], timeout=10)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Status classification
# ---------------------------------------------------------------------------

def classify_status(monitor_data: dict, launch_timeout: int,
                    install_error: Optional[str] = None) -> tuple[AppStatus, str, list[str]]:
    """
    Classify the app status from monitoring data.

    Returns (AppStatus, summary, details).
    """
    details = list(monitor_data.get("details", []))
    syslog_analysis = monitor_data.get("syslog_analysis", {})

    # 1. Installation failure
    if install_error:
        details.insert(0, f"INSTALL_FAILURE: {install_error}")
        return AppStatus.INSTALL_FAILURE, install_error, details

    # 2. Launch Failure - app never started
    if not monitor_data.get("process_started"):
        # Check debugger error FIRST (more specific/reliable than syslog keyword matching)
        debugger_error = monitor_data.get("debugger_error", "")
        if debugger_error:
            if "debugserver" in debugger_error.lower():
                if monitor_data.get("fallback_used"):
                    msg = (f"Launch failed: debugserver unavailable and ios-deploy "
                           f"fallback also failed. Check: (1) Developer Mode enabled "
                           f"in Settings > Privacy & Security, (2) device trusted "
                           f"this computer. Error: {debugger_error[:150]}")
                else:
                    msg = (f"Launch failed: debugserver unavailable. "
                           f"Developer disk image may not be mounted, or Developer "
                           f"Mode not enabled on device. Error: {debugger_error[:150]}")
            else:
                msg = (f"Launch failed: debugger error (exit="
                       f"{monitor_data.get('exit_code', '?')}). "
                       f"{debugger_error[:200]}")
            return AppStatus.LAUNCH_FAILURE, msg, details

        # Check signing errors from syslog (only if NO debugger error)
        signing_errors = syslog_analysis.get("signing_errors", [])
        if signing_errors:
            msg = f"Launch failed: possible signing/entitlement issues: {', '.join(signing_errors)}"
            return AppStatus.LAUNCH_FAILURE, msg, details

        elapsed_ms = monitor_data.get("launch_duration_ms", 0)
        debugger_output = monitor_data.get("debugger_output", "")
        for pattern, name in CODESIGNING_KILL_PATTERNS:
            if pattern.search(debugger_output):
                msg = (f"Launch crash: app killed by CODESIGNING "
                       f"(code signing violation / Invalid Page). "
                       f"Check entitlements: com.apple.security.cs.allow-jit "
                       f"or com.apple.security.cs.allow-unsigned-executable-memory "
                       f"may be required for iOS 18+")
                return AppStatus.LAUNCH_CRASH, msg, details
        if elapsed_ms > 0:
            msg = f"Launch failed: app process never appeared after {elapsed_ms}ms"
        else:
            msg = f"Launch failed: app process never started"
        return AppStatus.LAUNCH_FAILURE, msg, details

    # 3. Launch Crash - app crashed within launch_timeout
    if monitor_data.get("crash_detected"):
        runtime_before_crash = monitor_data.get("runtime_before_crash_ms", 0)
        if runtime_before_crash < launch_timeout * 1000:
            crash_info = ", ".join(syslog_analysis.get("exception_types", [])[:3])
            if not crash_info:
                crash_info = "unknown crash signal"

            # Check if it's actually a watchdog timeout
            if monitor_data.get("watchdog_detected") or syslog_analysis.get("watchdog_events"):
                wd_events = ", ".join(syslog_analysis.get("watchdog_events", []))
                msg = f"Launch timeout: app killed by system watchdog. Events: {wd_events}"
                return AppStatus.LAUNCH_TIMEOUT, msg, details

            msg = f"Launch crash: app crashed {runtime_before_crash}ms after start. {crash_info}"
            return AppStatus.LAUNCH_CRASH, msg, details

    # 4. Launch Timeout / System Kill without explicit crash
    if monitor_data.get("watchdog_detected") or syslog_analysis.get("watchdog_events"):
        wd_events = ", ".join(syslog_analysis.get("watchdog_events", []))
        msg = f"Launch timeout: system watchdog killed app. Events: {wd_events}"
        return AppStatus.LAUNCH_TIMEOUT, msg, details

    # 5. Runtime Crash - crashed after launch_timeout
    if monitor_data.get("crash_detected"):
        crash_info = ", ".join(syslog_analysis.get("exception_types", [])[:3])
        if not crash_info:
            crash_info = "unknown crash signal"
        msg = f"Runtime crash: app crashed after running. {crash_info}"
        return AppStatus.RUNTIME_CRASH, msg, details

    # 6. Check for process disappearing without crash (possible system kill)
    if not monitor_data.get("process_ended_cleanly") and monitor_data.get("process_started"):
        jetsam_events = syslog_analysis.get("jetsam_events", [])
        if jetsam_events:
            msg = f"Runtime crash: app killed by Jetsam (memory pressure): {', '.join(jetsam_events)}"
            return AppStatus.RUNTIME_CRASH, msg, details

        freeze_events = syslog_analysis.get("freeze_hang_events", [])
        if freeze_events:
            msg = f"Runtime crash: app terminated after hang/freeze: {', '.join(freeze_events)}"
            return AppStatus.RUNTIME_CRASH, msg, details

        # Process just died
        msg = "App process terminated unexpectedly (no crash signal detected)"
        return AppStatus.RUNTIME_CRASH, msg, details

    # 7. Success
    runtime_ms = monitor_data.get("runtime_before_crash_ms", 0)
    msg = f"App launched and ran successfully ({runtime_ms}ms monitored)"
    return AppStatus.SUCCESS, msg, details


# ---------------------------------------------------------------------------
# Log collection
# ---------------------------------------------------------------------------

def collect_crash_reports(udid: str, output_dir: str, bundle_id: Optional[str] = None,
                          app_name: Optional[str] = None) -> list[str]:
    """Collect crash reports from device. Returns list of report file paths.

    If app_name is provided, filters by the app's process name (e.g., 'SecureUtilityPlusDemo').
    If bundle_id is provided, it's used as a secondary filter.
    """
    crash_dir = os.path.join(output_dir, "crash_reports")
    os.makedirs(crash_dir, exist_ok=True)

    cmd = [IDEVICECRASHREPORT, "-u", udid, "-e", "-k", crash_dir]
    if app_name:
        cmd.extend(["-f", app_name])
    elif bundle_id:
        cmd.extend(["-f", bundle_id])

    try:
        result = run_cmd(cmd, timeout=30)
        print(f"[INFO] Crash report collection: {result.stdout.strip()}")
    except subprocess.TimeoutExpired:
        print("[WARN] Crash report collection timed out")
    except Exception as e:
        print(f"[WARN] Crash report collection failed: {e}")

    reports = []
    if os.path.isdir(crash_dir):
        for root, _dirs, files in os.walk(crash_dir):
            for f in files:
                if f.endswith(".ips"):
                    reports.append(os.path.join(root, f))
    return reports


def collect_logarchive(udid: str, output_dir: str, name: str = "logarchive") -> Optional[str]:
    """
    Collect full logarchive from device (includes OSLog, crash logs, hang/freeze data).
    Returns path to tar file or None.
    """
    output_path = os.path.join(output_dir, f"{name}.tar")
    os.makedirs(output_dir, exist_ok=True)

    # idevicesyslog archive outputs .tar data
    cmd = [IDEVICESYSLOG, "-u", udid, "archive", output_path]

    try:
        result = run_cmd(cmd, timeout=60)
        if result.returncode == 0 and os.path.isfile(output_path):
            print(f"[INFO] Logarchive saved: {output_path} "
                  f"({os.path.getsize(output_path)} bytes)")
            return output_path
        else:
            print(f"[WARN] Logarchive collection failed: {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        print("[WARN] Logarchive collection timed out")
    except Exception as e:
        print(f"[WARN] Logarchive collection failed: {e}")

    return None


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def run_auto_test(ipa_path: Optional[str] = None,
                   bundle_id: Optional[str] = None,
                   udid: Optional[str] = None,
                   no_install: bool = False,
                   reinstall: bool = False,
                   launch_timeout: int = 20,
                   monitor_time: int = 30,
                   output_dir: str = "./ios_test_output",
                   auto_sign: bool = False,
                   sign_entitlements: Optional[list[str]] = None,
                   restore_symbols: bool = False,
                   provision_profile: Optional[str] = None,
                   restore_stripped: bool = False,
                   lldb_debug: bool = False) -> TestResult:
    """
    Run the complete automated test flow.

    Args:
        ipa_path: Path to IPA file for installation
        bundle_id: Bundle identifier (auto-detected from IPA if not provided)
        udid: Device UDID (auto-detected if not provided)
        no_install: Skip installation, use already-installed app
        reinstall: Force reinstall even if app already exists
        launch_timeout: Max seconds to wait for app launch
        monitor_time: How long to monitor after successful launch
        output_dir: Directory for all output files

    Returns:
        TestResult with full status and log references
    """
    # Initialize result
    result = TestResult()
    result.start_time = datetime.now().isoformat()
    os.makedirs(output_dir, exist_ok=True)

    # -----------------------------------------------------------------------
    # Step 1: Detect device
    # -----------------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f"[STEP 1/6] Detecting iOS device...")
    print(f"{'='*60}")
    try:
        device_udid, device_name = detect_device(udid)
        result.device_udid = device_udid
        result.device_name = device_name
        print(f"[OK] Device: {device_udid} ({device_name})")
    except Exception as e:
        result.status = AppStatus.UNKNOWN.value
        result.errors.append(f"Device detection failed: {e}")
        result.end_time = datetime.now().isoformat()
        return result

    # -----------------------------------------------------------------------
    # Step 2: Determine bundle ID
    # -----------------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f"[STEP 2/6] Determining bundle ID...")
    print(f"{'='*60}")

    if bundle_id:
        print(f"[INFO] Using provided bundle ID: {bundle_id}")
    elif ipa_path:
        try:
            bundle_id = extract_bundle_id_from_ipa(ipa_path)
            print(f"[OK] Bundle ID from IPA: {bundle_id}")
        except Exception as e:
            result.status = AppStatus.UNKNOWN.value
            result.errors.append(f"Bundle ID extraction failed: {e}")
            result.end_time = datetime.now().isoformat()
            return result
    else:
        result.status = AppStatus.UNKNOWN.value
        result.errors.append("Must provide --ipa or --bundle-id")
        result.end_time = datetime.now().isoformat()
        return result

    result.bundle_id = bundle_id
    if ipa_path:
        result.ipa_path = ipa_path

    if auto_sign and ipa_path:
        print(f"\n{'='*60}")
        print(f"[STEP 2.5/6] Auto-signing IPA with extra entitlements...")
        print(f"{'='*60}")
        ents = sign_entitlements or DEFAULT_EXTRA_ENTITLEMENTS
        print(f"[INFO] Adding entitlements: {', '.join(ents)}")
        signed_path = auto_sign_ipa(ipa_path, extra_entitlements=ents,
                                     provision_profile=provision_profile,
                                     restore_stripped=restore_stripped)
        if signed_path:
            ipa_path = signed_path
            result.ipa_path = ipa_path
            print(f"[OK] Signed IPA: {ipa_path}")

            os.makedirs(output_dir, exist_ok=True)
            ent_dir = os.path.join(output_dir, "entitlements.json")
            with open(ent_dir, "w") as f:
                json.dump(ents, f)
        else:
            print("[WARN] Auto-sign failed, continuing with original IPA")

    # -----------------------------------------------------------------------
    # Step 3: Install app
    # -----------------------------------------------------------------------
    install_error = None

    if no_install:
        print(f"\n{'='*60}")
        print(f"[STEP 3/6] Skipping installation (--no-install)...")
        print(f"{'='*60}")
        if not check_app_installed(bundle_id, device_udid):
            print(f"[WARN] App {bundle_id} is not installed on device!")
    elif ipa_path:
        print(f"\n{'='*60}")
        print(f"[STEP 3/6] Installing app...")
        print(f"{'='*60}")
        success, msg = install_app(ipa_path, device_udid, reinstall)
        if not success:
            install_error = msg
            result.errors.append(msg)
            print(f"[FAIL] {msg}")
            if auto_sign and "entitlement" in msg.lower():
                print("[NOTE] JIT/memory entitlements require a paid "
                      "Apple Developer account to pass install verification.")

            result.status = AppStatus.INSTALL_FAILURE.value
            result.summary = msg
            result.end_time = datetime.now().isoformat()
            collect_crash_reports(device_udid, output_dir, bundle_id)
            collect_logarchive(device_udid, output_dir)
            return result
        print(f"[OK] {msg}")
    else:
        # No IPA, check if app exists
        if not check_app_installed(bundle_id, device_udid):
            msg = f"App {bundle_id} not installed and no IPA provided for installation"
            result.errors.append(msg)
            result.status = AppStatus.LAUNCH_FAILURE.value
            result.summary = msg
            result.end_time = datetime.now().isoformat()
            return result

    # -----------------------------------------------------------------------
    # Step 4: Start syslog capture
    # -----------------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f"[STEP 4/6] Starting syslog capture...")
    print(f"{'='*60}")

    syslog_path = os.path.join(output_dir, f"syslog_{bundle_id.replace('.', '_')}.log")
    syslog_capturer = SyslogCapturer(device_udid, output_path=syslog_path)
    syslog_capturer.start()
    time.sleep(2)  # Let syslog connection stabilize

    # Also capture process-specific logs
    process_syslog = SyslogCapturer(
        device_udid,
        process_name=bundle_id,
    )
    process_syslog.start()
    time.sleep(1)

    print(f"[OK] Syslog capture started -> {syslog_path}")

    # -----------------------------------------------------------------------
    # Step 5: Launch and monitor
    # -----------------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f"[STEP 5/6] Launching and monitoring app...")
    print(f"[INFO] Launch timeout: {launch_timeout}s, Monitor time: {monitor_time}s")
    print(f"{'='*60}")

    # Kill any existing instance first
    try:
        kill_app(bundle_id, device_udid)
        time.sleep(1)
    except Exception:
        pass

    # Also check and kill any zombie process
    pid = get_app_pid(bundle_id, device_udid)
    if pid:
        print(f"[INFO] Killing existing process PID={pid}")
        run_cmd([IDEVICEDEBUG, "-u", device_udid, "kill", bundle_id], timeout=5)
        time.sleep(1)

    lldb_script = os.path.join(output_dir, "lldb_load_symbols.txt")
    lldb_script_path_arg = None
    if lldb_debug:
        if not os.path.exists(lldb_script) and ipa_path:
            extract_dir = os.path.join(output_dir, "ipa_binaries")
            generate_lldb_symbol_script(ipa_path, lldb_script,
                                        extract_dir=extract_dir)
        if os.path.exists(lldb_script):
            lldb_script_path_arg = lldb_script

    monitor_data = launch_and_monitor(
        bundle_id, device_udid, launch_timeout, monitor_time,
        lldb_debug=lldb_debug,
        lldb_script_path=lldb_script_path_arg,
    )

    # -----------------------------------------------------------------------
    # Step 5b: Stop syslog
    # -----------------------------------------------------------------------
    syslog_capturer.stop()
    process_syslog.stop()

    # Save process-specific logs
    process_log_path = os.path.join(
        output_dir,
        f"syslog_{bundle_id.replace('.', '_')}_process.log",
    )
    process_syslog.dump_to_file(process_log_path)

    result.log_files["syslog_full"] = syslog_path
    result.log_files["syslog_process"] = process_log_path

    # -----------------------------------------------------------------------
    # Step 6: Classify status and collect crash reports
    # -----------------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f"[STEP 6/6] Classifying status and collecting logs...")
    print(f"{'='*60}")

    status, summary, details = classify_status(monitor_data, launch_timeout, install_error)

    result.status = status.value
    result.summary = summary
    result.details = details
    result.launch_duration_ms = monitor_data.get("launch_duration_ms", 0)
    result.runtime_duration_ms = monitor_data.get("runtime_before_crash_ms", 0)
    result.exit_code = monitor_data.get("exit_code", 0)

    debugger_output = monitor_data.get("debugger_output", "")
    if debugger_output:
        suffix = "_lldb.log" if lldb_debug else ".log"
        debug_path = os.path.join(output_dir, f"debugger_output{suffix}")
        with open(debug_path, "w") as f:
            f.write(debugger_output)
        result.log_files["debugger_output"] = debug_path

    # Collect crash reports if there was a crash
    if status in {AppStatus.LAUNCH_CRASH, AppStatus.RUNTIME_CRASH,
                  AppStatus.LAUNCH_TIMEOUT, AppStatus.LAUNCH_FAILURE}:
        print("[INFO] Collecting crash reports...")
        app_name = bundle_id.split(".")[-1] if bundle_id else None
        crash_reports = collect_crash_reports(device_udid, output_dir,
                                              bundle_id=bundle_id,
                                              app_name=app_name)
        result.crash_reports = crash_reports
        if crash_reports:
            print(f"[OK] Found {len(crash_reports)} crash report(s)")
            if status == AppStatus.LAUNCH_FAILURE:
                for report_path in crash_reports:
                    try:
                        with open(report_path, "r", errors="ignore") as f:
                            content = f.read()
                        if "CODESIGNING" in content and "Invalid Page" in content:
                            result.status = AppStatus.LAUNCH_CRASH.value
                            result.summary = (
                                "Launch crash: CODESIGNING Invalid Page detected "
                                "in crash report. Code signing validation failure "
                                "at runtime. App may use JIT or runtime code "
                                "generation requiring entitlements: "
                                "com.apple.security.cs.allow-jit, "
                                "com.apple.security.cs.allow-unsigned-executable-memory")
                            result.details.append(
                                f"CODESIGNING detected in: {os.path.basename(report_path)}")
                            break
                    except Exception:
                        pass
        else:
            print("[INFO] No crash reports found on device")

    # Always collect logarchive for full diagnostics (OSLog, hang logs, etc.)
    print("[INFO] Collecting logarchive (OSLog, hang/freeze data)...")
    logarchive_path = collect_logarchive(device_udid, output_dir)
    if logarchive_path:
        result.log_files["logarchive"] = logarchive_path

    # Save syslog analysis
    syslog_analysis = monitor_data.get("syslog_analysis", {})
    if syslog_analysis:
        analysis_path = os.path.join(output_dir, "syslog_analysis.json")
        with open(analysis_path, "w") as f:
            json.dump(syslog_analysis, f, indent=2, ensure_ascii=False)
        result.log_files["syslog_analysis"] = analysis_path

    # Save full test result
    result_path = os.path.join(output_dir, "test_result.json")
    with open(result_path, "w") as f:
        f.write(result.to_json())
    result.log_files["test_result"] = result_path

    result.end_time = datetime.now().isoformat()

    if restore_symbols and ipa_path:
        print(f"\n{'='*60}")
        print(f"[STEP 7/7] Symbolicating crash reports...")
        print(f"{'='*60}")

        lldb_script = os.path.join(output_dir, "lldb_load_symbols.txt")
        extract_dir = os.path.join(output_dir, "ipa_binaries")
        generate_lldb_symbol_script(ipa_path, lldb_script, extract_dir=extract_dir)
        result.log_files["lldb_script"] = lldb_script
        print(f"[OK] lldb symbol script -> {lldb_script}")
        print(f"[INFO] To use in lldb: (lldb) command source {lldb_script}")

        if result.crash_reports:
            sym_dir = os.path.join(output_dir, "symbolicated")
            sym_paths = symbolicate_all_reports(
                os.path.join(output_dir, "crash_reports"), ipa_path, sym_dir,
            )
            if sym_paths:
                result.log_files["symbolicated"] = sym_dir
                print(f"[OK] {len(sym_paths)} symbolicated reports -> {sym_dir}")
            else:
                print("[WARN] Symbolication produced no output")
        else:
            print("[INFO] No crash reports to symbolicate (app ran successfully)")

    # Print summary banner
    print(f"\n{'='*60}")
    print(f"  TEST RESULT: {result.status}")
    print(f"  {result.summary}")
    print(f"  Device: {result.device_udid} ({result.device_name})")
    print(f"  Bundle ID: {result.bundle_id}")
    print(f"  Launch duration: {result.launch_duration_ms}ms")
    print(f"  Runtime duration: {result.runtime_duration_ms}ms")
    print(f"  Output: {output_dir}")
    print(f"  Full report: {result_path}")
    print(f"{'='*60}")

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="iOS App Automation Test Tool - Install, Launch, Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ios_auto_test.py --ipa /path/to/app.ipa
  python3 ios_auto_test.py --ipa /path/to/app.ipa --bundle-id com.example.app
  python3 ios_auto_test.py --bundle-id com.example.app --no-install
  python3 ios_auto_test.py --ipa /path/to/app.ipa --monitor-time 60 --launch-timeout 30
  python3 ios_auto_test.py --ipa /path/to/app.ipa --udid 00008110-XXXX
  python3 ios_auto_test.py --ipa /path/to/app.ipa --reinstall

Status Classifications:
  SUCCESS         - App launched and ran normally
  LAUNCH_CRASH    - App crashed during launch phase
  LAUNCH_TIMEOUT  - App killed by system watchdog during launch
  RUNTIME_CRASH   - App crashed after running successfully
  LAUNCH_FAILURE  - App failed to start (signing, entitlements, etc.)
  INSTALL_FAILURE - App installation failed
""",
    )

    parser.add_argument(
        "--ipa", type=str, default=None,
        help="Path to .ipa file for installation",
    )
    parser.add_argument(
        "--bundle-id", type=str, default=None,
        help="Bundle identifier (auto-detected from IPA if not specified)",
    )
    parser.add_argument(
        "--udid", type=str, default=None,
        help="Device UDID (auto-detected if not specified)",
    )
    parser.add_argument(
        "--no-install", action="store_true",
        help="Skip installation, use already-installed app",
    )
    parser.add_argument(
        "--reinstall", action="store_true",
        help="Force reinstall even if app already exists",
    )
    parser.add_argument(
        "--launch-timeout", type=int, default=20,
        help="Max seconds to wait for app launch (default: 20)",
    )
    parser.add_argument(
        "--monitor-time", type=int, default=30,
        help="How many seconds to monitor after successful launch (default: 30)",
    )
    parser.add_argument(
        "--output-dir", type=str, default="./ios_test_output",
        help="Directory for test output and logs (default: ./ios_test_output)",
    )
    parser.add_argument(
        "--auto-sign", action="store_true",
        help="Auto-sign IPA with JIT/memory entitlements before installing",
    )
    parser.add_argument(
        "--sign-entitlements", type=str, default=None,
        help="Comma-separated extra entitlements (defaults to JIT+memory+debugger)",
    )
    parser.add_argument(
        "--restore-symbols", action="store_true",
        help="Symbolicate crash reports after test using app binary",
    )
    parser.add_argument(
        "--restore-stripped-symbols", action="store_true",
        help="Run restore-symbol on all Mach-O binaries to recover ObjC "
             "method symbols before signing (requires --auto-sign)",
    )
    parser.add_argument(
        "--provision-profile", type=str, default=None,
        help="Path to .mobileprovision file for signing (e.g. wildcard profile)",
    )
    parser.add_argument(
        "--lldb-debug", action="store_true",
        help="Launch app with lldb attached to capture real-time crash "
             "backtrace, registers, and local variables",
    )

    args = parser.parse_args()

    extra_entitlements = None
    if args.sign_entitlements:
        extra_entitlements = [e.strip() for e in args.sign_entitlements.split(",")]

    result = run_auto_test(
        ipa_path=args.ipa,
        bundle_id=args.bundle_id,
        udid=args.udid,
        no_install=args.no_install,
        reinstall=args.reinstall,
        launch_timeout=args.launch_timeout,
        monitor_time=args.monitor_time,
        output_dir=args.output_dir,
        auto_sign=args.auto_sign,
        sign_entitlements=extra_entitlements,
        restore_symbols=args.restore_symbols,
        provision_profile=args.provision_profile,
        restore_stripped=args.restore_stripped_symbols,
        lldb_debug=args.lldb_debug,
    )

    # Exit with appropriate code
    exit_map = {
        "SUCCESS": 0,
        "LAUNCH_CRASH": 1,
        "LAUNCH_TIMEOUT": 2,
        "RUNTIME_CRASH": 3,
        "LAUNCH_FAILURE": 4,
        "INSTALL_FAILURE": 5,
        "UNKNOWN": 6,
    }
    sys.exit(exit_map.get(result.status, 6))


if __name__ == "__main__":
    main()
