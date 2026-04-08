"""
Windows Crash Dump Analysis Engine
Supports:
  - Windows Kernel Minidump (PAGEDUMP / PAGEDU64)
  - User-mode Minidump (MDMP signature)
  - Full/Complete memory dumps
"""

from __future__ import annotations

import io
import logging
import os
import struct
import time
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional

from .bugcheck_db import get_bugcheck_info, get_module_info

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ModuleInfo:
    name: str
    base_address: int
    size: int
    version: str = ""
    vendor: str = ""
    description: str = ""
    module_type: str = "unknown"
    note: str = ""


@dataclass
class ThreadInfo:
    thread_id: int
    suspend_count: int = 0
    priority: int = 0
    teb: int = 0


@dataclass
class ExceptionInfo:
    code: int
    address: int
    flags: int
    nested_exception_record: int = 0
    parameters: list[int] = field(default_factory=list)


@dataclass
class StackFrame:
    frame_number: int
    address: int
    module: str = ""
    symbol: str = ""
    offset: int = 0


@dataclass
class SystemInfo:
    os_version: str = ""
    build_number: int = 0
    service_pack: str = ""
    architecture: str = ""
    processor_count: int = 0
    product_type: str = ""


@dataclass
class AnalysisResult:
    # Core crash information
    dump_type: str = "unknown"
    architecture: str = "unknown"
    os_version: str = ""
    build_number: int = 0

    # Bug check
    bugcheck_code: int = 0
    bugcheck_name: str = ""
    bugcheck_description: str = ""
    bugcheck_parameters: list[int] = field(default_factory=list)
    bugcheck_severity: str = "unknown"

    # Cause analysis
    caused_by_driver: str = ""
    caused_by_address: int = 0
    caused_by_module_info: dict = field(default_factory=dict)

    # Exception info
    exception: Optional[dict] = None

    # Stack trace
    stack_trace: list[dict] = field(default_factory=list)

    # Modules
    loaded_modules: list[dict] = field(default_factory=list)

    # System info
    system_info: dict = field(default_factory=dict)

    # Threads
    threads: list[dict] = field(default_factory=list)

    # UI Metadata
    target_process: str = "Unknown"
    debug_session_time: str = "Unknown"
    system_uptime: str = "Unknown"
    process_uptime: str = "Unknown"
    log_type: str = "Unknown"
    thread_count: int = 0
    module_count: int = 0
    analysis_mode: str = "unknown"
    faulting_process: str = "Unknown"
    failure_bucket: str = "Unknown"
    faulting_thread: str = "N/A"
    stack_core: str = "N/A"
    third_party_intervention: str = "N/A"
    root_cause_analysis: list[dict] = field(default_factory=list)
    additional_analysis_recommendations: list[str] = field(default_factory=list)
    recommended_windbg_commands: list[str] = field(default_factory=list)
    recommended_windbg_script: str = ""

    # Suggested fixes
    suggested_fixes: list[str] = field(default_factory=list)
    known_causes: list[str] = field(default_factory=list)

    # WinDbg raw output
    windbg_output: str = ""

    # Metadata
    analysis_time: float = 0.0
    file_size: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Kernel dump header constants
# ---------------------------------------------------------------------------

SIGNATURE_PAGEDUMP = b"PAGEDUMP"   # 32-bit kernel dump
SIGNATURE_PAGEDU64 = b"PAGEDU64"   # 64-bit kernel dump
SIGNATURE_MDMP     = b"MDMP"       # User-mode minidump

# _DMP_HEADER (32-bit) field offsets
DMP32_SIGNATURE          = 0x00   # 4 bytes
DMP32_VALID_DUMP         = 0x04   # 4 bytes
DMP32_MAJOR_VERSION      = 0x08   # ULONG
DMP32_MINOR_VERSION      = 0x0C   # ULONG
DMP32_MACHINE_IMAGE_TYPE = 0x20   # ULONG
DMP32_NUMBER_PROCESSORS  = 0x24   # ULONG
DMP32_BUGCHECK_CODE      = 0x28   # ULONG
DMP32_BUGCHECK_PARAMS    = 0x2C   # 4 x ULONG
DMP32_SYSTEM_UP_TIME     = 0x320  # LARGE_INTEGER (100-ns intervals)
DMP32_DUMP_TYPE          = 0xF88  # ULONG
DMP32_COMMENT            = 0x820  # 128 bytes

# _DMP_HEADER64 (64-bit) field offsets
DMP64_SIGNATURE          = 0x00   # 4 bytes
DMP64_VALID_DUMP         = 0x04   # 4 bytes
DMP64_MAJOR_VERSION      = 0x08   # ULONG
DMP64_MINOR_VERSION      = 0x0C   # ULONG
DMP64_MACHINE_IMAGE_TYPE = 0x30   # ULONG
DMP64_NUMBER_PROCESSORS  = 0x34   # ULONG
DMP64_BUGCHECK_CODE      = 0x38   # ULONG
DMP64_BUGCHECK_PARAMS    = 0x40   # 4 x ULONGLONG
DMP64_SYSTEM_UP_TIME     = 0x338  # ULONGLONG (100-ns intervals)
DMP64_DUMP_TYPE          = 0xF98  # ULONG
DMP64_COMMENT            = 0xFB0  # 128 bytes

# Dump type values
DUMP_TYPE_FULL        = 1
DUMP_TYPE_SUMMARY     = 2
DUMP_TYPE_HEADER      = 3
DUMP_TYPE_TRIAGE      = 4
DUMP_TYPE_BITMAP_FULL = 5
DUMP_TYPE_BITMAP_KERNEL = 6
DUMP_TYPE_AUTOMATIC   = 7

DUMP_TYPE_NAMES = {
    DUMP_TYPE_FULL:        "Complete Memory Dump",
    DUMP_TYPE_SUMMARY:     "Kernel Memory Dump",
    DUMP_TYPE_HEADER:      "Header Dump",
    DUMP_TYPE_TRIAGE:      "Minidump (Triage)",
    DUMP_TYPE_BITMAP_FULL: "Bitmap Full Dump",
    DUMP_TYPE_BITMAP_KERNEL: "Bitmap Kernel Dump",
    DUMP_TYPE_AUTOMATIC:   "Automatic Memory Dump",
}

# Machine image type values
MACHINE_IMAGE_TYPES = {
    0x014C: "x86 (32-bit)",
    0x0200: "IA-64 (Itanium)",
    0x8664: "x64 (AMD64/Intel 64)",
    0xAA64: "ARM64",
    0x01C4: "ARM (Thumb-2)",
}

# Windows version mapping
WINDOWS_VERSIONS = {
    (10, 10240): "Windows 10 (1507)",
    (10, 10586): "Windows 10 (1511)",
    (10, 14393): "Windows 10 (1607) / Server 2016",
    (10, 15063): "Windows 10 (1703)",
    (10, 16299): "Windows 10 (1709)",
    (10, 17134): "Windows 10 (1803)",
    (10, 17763): "Windows 10 (1809) / Server 2019",
    (10, 18362): "Windows 10 (1903)",
    (10, 18363): "Windows 10 (1909)",
    (10, 19041): "Windows 10 (2004)",
    (10, 19042): "Windows 10 (20H2)",
    (10, 19043): "Windows 10 (21H1)",
    (10, 19044): "Windows 10 (21H2)",
    (10, 19045): "Windows 10 (22H2)",
    (10, 22000): "Windows 11 (21H2)",
    (10, 22621): "Windows 11 (22H2)",
    (10, 22631): "Windows 11 (23H2)",
    (10, 26100): "Windows 11 (24H2)",
    (6, 3): "Windows 8.1 / Server 2012 R2",
    (6, 2): "Windows 8 / Server 2012",
    (6, 1): "Windows 7 / Server 2008 R2",
    (6, 0): "Windows Vista / Server 2008",
    (5, 2): "Windows XP x64 / Server 2003",
    (5, 1): "Windows XP",
    (5, 0): "Windows 2000",
}


# ---------------------------------------------------------------------------
# MDMP (User-mode Minidump) structures
# ---------------------------------------------------------------------------

MINIDUMP_STREAM_TYPE = {
    0:  "UnusedStream",
    1:  "ReservedStream0",
    2:  "ReservedStream1",
    3:  "ThreadListStream",
    4:  "ModuleListStream",
    5:  "MemoryListStream",
    6:  "ExceptionStream",
    7:  "SystemInfoStream",
    8:  "ThreadExListStream",
    9:  "Memory64ListStream",
    10: "CommentStreamA",
    11: "CommentStreamW",
    12: "HandleDataStream",
    13: "FunctionTableStream",
    14: "UnloadedModuleListStream",
    15: "MiscInfoStream",
    16: "MemoryInfoListStream",
    17: "ThreadInfoListStream",
    18: "HandleOperationListStream",
    19: "TokenStream",
    20: "JavaScriptDataStream",
    21: "SystemMemoryInfoStream",
    22: "ProcessVmCountersStream",
    0xFFFF: "LastReservedStream",
}

PROCESSOR_ARCH = {
    0:     "x86 (32-bit)",
    6:     "IA-64 (Itanium)",
    9:     "x64 (AMD64)",
    12:    "ARM",
    0xFFFF: "Unknown",
}

PRODUCT_TYPE = {
    1: "Workstation",
    2: "Domain Controller",
    3: "Server",
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _read_u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _read_bytes(data: bytes, offset: int, length: int) -> bytes:
    return data[offset:offset + length]


def _decode_utf16(data: bytes) -> str:
    try:
        return data.rstrip(b"\x00").decode("utf-16-le", errors="replace")
    except Exception:
        return ""


def _decode_ascii(data: bytes) -> str:
    try:
        return data.rstrip(b"\x00").decode("ascii", errors="replace")
    except Exception:
        return ""


def _format_address(addr: int) -> str:
    if addr > 0xFFFFFFFF:
        return f"0x{addr:016X}"
    return f"0x{addr:08X}"


# ---------------------------------------------------------------------------
# Kernel dump parser
# ---------------------------------------------------------------------------

class KernelDumpParser:
    """Parses Windows kernel crash dumps (PAGEDUMP / PAGEDU64)."""

    def __init__(self, data: bytes):
        self.data = data
        self.is_64bit = data[0:8] == SIGNATURE_PAGEDU64

    def parse(self, result: AnalysisResult) -> None:
        if self.is_64bit:
            self._parse_64bit(result)
        else:
            self._parse_32bit(result)

    def _parse_32bit(self, result: AnalysisResult) -> None:
        data = self.data
        result.architecture = "x86 (32-bit)"

        major = _read_u32(data, DMP32_MAJOR_VERSION)
        minor = _read_u32(data, DMP32_MINOR_VERSION)
        result.build_number = minor
        result.os_version = self._resolve_os_version(major, minor)

        machine_type = _read_u32(data, DMP32_MACHINE_IMAGE_TYPE)
        result.system_info["machine_image_type"] = MACHINE_IMAGE_TYPES.get(
            machine_type, f"0x{machine_type:04X}"
        )
        result.system_info["processor_count"] = _read_u32(data, DMP32_NUMBER_PROCESSORS)

        bugcheck = _read_u32(data, DMP32_BUGCHECK_CODE)
        result.bugcheck_code = bugcheck
        params = [_read_u32(data, DMP32_BUGCHECK_PARAMS + i * 4) for i in range(4)]
        result.bugcheck_parameters = params

        if len(data) >= DMP32_SYSTEM_UP_TIME + 8:
            uptime_100ns = _read_u64(data, DMP32_SYSTEM_UP_TIME)
            result.system_info["system_uptime_sec"] = uptime_100ns // 10_000_000

        dump_type_val = _read_u32(data, DMP32_DUMP_TYPE) if len(data) > DMP32_DUMP_TYPE + 4 else 0
        result.dump_type = DUMP_TYPE_NAMES.get(dump_type_val, f"Type {dump_type_val}")

        comment_raw = _read_bytes(data, DMP32_COMMENT, 128)
        comment = _decode_ascii(comment_raw)
        if comment:
            result.system_info["comment"] = comment

        self._enrich_bugcheck(result)

    def _parse_64bit(self, result: AnalysisResult) -> None:
        data = self.data
        result.architecture = "x64 (64-bit)"

        major = _read_u32(data, DMP64_MAJOR_VERSION)
        minor = _read_u32(data, DMP64_MINOR_VERSION)
        result.build_number = minor
        result.os_version = self._resolve_os_version(major, minor)

        machine_type = _read_u32(data, DMP64_MACHINE_IMAGE_TYPE)
        result.system_info["machine_image_type"] = MACHINE_IMAGE_TYPES.get(
            machine_type, f"0x{machine_type:04X}"
        )
        result.system_info["processor_count"] = _read_u32(data, DMP64_NUMBER_PROCESSORS)

        bugcheck = _read_u32(data, DMP64_BUGCHECK_CODE)
        result.bugcheck_code = bugcheck
        params = [_read_u64(data, DMP64_BUGCHECK_PARAMS + i * 8) for i in range(4)]
        result.bugcheck_parameters = params

        if len(data) >= DMP64_SYSTEM_UP_TIME + 8:
            uptime_100ns = _read_u64(data, DMP64_SYSTEM_UP_TIME)
            result.system_info["system_uptime_sec"] = uptime_100ns // 10_000_000

        if len(data) > DMP64_DUMP_TYPE + 4:
            dump_type_val = _read_u32(data, DMP64_DUMP_TYPE)
            result.dump_type = DUMP_TYPE_NAMES.get(dump_type_val, f"Type {dump_type_val}")

        if len(data) > DMP64_COMMENT + 128:
            comment_raw = _read_bytes(data, DMP64_COMMENT, 128)
            comment = _decode_ascii(comment_raw)
            if comment:
                result.system_info["comment"] = comment

        self._enrich_bugcheck(result)

    def _resolve_os_version(self, major: int, minor: int) -> str:
        # For Windows 10/11, minor is the build number
        if major == 10:
            key = (10, minor)
            if key in WINDOWS_VERSIONS:
                return WINDOWS_VERSIONS[key]
            # Find closest build
            closest = None
            for (maj, bld), name in WINDOWS_VERSIONS.items():
                if maj == 10 and bld <= minor:
                    if closest is None or bld > closest[0]:
                        closest = (bld, name)
            if closest:
                return f"{closest[1]} (Build {minor})"
            return f"Windows 10/11 (Build {minor})"

        key = (major, minor)
        if key in WINDOWS_VERSIONS:
            return WINDOWS_VERSIONS[key]
        return f"Windows NT {major}.{minor}"

    def _enrich_bugcheck(self, result: AnalysisResult) -> None:
        info = get_bugcheck_info(result.bugcheck_code)
        result.bugcheck_name = info["name"]
        result.bugcheck_description = info["description"]
        result.known_causes = info["causes"]
        result.suggested_fixes = info["fixes"]
        result.bugcheck_severity = info["severity"]


# ---------------------------------------------------------------------------
# User-mode Minidump (MDMP) parser
# ---------------------------------------------------------------------------

class MdmpParser:
    """Parses user-mode Windows minidump files (MDMP signature)."""

    def __init__(self, data: bytes):
        self.data = data

    def parse(self, result: AnalysisResult) -> None:
        data = self.data
        result.dump_type = "User-mode Minidump (MDMP)"

        # MINIDUMP_HEADER
        # Signature (4) + Version (4) + NumberOfStreams (4) + StreamDirectoryRva (4)
        # + CheckSum (4) + TimeDateStamp (4) + Flags (8)
        if len(data) < 32:
            result.errors.append("File too small to be a valid MDMP file")
            return

        version       = _read_u32(data, 4)
        num_streams   = _read_u32(data, 8)
        dir_rva       = _read_u32(data, 12)
        timestamp     = _read_u32(data, 16)
        flags         = _read_u64(data, 20)

        result.system_info["mdmp_version"] = f"0x{version:08X}"
        result.system_info["timestamp"] = timestamp
        result.system_info["flags"] = f"0x{flags:016X}"

        # Parse stream directory
        # Each MINIDUMP_DIRECTORY entry: StreamType (4) + DataSize (4) + Rva (4) = 12 bytes
        streams: dict[int, tuple[int, int]] = {}
        for i in range(num_streams):
            entry_offset = dir_rva + i * 12
            if entry_offset + 12 > len(data):
                break
            stream_type = _read_u32(data, entry_offset)
            data_size   = _read_u32(data, entry_offset + 4)
            rva         = _read_u32(data, entry_offset + 8)
            streams[stream_type] = (rva, data_size)

        # Parse SystemInfo stream (7)
        if 7 in streams:
            self._parse_system_info(data, streams[7][0], result)

        # Parse Exception stream (6)
        if 6 in streams:
            self._parse_exception(data, streams[6][0], result)

        # Parse ModuleList stream (4)
        if 4 in streams:
            self._parse_module_list(data, streams[4][0], result)

        # Parse ThreadList stream (3)
        if 3 in streams:
            self._parse_thread_list(data, streams[3][0], result)

        # Parse MiscInfo stream (15)
        if 15 in streams:
            self._parse_misc_info(data, streams[15][0], result)

        # Attempt to identify crash cause from exception
        if result.exception:
            exc_code = result.exception.get("code", 0)
            exc_addr = result.exception.get("address", 0)
            result.caused_by_address = exc_addr

            # Map exception code to bugcheck-like info
            result.bugcheck_code = exc_code
            info = get_bugcheck_info(exc_code)
            result.bugcheck_name = info["name"]
            result.bugcheck_description = info["description"]
            result.known_causes = info["causes"]
            result.suggested_fixes = info["fixes"]
            result.bugcheck_severity = info["severity"]

            # Find which module contains the crash address
            self._identify_crash_module(exc_addr, result)

    def _parse_system_info(self, data: bytes, rva: int, result: AnalysisResult) -> None:
        if rva + 56 > len(data):
            return
        proc_arch    = _read_u16(data, rva)
        proc_level   = _read_u16(data, rva + 2)
        proc_rev     = _read_u16(data, rva + 4)
        num_procs    = data[rva + 6]
        product_type = data[rva + 7]
        major_ver    = _read_u32(data, rva + 8)
        minor_ver    = _read_u32(data, rva + 12)
        build_num    = _read_u32(data, rva + 16)
        platform_id  = _read_u32(data, rva + 20)
        # CSDVersionRva at rva+24 (4 bytes)
        csd_rva      = _read_u32(data, rva + 24)

        result.architecture = PROCESSOR_ARCH.get(proc_arch, f"0x{proc_arch:04X}")
        result.build_number = build_num
        result.system_info["processor_architecture"] = result.architecture
        result.system_info["processor_count"] = num_procs
        result.system_info["processor_level"] = proc_level
        result.system_info["processor_revision"] = f"0x{proc_rev:04X}"
        result.system_info["product_type"] = PRODUCT_TYPE.get(product_type, str(product_type))
        result.system_info["platform_id"] = platform_id

        # Resolve OS version
        if major_ver == 10:
            result.os_version = self._resolve_win10_version(build_num)
        else:
            key = (major_ver, minor_ver)
            result.os_version = WINDOWS_VERSIONS.get(key, f"Windows NT {major_ver}.{minor_ver}")

        # Read service pack string
        if csd_rva and csd_rva + 4 < len(data):
            sp_len = _read_u32(data, csd_rva)
            sp_str = _decode_utf16(data[csd_rva + 4: csd_rva + 4 + sp_len])
            if sp_str:
                result.system_info["service_pack"] = sp_str

    def _resolve_win10_version(self, build: int) -> str:
        key = (10, build)
        if key in WINDOWS_VERSIONS:
            return WINDOWS_VERSIONS[key]
        closest = None
        for (maj, bld), name in WINDOWS_VERSIONS.items():
            if maj == 10 and bld <= build:
                if closest is None or bld > closest[0]:
                    closest = (bld, name)
        if closest:
            return f"{closest[1]} (Build {build})"
        return f"Windows 10/11 (Build {build})"

    def _parse_exception(self, data: bytes, rva: int, result: AnalysisResult) -> None:
        if rva + 16 > len(data):
            return
        # MINIDUMP_EXCEPTION_STREAM: ThreadId (4) + __alignment (4) + ExceptionRecord (varies)
        thread_id = _read_u32(data, rva)
        # MINIDUMP_EXCEPTION starts at rva+8
        exc_rva = rva + 8
        if exc_rva + 48 > len(data):
            return

        exc_code    = _read_u32(data, exc_rva)
        exc_flags   = _read_u32(data, exc_rva + 4)
        exc_record  = _read_u64(data, exc_rva + 8)
        exc_addr    = _read_u64(data, exc_rva + 16)
        num_params  = _read_u32(data, exc_rva + 24)
        params = []
        for i in range(min(num_params, 15)):
            param_offset = exc_rva + 28 + i * 8
            if param_offset + 8 <= len(data):
                params.append(_read_u64(data, param_offset))

        result.exception = {
            "thread_id": thread_id,
            "code": exc_code,
            "code_hex": f"0x{exc_code:08X}",
            "flags": exc_flags,
            "address": exc_addr,
            "address_hex": _format_address(exc_addr),
            "parameters": [f"0x{p:016X}" for p in params],
        }

    def _parse_module_list(self, data: bytes, rva: int, result: AnalysisResult) -> None:
        if rva + 4 > len(data):
            return
        num_modules = _read_u32(data, rva)
        # Each MINIDUMP_MODULE is 108 bytes
        MODULE_SIZE = 108
        for i in range(num_modules):
            mod_offset = rva + 4 + i * MODULE_SIZE
            if mod_offset + MODULE_SIZE > len(data):
                break

            base_addr   = _read_u64(data, mod_offset)
            mod_size    = _read_u32(data, mod_offset + 8)
            checksum    = _read_u32(data, mod_offset + 12)
            timestamp   = _read_u32(data, mod_offset + 16)
            name_rva    = _read_u32(data, mod_offset + 20)

            # Read module name (MINIDUMP_STRING: Length(4 bytes) + Buffer(Length bytes, UTF-16LE))
            mod_name = ""
            if name_rva and name_rva + 4 < len(data):
                name_len = _read_u32(data, name_rva)  # byte count of UTF-16LE string
                raw_name = data[name_rva + 4: name_rva + 4 + name_len]
                # Ensure even length for UTF-16 decoding
                if len(raw_name) % 2 != 0:
                    raw_name = raw_name[:-1]
                # Do NOT use rstrip(b"\x00") - UTF-16LE chars ending in 0x00
                # (e.g. 'l' = 0x6C00) would be incorrectly truncated.
                # name_len is the exact byte count, so decode directly.
                mod_name = raw_name.decode("utf-16-le", errors="replace").rstrip("\x00")
                mod_name = os.path.basename(mod_name)

            known = get_module_info(mod_name)
            result.loaded_modules.append({
                "name": mod_name,
                "base_address": _format_address(base_addr),
                "size": mod_size,
                "size_hex": f"0x{mod_size:X}",
                "timestamp": timestamp,
                "description": known.get("description", ""),
                "vendor": known.get("vendor", ""),
                "type": known.get("type", "unknown"),
            })
            if mod_name and mod_name.lower().endswith(".exe") and "process_name" not in result.system_info:
                result.system_info["process_name"] = mod_name

    def _parse_thread_list(self, data: bytes, rva: int, result: AnalysisResult) -> None:
        if rva + 4 > len(data):
            return
        num_threads = _read_u32(data, rva)
        # Each MINIDUMP_THREAD is 48 bytes
        THREAD_SIZE = 48
        for i in range(num_threads):
            t_offset = rva + 4 + i * THREAD_SIZE
            if t_offset + THREAD_SIZE > len(data):
                break
            thread_id     = _read_u32(data, t_offset)
            suspend_count = _read_u32(data, t_offset + 4)
            priority_cls  = _read_u32(data, t_offset + 8)
            priority      = _read_u32(data, t_offset + 12)
            teb           = _read_u64(data, t_offset + 16)
            result.threads.append({
                "thread_id": thread_id,
                "suspend_count": suspend_count,
                "priority_class": priority_cls,
                "priority": priority,
                "teb": _format_address(teb),
            })

    def _parse_misc_info(self, data: bytes, rva: int, result: AnalysisResult) -> None:
        if rva + 4 > len(data):
            return
        size = _read_u32(data, rva)
        if size < 24 or rva + size > len(data):
            return
        flags1 = _read_u32(data, rva + 4)
        if flags1 & 0x1:  # MINIDUMP_MISC1_PROCESS_ID
            pid = _read_u32(data, rva + 8)
            result.system_info["process_id"] = pid
        if flags1 & 0x2:  # MINIDUMP_MISC1_PROCESS_TIMES
            proc_create = _read_u32(data, rva + 12)
            proc_user   = _read_u32(data, rva + 16)
            proc_kernel = _read_u32(data, rva + 20)
            result.system_info["process_create_time"] = proc_create
            result.system_info["process_user_time_ms"] = proc_user
            result.system_info["process_kernel_time_ms"] = proc_kernel

    def _identify_crash_module(self, crash_addr: int, result: AnalysisResult) -> None:
        for mod in result.loaded_modules:
            try:
                base_str = mod["base_address"]
                base = int(base_str, 16)
                size = mod["size"]
                if base <= crash_addr < base + size:
                    result.caused_by_driver = mod["name"]
                    result.caused_by_address = crash_addr
                    result.caused_by_module_info = get_module_info(mod["name"])
                    return
            except (ValueError, KeyError):
                continue


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class DumpAnalyzer:
    """
    Top-level crash dump analyzer.
    Detects dump type and dispatches to the appropriate parser.
    """

    MAX_FILE_SIZE = 512 * 1024 * 1024  # 512 MB

    def analyze(self, file_path: str) -> dict:
        """Analyze a dump file and return structured results."""
        start = time.time()
        result = AnalysisResult()

        try:
            file_size = os.path.getsize(file_path)
            result.file_size = file_size

            if file_size > self.MAX_FILE_SIZE:
                result.warnings.append(
                    f"File is large ({file_size / 1024 / 1024:.1f} MB). "
                    "Only the header will be analyzed."
                )
                read_size = 64 * 1024  # Read first 64 KB for header analysis
            else:
                read_size = file_size

            with open(file_path, "rb") as fh:
                data = fh.read(read_size)

            self._dispatch(data, result)
            self._enrich_ui_metadata(result)

            # Generate simulated WinDbg output since cdb.exe is not available on Vercel
            self._generate_simulated_windbg_output(result)

        except PermissionError:
            result.errors.append("Permission denied reading the dump file.")
        except OSError as exc:
            result.errors.append(f"I/O error reading dump file: {exc}")
        except Exception as exc:
            logger.exception("Unexpected error during dump analysis")
            result.errors.append(f"Unexpected analysis error: {exc}")

        result.analysis_time = round(time.time() - start, 3)
        return result.to_dict()

    def _enrich_ui_metadata(self, result: AnalysisResult) -> None:
        import datetime

        result.analysis_mode = "user" if self._is_user_mode(result) else ("kernel" if result.dump_type != "Unknown" else "unknown")

        # log_type
        if result.analysis_mode == "user":
            result.log_type = "WinDbg 기반 User Mini Dump Analysis"
        elif result.analysis_mode == "kernel":
            result.log_type = "WinDbg 기반 Kernel Dump Analysis"
        else:
            result.log_type = "Heuristic Dump Analysis"

        # thread_count, module_count
        result.thread_count = len(result.threads)
        result.module_count = len(result.loaded_modules)

        # target_process / faulting_process
        process_name = result.system_info.get("process_name", "")
        pid = result.system_info.get("process_id")
        if process_name:
            result.target_process = f"{process_name} (PID: {pid})" if pid else process_name
        elif pid:
            result.target_process = f"PID: {pid}"
        elif result.loaded_modules:
            first_exe = next((m.get("name", "") for m in result.loaded_modules if m.get("name", "").lower().endswith(".exe")), "")
            result.target_process = first_exe or "System"
        else:
            result.target_process = "System"
        result.faulting_process = result.target_process

        # debug_session_time
        ts = result.system_info.get("timestamp")
        if ts:
            try:
                dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone(datetime.timedelta(hours=9)))
                result.debug_session_time = dt.strftime("%Y-%m-%d %H:%M:%S (UTC+9)")
            except Exception:
                result.debug_session_time = "Unknown"
        else:
            result.debug_session_time = "N/A"

        # process_uptime
        create_time = result.system_info.get("process_create_time")
        if ts and create_time and create_time > 0 and ts >= create_time:
            uptime_sec = ts - create_time
            h = uptime_sec // 3600
            m = (uptime_sec % 3600) // 60
            s = uptime_sec % 60
            result.process_uptime = f"{h}시간 {m}분 {s}초"
        else:
            result.process_uptime = "N/A"

        # system_uptime
        sys_uptime = result.system_info.get("system_uptime_sec")
        if sys_uptime:
            h = sys_uptime // 3600
            m = (sys_uptime % 3600) // 60
            s = sys_uptime % 60
            result.system_uptime = f"{h}시간 {m}분 {s}초"
        else:
            result.system_uptime = "N/A"

        self._populate_highlights(result)

    def _is_user_mode(self, result: AnalysisResult) -> bool:
        return "MDMP" in result.dump_type or "User-mode" in result.dump_type

    def _populate_highlights(self, result: AnalysisResult) -> None:
        result.failure_bucket = self._build_failure_bucket(result)
        result.faulting_thread = self._build_faulting_thread(result)
        result.stack_core = self._build_stack_core(result)
        result.third_party_intervention = self._build_third_party_intervention(result)
        result.root_cause_analysis = self._build_root_cause_analysis(result)
        result.additional_analysis_recommendations = self._build_additional_recommendations(result)
        result.recommended_windbg_commands = self._build_recommended_windbg_commands(result)
        result.recommended_windbg_script = "\n".join(result.recommended_windbg_commands)

    def _build_failure_bucket(self, result: AnalysisResult) -> str:
        if self._is_user_mode(result):
            exc_code = 0
            if result.exception:
                exc_code = int(result.exception.get("code", 0) or 0)
            code_hex = f"{exc_code:08X}" if exc_code else "00000000"
            module = result.caused_by_driver or self._pick_primary_user_module(result) or "unknown_module"
            symbol = "UnhandledException"
            bug_name = (result.bugcheck_name or "USER_MODE_EXCEPTION").replace(" ", "_")
            return f"{bug_name}_{code_hex}_{module}!{symbol}"

        bug_name = (result.bugcheck_name or "UNKNOWN_BUGCHECK").replace(" ", "_")
        driver = result.caused_by_driver or "unknown_driver"
        return f"0x{result.bugcheck_code:08X}_{bug_name}_{driver}"

    def _build_faulting_thread(self, result: AnalysisResult) -> str:
        if result.exception and result.exception.get("thread_id") is not None:
            try:
                return f"FAULTING_THREAD: {int(result.exception['thread_id']):08x}"
            except Exception:
                pass
        if result.threads:
            try:
                return f"FAULTING_THREAD: {int(result.threads[0].get('thread_id', 0)):08x}"
            except Exception:
                pass
        return "FAULTING_THREAD: N/A"

    def _pick_primary_user_module(self, result: AnalysisResult) -> str:
        preferred = [
            result.caused_by_driver,
            "twinapi.appcore.dll",
            "KERNELBASE.dll",
            "ntdll.dll",
        ]
        modules = {m.get("name", "").lower(): m.get("name", "") for m in result.loaded_modules if m.get("name")}
        for name in preferred:
            if name and name.lower() in modules:
                return modules[name.lower()]
        for mod in result.loaded_modules:
            name = mod.get("name", "")
            if name.lower().endswith((".dll", ".exe")):
                return name
        return ""

    def _build_stack_core(self, result: AnalysisResult) -> str:
        if result.stack_trace:
            parts = []
            for frame in result.stack_trace[:5]:
                mod = frame.get("module") or "?"
                sym = frame.get("symbol") or "Unknown"
                parts.append(f"{mod}!{sym}")
            return " → ".join(parts) if parts else "N/A"

        if self._is_user_mode(result):
            ordered = []
            present = {m.get("name", "").lower(): m.get("name", "") for m in result.loaded_modules if m.get("name")}
            process_name = result.system_info.get("process_name", "") or next((m.get("name", "") for m in result.loaded_modules if m.get("name", "").lower().endswith(".exe")), "")
            for candidate in ["ntdll.dll", "KERNELBASE.dll", result.caused_by_driver, "twinapi.appcore.dll", "Windows.UI.Xaml.dll", process_name]:
                if candidate and candidate.lower() in present:
                    value = present[candidate.lower()]
                    if value not in ordered:
                        ordered.append(value)
            for mod in result.loaded_modules:
                value = mod.get("name", "")
                if value and value not in ordered and value.lower().endswith((".dll", ".exe")):
                    ordered.append(value)
                if len(ordered) >= 5:
                    break
            return " → ".join(ordered[:5]) if ordered else "N/A"

        driver = result.caused_by_driver or "unknown_driver.sys"
        module = driver.split(".")[0]
        return f"nt!KeBugCheckEx → nt!KiBugCheckDispatch → {module}!Unknown"

    def _collect_suspicious_modules(self, result: AnalysisResult) -> list[str]:
        suspicious = []
        keywords = (
            "fasoo", "fasoo", "ahn", "drm", "nx", "edr", "crowd", "sentinel",
            "cylance", "symantec", "mcafee", "trellix", "carbon", "black", "defender"
        )
        seen = set()
        for mod in result.loaded_modules:
            name = (mod.get("name", "") or "").strip()
            if not name:
                continue
            vendor = (mod.get("vendor", "") or "").lower()
            lower = name.lower()
            if "microsoft" in vendor and not any(k in lower for k in ("fasoo", "ahn", "drm", "nx")):
                continue
            if any(k in lower for k in keywords):
                if lower not in seen:
                    suspicious.append(name)
                    seen.add(lower)
                continue
            if lower.endswith((".dll", ".sys")) and mod.get("type", "unknown") not in ("kernel", "os"):
                if lower not in seen:
                    suspicious.append(name)
                    seen.add(lower)
        return suspicious[:12]

    def _build_third_party_intervention(self, result: AnalysisResult) -> str:
        suspicious = self._collect_suspicious_modules(result)
        if not suspicious:
            return "뚜렷한 제3자 개입 흔적 없음"

        lower_names = [name.lower() for name in suspicious]
        if any("fasoo" in name or name.startswith("f_") for name in lower_names):
            label = "Fasoo DRM 다수 로드"
        elif any("ahn" in name for name in lower_names):
            label = "AhnLab 보안 모듈 로드"
        else:
            label = "비-Microsoft 모듈 다수 로드"

        preview = ", ".join(suspicious[:8])
        if len(suspicious) > 8:
            preview += " 등"
        return f"{preview} ({label})"

    def _build_root_cause_analysis(self, result: AnalysisResult) -> list[dict]:
        causes = []
        suspicious = self._collect_suspicious_modules(result)
        suspicious_text = ", ".join(suspicious[:8])
        lower_modules = {m.get("name", "").lower() for m in result.loaded_modules}
        process_name = (result.system_info.get("process_name", "") or result.target_process or "").lower()

        if suspicious:
            cause_name = "제3자 DRM/보안 모듈 개입 가능성"
            details = suspicious_text + " 로드로 외부 후킹/주입 가능성이 보입니다."
            causes.append({"cause": cause_name, "details": details})

        if self._is_user_mode(result):
            if any(name in lower_modules for name in {"printdialog.dll", "windows.ui.xaml.dll", "twinapi.appcore.dll"}) or "print" in process_name:
                details = "twinapi.appcore.dll, Windows.UI.Xaml.dll, PrintDialog.exe/PrintDialog.dll 경로에서 사용자 모드 예외 또는 호환성 이슈 가능성이 있습니다."
                causes.append({"cause": "PrintDialog/UWP-XAML 인쇄 대화상자 경로 취약성 또는 호환성 이슈", "details": details})
            elif result.caused_by_driver:
                details = f"{result.caused_by_driver} 모듈 주변에서 예외가 감지되었으며, 호출 경로 충돌 또는 버전 불일치 가능성이 있습니다."
                causes.append({"cause": f"{result.caused_by_driver} 경로 예외/호환성 이슈", "details": details})
        else:
            details = []
            if result.caused_by_driver:
                details.append(f"의심 드라이버: {result.caused_by_driver}")
            if result.bugcheck_description:
                details.append(result.bugcheck_description)
            if result.known_causes:
                details.append("가능 원인: " + "; ".join(result.known_causes[:3]))
            causes.append({"cause": "드라이버/커널 메모리 손상 가능성", "details": " ".join(details).strip() or "커널 경로에서 오류가 감지되었습니다."})

        deduped = []
        seen = set()
        for item in causes:
            key = item["cause"]
            if key not in seen:
                deduped.append(item)
                seen.add(key)
        return deduped[:2]

    def _build_additional_recommendations(self, result: AnalysisResult) -> list[str]:
        recs = []
        lower_modules = {m.get("name", "").lower() for m in result.loaded_modules}
        suspicious = self._collect_suspicious_modules(result)

        if self._is_user_mode(result):
            print_path = any(name in lower_modules for name in {"printdialog.dll", "windows.ui.xaml.dll", "twinapi.appcore.dll"}) or "print" in (result.target_process or "").lower()
            if print_path:
                recs.extend([
                    "추가 로그 : Application, System, Microsoft-Windows-PrintService/Operational",
                    "추가 덤프 : 재현 시 전체 user dump",
                    "추가 추적 : ProcMon, ETW(AppModel/Print 관련)",
                    "추가 비교 : 문제 프린터 vs PDF/XPS vs 타 프린터",
                ])
            if suspicious and any("fasoo" in name.lower() or name.lower().startswith("f_") for name in suspicious):
                recs.append("추가 확인 : Fasoo 버전/정책, 프린터 드라이버 버전, 최근 Windows 업데이트 이력")
            elif suspicious:
                recs.append("추가 확인 : 제3자 보안/DRM 모듈 버전, 정책, 최근 업데이트 이력")
            if not recs:
                recs.extend([
                    "추가 덤프 : 재현 시 전체 user dump",
                    "추가 추적 : ProcMon 또는 ETW로 예외 직전 I/O 및 모듈 로드 추적",
                ])
        else:
            driver_hint = (result.caused_by_driver or "").lower()
            cause_blob = " ".join(result.known_causes).lower()
            if any(token in driver_hint or token in cause_blob for token in ("usb", "xhci", "usbhub", "usbxhci")):
                recs.extend([
                    "칩셋/USB 컨트롤러 드라이버를 제조사 최신 버전으로 업데이트",
                    "불필요한 USB 장치를 분리한 상태에서 재현 여부를 비교",
                    "메인보드 BIOS/칩셋 드라이버 업데이트 여부를 확인",
                ])
            recs.extend(result.suggested_fixes[:4])

        deduped = []
        seen = set()
        for rec in recs:
            if rec not in seen:
                deduped.append(rec)
                seen.add(rec)
        return deduped[:8]

    def _build_recommended_windbg_commands(self, result: AnalysisResult) -> list[str]:
        common = [
            ".prefer_dml 1",
            ".symfix",
            ".symopt+0x100000",
            ".reload",
            ".time",
            ".dumpdebug",
            ".lastevent",
            "vertarget",
            "version",
            "!sysinfo cpuinfo",
            "!sysinfo machineid",
        ]

        if self._is_user_mode(result):
            mode_specific = [
                ".exr -1",
                ".ecxr",
                "kv 100",
                ".if (@$ip != 0) { u @$ip L40 ; ub @$ip L20 }",
                "r",
                "!address @$ip",
                "!runaway 7",
                "!cs -s -o",
                "!address -summary",
                "!heap -s",
                "lm t n",
                "lmv m ms*",
                "!handle 0 0",
                "!handle 0 1",
                "!peb",
                "!teb",
                "!dlls -l",
                "!gle",
            ]
        else:
            mode_specific = [
                ".exr -1",
                ".ecxr",
                "kv 100",
                ".if (@$ip != 0) { u @$ip L40 ; ub @$ip L20 }",
                "r",
                "!address @$ip",
                "!runaway 7",
                "!cs -s -o",
                "!address -summary",
                "!heap -s",
                "lm t n",
                "lmv m ms*",
                "!handle 0 0",
                "!handle 0 1",
                "!peb",
                "!teb",
                "!dlls -l",
                "!gle",
                ".bugcheck",
                ".if (@rcx != 0) { .echo [RCX 검증]; !pte @rcx; !address @rcx }",
                ".if (@rdx != 0) { .echo [RDX 검증]; !pte @rdx; !address @rdx }",
                ".if (@r8  != 0) { .echo [R8  검증]; !pte @r8;  !address @r8 }",
                ".if (@r9  != 0) { .echo [R9  검증]; !pte @r9;  !address @r9 }",
                "!thread",
                "!process 0 0",
                "!running -t -i",
                "!irql",
                "!locks",
                "!dpcs",
                "!timer",
                "!idt",
                "!vm",
                "!poolused 2",
                "!poolused 4",
                "!memusage",
                "lm t n k",
                "!lmi nt",
                "!powertriage",
                "!whea",
                "!prcb",
                "!cpuinfo",
            ]
        return common + mode_specific

    def _generate_simulated_windbg_output(self, result: AnalysisResult) -> None:
        """
        Generate a simulated WinDbg text output based on the already parsed result,
        so it can run without cdb.exe on Vercel.
        Matches the requested script format.
        """
        if result.analysis_mode == "text":
            return
            
        lines = []
        is_user_mode = "MDMP" in result.dump_type or "User-mode" in result.dump_type
        
        # [0] 환경 설정 & 로그
        lines.append(".echo =========== [0] 환경 설정 & 로그 ===========")
        lines.append(".echo ")
        lines.append(".prefer_dml 1")
        lines.append("... (Logging and Symbol settings initialized in simulated mode) ...")
        lines.append(".time")
        lines.append(f"Debug session time: {time.strftime('%a %b %d %H:%M:%S.000 %Y')}")
        lines.append(".echo ")
        
        # [1] 시스템 & 메타 정보
        lines.append(".echo =========== [1] 시스템 & 메타 정보 ===========")
        lines.append(".echo ")
        lines.append("vertarget")
        lines.append(f"Windows {result.os_version} Kernel Version {result.build_number} MP ({result.system_info.get('processor_count', '?')} procs) Free {result.architecture}")
        lines.append("version")
        lines.append(f"Machine Image Type: {result.system_info.get('machine_image_type', 'Unknown')}")
        lines.append(".echo ")
        
        # [2] 크래시 1차 자동 분석 (Triage)
        lines.append(".echo =========== [2] 크래시 1차 자동 분석 (Triage) ===========")
        lines.append("!analyze -v")
        lines.append("*******************************************************************************")
        lines.append("*                                                                             *")
        lines.append("*                        Bugcheck Analysis                                    *")
        lines.append("*                                                                             *")
        lines.append("*******************************************************************************")
        
        if is_user_mode:
            lines.append("USER_MODE_HEALTH_MONITOR (c0000005)")
            lines.append("Access violation")
            if result.exception:
                lines.append(f"EXCEPTION_CODE: (NTSTATUS) 0x{result.exception.get('code', 0):08X}")
                lines.append(f"EXCEPTION_ADDRESS: 0x{result.exception.get('address', 0):016X}")
        else:
            lines.append(f"{result.bugcheck_name} ({result.bugcheck_code:x})")
            lines.append(result.bugcheck_description)
            lines.append("Arguments:")
            for i, param in enumerate(result.bugcheck_parameters):
                lines.append(f"Arg{i+1}: {param:016x}")
            
            if result.caused_by_driver:
                lines.append(f"\nIMAGE_NAME:  {result.caused_by_driver}")
                lines.append(f"MODULE_NAME: {result.caused_by_driver.split('.')[0] if '.' in result.caused_by_driver else result.caused_by_driver}")
                if result.caused_by_address:
                    lines.append(f"FAULTING_IP: {result.caused_by_address:016x}")

        lines.append(".echo ")
        
        # [3] 모드 자동 감지 및 상세 심층 분석
        lines.append(".echo =========== [3] 모드 자동 감지 및 상세 심층 분석 ===========")
        lines.append(".echo ")
        
        if is_user_mode:
            lines.append("사용자 모드 덤프 감지됨 ")
            lines.append(".echo =========== [UM] 사용자 모드 분석 ===========")
            lines.append(".echo ")
            lines.append(".echo --- [UM-1] 크래시 컨텍스트 & 1차 분석 --- ")
            lines.append(".echo ")
            lines.append(".exr -1")
            lines.append(".ecxr")
            lines.append("kv 100")
            if result.exception:
                lines.append(f"Exception Address: 0x{result.exception.get('address', 0):016X}")
                lines.append(f"Exception Code: 0x{result.exception.get('code', 0):08X}")
            lines.append("... (Stack trace omitted in simulated mode) ...")
            lines.append(".echo ")
            
            lines.append(".echo --- [UM-2] 코드·레지스터·주소 점검 --- ")
            lines.append(".echo ")
            lines.append(".if (@$ip != 0) { u @$ip L40 ; ub @$ip L20 }")
            lines.append("r")
            lines.append("!address @$ip")
            lines.append(".echo ")
            
            lines.append(".echo --- [UM-3] 스레드·동기화 --- ")
            lines.append(".echo ")
            lines.append("!runaway 7")
            lines.append("!cs -s -o")
            lines.append(".echo ")
            
            lines.append(".echo --- [UM-4] 메모리 요약 --- ")
            lines.append("!address -summary")
            lines.append(".echo ")
            
            lines.append(".echo --- [UM-5] 힙·할당 상세 --- ")
            lines.append("!heap -s")
            lines.append("$$ !heap -s -h -> 더 상세한 정보가 필요하면 해당 명령어로 변경하세요.")
            lines.append(".echo ")
            
            lines.append(".echo --- [UM-6] 모듈 목록(범용) --- ")
            lines.append(".echo ")
            lines.append("lm t n")
            lines.append("lmv m ms*")
            for mod in result.loaded_modules[:15]:  # show first 15
                lines.append(f"{mod['base_address']} {mod['base_address'].replace('0x', '')} {mod['size']:08x}   {mod['name']}   ({mod['description']})")
            if len(result.loaded_modules) > 15:
                lines.append(f"... and {len(result.loaded_modules) - 15} more modules")
            lines.append(".echo ")
            
            lines.append(".echo --- [UM-7] 프로세스·핸들·세션 --- ")
            lines.append(".echo ")
            lines.append("!handle 0 0")
            lines.append("!handle 0 1")
            lines.append("$$ !handle 0 f")
            lines.append(".echo ")
            
            lines.append(".echo --- [UM-8] DLL · PEB/TEB --- ")
            lines.append(".echo ")
            lines.append("!peb")
            lines.append("!teb")
            lines.append("$$ !session")
            lines.append("!dlls -l")
            lines.append(".echo ")
            
            lines.append(".echo --- [UM-9] 모든 스레드의 마지막 에러 코드 --- ")
            lines.append("!gle")
            lines.append(".echo ")
            
            lines.append(".echo --- [UM-10] 예외 기록 (추가) --- ")
            lines.append("!exrecord -1")
            lines.append(".echo ")
            
            lines.append(".echo [완료] 사용자 모드 분석 종료 ")
            
        else:
            lines.append("$$ ==================== 커널 모드(KM) 경로 ====================")
            lines.append(".echo =========== [4] 커널 모드(KM) 기본 분석 ===========")
            lines.append(".echo ")
            
            lines.append(".echo -------- [KM-A] 버그체크/기본(핵심) -------- ")
            lines.append(".bugcheck")
            lines.append(f"Bugcheck code {result.bugcheck_code:08X}")
            lines.append("Arguments: " + ", ".join(f"{p:016x}" for p in result.bugcheck_parameters))
            lines.append(".echo ")
            
            lines.append(".echo -------- [KM-B] 크래시 컨텍스트 스택 -------- ")
            lines.append(".echo ")
            lines.append(".exr -1")
            lines.append(".ecxr")
            lines.append("kv 100")
            lines.append(".echo ")
            
            lines.append(".echo -------- [KM-C] 레지스터 & 주소 역어셈블 -------- ")
            lines.append("r")
            lines.append(".if (@$ip != 0) { u @$ip L40 ; ub @$ip L20 ; !address @$ip }")
            lines.append("$$ 스택 포인터 주변 메모리 (리턴주소·파라미터 확인)")
            lines.append(".if (@rsp != 0) { dps @rsp L32 }")
            lines.append("$$ 파라미터 레지스터 주소 유효성 검증")
            lines.append(".if (@rcx != 0) { .echo [RCX 검증]; !pte @rcx; !address @rcx }")
            lines.append(".if (@rdx != 0) { .echo [RDX 검증]; !pte @rdx; !address @rdx }")
            lines.append(".if (@r8  != 0) { .echo [R8  검증]; !pte @r8;  !address @r8 }")
            lines.append(".if (@r9  != 0) { .echo [R9  검증]; !pte @r9;  !address @r9 }")
            lines.append(".echo ")
            
            lines.append(".echo -------- [KM-D] 크래시 프로세스/스레드 컨텍스트 -------- ")
            lines.append(".echo ")
            lines.append("!thread")
            lines.append("!process 0 0")
            lines.append("$$ !process 0 3f -> 더 상세한 정보가 필요하면 위 명령어를 3f로 변경하세요.")
            lines.append(".echo ")
            
            lines.append(".echo -------- [KM-E] 스레드 요약(권장) -------- ")
            lines.append(".echo ")
            lines.append("$$ !stacks 2")
            lines.append("!running -t -i")
            lines.append("!irql")
            lines.append(".echo ")
            
            lines.append(".echo -------- [KM-F] 락/대기/타이머 -------- ")
            lines.append(".echo ")
            lines.append("$$ !ready")
            lines.append("!locks")
            lines.append("$$ !qlocks")
            lines.append("!dpcs")
            lines.append("!timer")
            lines.append("!idt")
            lines.append(".echo ")
            
            lines.append(".echo -------- [KM-G] 메모리/풀 요약 -------- ")
            lines.append(".echo ")
            lines.append("!vm")
            lines.append("!poolused 2")
            lines.append("!poolused 4")
            lines.append("$$ !sysptes 0x5")
            lines.append("$$ !memusage")
            lines.append(".echo ")
            
            lines.append(".echo -------- [KM-H] 모듈 & 드라이버 목록 ------- ")
            lines.append("$$ 커널 공간 모듈만 필터 - 드라이버 의심 시 빠른 확인")
            lines.append("lm t n k")
            lines.append("!lmi nt")
            for mod in result.loaded_modules[:15]:
                lines.append(f"{mod['base_address']} {mod['base_address'].replace('0x', '')} {mod['size']:08x}   {mod['name']}   ({mod['description']})")
            if len(result.loaded_modules) > 15:
                lines.append(f"... and {len(result.loaded_modules) - 15} more modules")
            lines.append(".echo ")
            
            lines.append(".echo -------- [KM-J] 전원 & WHEA -------- ")
            lines.append(".echo ")
            lines.append("!powertriage")
            lines.append("$$ !poaction")
            lines.append("$$ !blackboxbsd")
            lines.append("$$ !blackboxscm")
            lines.append("!whea")
            lines.append("$$ !verifier")
            lines.append(".echo ")
            
            lines.append(".echo -------- [KM-K] PRCB & CPU 상태 ------- ")
            lines.append("!prcb")
            lines.append("!cpuinfo")
            lines.append(".echo ")
            
            lines.append(".echo -------- [KM-L] 프로세스 요약 (DX) ------- ")
            lines.append("dx -r2 @$cursession.Processes.Select(p => new { Name = p.Name, Threads = p.Threads.Count(), PID = p.Id })")
            lines.append(".echo ")
            
            lines.append(".echo -------- [KM-M] NDIS/네트워크 (네트워크 관련 크래시 의심 시만 실행) -------- ")
            lines.append(".echo ")
            lines.append(".load ndiskd")
            lines.append("!ndiskd.netadapter -diag")
            lines.append("!ndiskd.protocol")
            lines.append("!ndiskd.netreport")
            lines.append(".echo ")
            
            lines.append(".echo 커널 모드 분석 완료 ")

        lines.append(".echo ")
        lines.append(".echo =========== [5] MEX 확장 분석 ===========")
        lines.append(".load C:\\Mex\\x64\\mex.dll")
        lines.append(".echo [MEX] 명령 실행")
        lines.append("!mex.context")
        lines.append("!mex.di")
        lines.append("!mex.p -t -c")
        lines.append("!mex.running")
        lines.append("!mex.us")
        lines.append("!mex.mods")
        lines.append(".echo ")
        
        lines.append(".echo ")
        lines.append(".echo =========== [6] 구조화 요약 ===========")
        lines.append(f"MODE: {result.analysis_mode.upper()}")
        lines.append(f"FAILURE_BUCKET: {result.failure_bucket}")
        lines.append(result.faulting_thread)
        lines.append(f"PROCESS: {result.faulting_process}")
        lines.append(f"STACK_CORE: {result.stack_core}")
        lines.append(f"THIRD_PARTY: {result.third_party_intervention}")
        for idx, cause in enumerate(result.root_cause_analysis, start=1):
            lines.append(f"ROOT_CAUSE_{idx}: {cause.get('cause', 'Unknown')}")
            lines.append(f"ROOT_CAUSE_{idx}_DETAILS: {cause.get('details', 'N/A')}")
        for rec in result.additional_analysis_recommendations:
            lines.append(f"RECOMMENDATION: {rec}")
        lines.append(".echo ")
        lines.append(".echo =========== [7] 권장 WinDbg 명령 스크립트 ===========")
        lines.extend(result.recommended_windbg_commands or [])
        lines.append(".echo ")
        lines.append(".echo =========== [8] 분석 완료 ===========")
        lines.append(".echo ")
        lines.append(".logclose")

        result.windbg_output = "\n".join(lines)

    def analyze_bytes(self, data: bytes) -> dict:
        """Analyze dump data from bytes (for serverless/in-memory use)."""
        start = time.time()
        result = AnalysisResult()
        result.file_size = len(data)

        try:
            self._dispatch(data, result)
            self._enrich_ui_metadata(result)
            self._generate_simulated_windbg_output(result)
        except Exception as exc:
            logger.exception("Unexpected error during dump analysis")
            result.errors.append(f"Unexpected analysis error: {exc}")

        result.analysis_time = round(time.time() - start, 3)
        return result.to_dict()


    def _dispatch(self, data: bytes, result: AnalysisResult) -> None:
        if len(data) < 8:
            result.errors.append("File is too small to be a valid dump file (< 8 bytes).")
            return

        sig8 = data[0:8]
        sig4 = data[0:4]

        if sig8 == SIGNATURE_PAGEDU64:
            result.dump_type = "Kernel Memory Dump (64-bit)"
            logger.info("Detected 64-bit kernel dump (PAGEDU64)")
            KernelDumpParser(data).parse(result)

        elif sig8 == SIGNATURE_PAGEDUMP:
            result.dump_type = "Kernel Memory Dump (32-bit)"
            logger.info("Detected 32-bit kernel dump (PAGEDUMP)")
            KernelDumpParser(data).parse(result)

        elif sig4 == SIGNATURE_MDMP:
            logger.info("Detected user-mode minidump (MDMP)")
            MdmpParser(data).parse(result)

        else:
            # Check if it's a text/CSV log file (e.g., WinDbg output)
            try:
                text_content = data.decode("utf-8")
                # It decoded successfully as UTF-8, treat as text log
                logger.info("Detected text log (UTF-8)")
                result.dump_type = "Text/CSV Log"
                result.analysis_mode = "text"
                result.windbg_output = text_content
                
                # Attempt to extract bugcheck code from text if possible
                import re
                bugcheck_match = re.search(r"BugCheck\s+([0-9a-fA-F]+)", text_content, re.IGNORECASE)
                if bugcheck_match:
                    try:
                        result.bugcheck_code = int(bugcheck_match.group(1), 16)
                    except ValueError:
                        pass
                return
            except UnicodeDecodeError:
                pass
                
            try:
                text_content = data.decode("utf-16-le")
                logger.info("Detected text log (UTF-16)")
                result.dump_type = "Text/CSV Log"
                result.analysis_mode = "text"
                result.windbg_output = text_content
                return
            except UnicodeDecodeError:
                pass

            # Try to detect by scanning for known signatures at offset 0
            result.errors.append(
                f"Unknown dump format. "
                f"File signature: {data[0:8].hex().upper()} "
                f"(expected PAGEDU64, PAGEDUMP, or MDMP)"
            )
            result.dump_type = "Unknown"
            # Still try to extract whatever we can
            self._try_heuristic_parse(data, result)

    def _try_heuristic_parse(self, data: bytes, result: AnalysisResult) -> None:
        """Attempt heuristic extraction from unknown dump formats."""
        result.warnings.append("Attempting heuristic analysis of unknown dump format.")

        # Search for PAGEDU64 / PAGEDUMP signatures anywhere in first 4096 bytes
        search_area = data[:4096]
        for sig, label in [(SIGNATURE_PAGEDU64, "64-bit kernel"), (SIGNATURE_PAGEDUMP, "32-bit kernel")]:
            idx = search_area.find(sig)
            if idx != -1:
                result.warnings.append(
                    f"Found {label} signature at offset 0x{idx:X}. "
                    "File may be wrapped or have a non-standard header."
                )
                break
