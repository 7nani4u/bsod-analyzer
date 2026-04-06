"""
Unit tests for the BSOD Analyzer engine.
Run with: python3 -m pytest tests/test_analyzer.py -v
"""

import os
import sys
import struct
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.dump_analyzer import DumpAnalyzer, KernelDumpParser, MdmpParser, AnalysisResult
from engine.bugcheck_db import get_bugcheck_info, get_module_info, BUGCHECK_CODES


# ── Bugcheck DB Tests ──────────────────────────────────────────────────────

class TestBugcheckDB:
    def test_known_code_irql(self):
        info = get_bugcheck_info(0x0000000A)
        assert info["name"] == "IRQL_NOT_LESS_OR_EQUAL"
        assert "severity" in info
        assert len(info["fixes"]) > 0
        assert len(info["causes"]) > 0

    def test_known_code_page_fault(self):
        info = get_bugcheck_info(0x00000050)
        assert info["name"] == "PAGE_FAULT_IN_NONPAGED_AREA"

    def test_known_code_memory_management(self):
        info = get_bugcheck_info(0x0000001A)
        assert info["name"] == "MEMORY_MANAGEMENT"

    def test_unknown_code_returns_fallback(self):
        info = get_bugcheck_info(0xDEADBEEF)
        assert "UNKNOWN" in info["name"].upper() or "0xDEADBEEF" in info["name"].upper()
        assert len(info["fixes"]) > 0

    def test_all_known_codes_have_required_fields(self):
        for code, info in BUGCHECK_CODES.items():
            assert "name" in info, f"Missing 'name' for code 0x{code:08X}"
            assert "description" in info, f"Missing 'description' for code 0x{code:08X}"
            assert "causes" in info, f"Missing 'causes' for code 0x{code:08X}"
            assert "fixes" in info, f"Missing 'fixes' for code 0x{code:08X}"
            assert "severity" in info, f"Missing 'severity' for code 0x{code:08X}"


class TestModuleDB:
    def test_known_module_ntoskrnl(self):
        info = get_module_info("ntoskrnl.exe")
        assert info["type"] == "kernel"
        assert "Microsoft" in info["vendor"]

    def test_known_module_nvidia(self):
        info = get_module_info("nvlddmkm.sys")
        assert info["type"] == "graphics"
        assert "NVIDIA" in info["vendor"]

    def test_unknown_module_returns_fallback(self):
        info = get_module_info("totally_unknown_driver.sys")
        assert "unknown" in info["type"].lower() or "Unknown" in info["description"]


# ── Kernel Dump Parser Tests ───────────────────────────────────────────────

def make_kernel64_header(
    bugcheck_code: int = 0x0000000A,
    bugcheck_params: list = None,
    major: int = 10,
    minor: int = 22621,
    machine_type: int = 0x8664,
    num_procs: int = 8,
    dump_type: int = 4,
) -> bytes:
    """Create a minimal 64-bit kernel dump header for testing."""
    if bugcheck_params is None:
        bugcheck_params = [0x1234, 0x2, 0x1, 0xFFFF]

    header = bytearray(8192)
    header[0x00:0x08] = b"PAGEDU64"
    struct.pack_into("<I", header, 0x08, major)
    struct.pack_into("<I", header, 0x0C, minor)
    struct.pack_into("<I", header, 0x30, machine_type)
    struct.pack_into("<I", header, 0x34, num_procs)
    struct.pack_into("<I", header, 0x38, bugcheck_code)
    for i, p in enumerate(bugcheck_params[:4]):
        struct.pack_into("<Q", header, 0x40 + i * 8, p)
    struct.pack_into("<I", header, 0xF98, dump_type)
    return bytes(header)


def make_kernel32_header(
    bugcheck_code: int = 0x00000050,
    bugcheck_params: list = None,
    major: int = 10,
    minor: int = 19045,
) -> bytes:
    """Create a minimal 32-bit kernel dump header for testing."""
    if bugcheck_params is None:
        bugcheck_params = [0x1234, 0x0, 0x0, 0x0]

    header = bytearray(4096)
    header[0x00:0x08] = b"PAGEDUMP"
    struct.pack_into("<I", header, 0x08, major)
    struct.pack_into("<I", header, 0x0C, minor)
    struct.pack_into("<I", header, 0x20, 0x014C)
    struct.pack_into("<I", header, 0x24, 4)
    struct.pack_into("<I", header, 0x28, bugcheck_code)
    for i, p in enumerate(bugcheck_params[:4]):
        struct.pack_into("<I", header, 0x2C + i * 4, p & 0xFFFFFFFF)
    struct.pack_into("<I", header, 0xF88, 4)
    return bytes(header)


class TestKernelDumpParser64:
    def test_detects_64bit_signature(self):
        data = make_kernel64_header()
        result = AnalysisResult()
        KernelDumpParser(data).parse(result)
        assert result.architecture == "x64 (64-bit)"

    def test_extracts_bugcheck_code(self):
        data = make_kernel64_header(bugcheck_code=0x0000000A)
        result = AnalysisResult()
        KernelDumpParser(data).parse(result)
        assert result.bugcheck_code == 0x0000000A
        assert result.bugcheck_name == "IRQL_NOT_LESS_OR_EQUAL"

    def test_extracts_bugcheck_params(self):
        params = [0xAABBCCDD, 0x2, 0x1, 0xDEADBEEF]
        data = make_kernel64_header(bugcheck_params=params)
        result = AnalysisResult()
        KernelDumpParser(data).parse(result)
        assert result.bugcheck_parameters[0] == 0xAABBCCDD
        assert result.bugcheck_parameters[1] == 0x2

    def test_extracts_os_version_win11(self):
        data = make_kernel64_header(major=10, minor=22621)
        result = AnalysisResult()
        KernelDumpParser(data).parse(result)
        assert "22621" in result.os_version or "22H2" in result.os_version

    def test_extracts_processor_count(self):
        data = make_kernel64_header(num_procs=16)
        result = AnalysisResult()
        KernelDumpParser(data).parse(result)
        assert result.system_info.get("processor_count") == 16

    def test_populates_suggested_fixes(self):
        data = make_kernel64_header(bugcheck_code=0x00000050)
        result = AnalysisResult()
        KernelDumpParser(data).parse(result)
        assert len(result.suggested_fixes) > 0

    def test_populates_known_causes(self):
        data = make_kernel64_header(bugcheck_code=0x0000009F)
        result = AnalysisResult()
        KernelDumpParser(data).parse(result)
        assert len(result.known_causes) > 0

    def test_dump_type_name(self):
        data = make_kernel64_header(dump_type=4)
        result = AnalysisResult()
        KernelDumpParser(data).parse(result)
        assert "Minidump" in result.dump_type or "Triage" in result.dump_type


class TestKernelDumpParser32:
    def test_detects_32bit_signature(self):
        data = make_kernel32_header()
        result = AnalysisResult()
        KernelDumpParser(data).parse(result)
        assert result.architecture == "x86 (32-bit)"

    def test_extracts_bugcheck_code_32(self):
        data = make_kernel32_header(bugcheck_code=0x0000001A)
        result = AnalysisResult()
        KernelDumpParser(data).parse(result)
        assert result.bugcheck_code == 0x0000001A
        assert result.bugcheck_name == "MEMORY_MANAGEMENT"


# ── MDMP Parser Tests ──────────────────────────────────────────────────────

def make_mdmp_dump(
    exception_code: int = 0xC0000005,
    exception_addr: int = 0x00007FF812345678,
) -> bytes:
    """Create a minimal MDMP file for testing."""
    NUM_STREAMS = 2
    HEADER_SIZE = 32
    DIR_SIZE    = NUM_STREAMS * 12

    # SystemInfo stream
    sysinfo_data = bytearray(48)
    struct.pack_into("<H", sysinfo_data, 0,  9)      # AMD64
    sysinfo_data[6] = 4                               # 4 processors
    sysinfo_data[7] = 1                               # Workstation
    struct.pack_into("<I", sysinfo_data, 8,  10)
    struct.pack_into("<I", sysinfo_data, 12, 0)
    struct.pack_into("<I", sysinfo_data, 16, 22621)
    struct.pack_into("<I", sysinfo_data, 20, 2)

    # Exception stream
    exc_stream = bytearray(8 + 152)
    struct.pack_into("<I", exc_stream, 0, 0x1234)
    struct.pack_into("<I", exc_stream, 8,  exception_code)
    struct.pack_into("<Q", exc_stream, 24, exception_addr)
    struct.pack_into("<I", exc_stream, 32, 0)

    sysinfo_rva = HEADER_SIZE + DIR_SIZE
    exc_rva     = sysinfo_rva + len(sysinfo_data)

    header = bytearray(HEADER_SIZE)
    header[0:4] = b"MDMP"
    struct.pack_into("<I", header, 4,  0x0000A793)
    struct.pack_into("<I", header, 8,  NUM_STREAMS)
    struct.pack_into("<I", header, 12, HEADER_SIZE)

    dir_data = bytearray(DIR_SIZE)
    struct.pack_into("<I", dir_data, 0,  7)
    struct.pack_into("<I", dir_data, 4,  len(sysinfo_data))
    struct.pack_into("<I", dir_data, 8,  sysinfo_rva)
    struct.pack_into("<I", dir_data, 12, 6)
    struct.pack_into("<I", dir_data, 16, len(exc_stream))
    struct.pack_into("<I", dir_data, 20, exc_rva)

    return bytes(header) + bytes(dir_data) + bytes(sysinfo_data) + bytes(exc_stream)


class TestMdmpParser:
    def test_detects_mdmp_signature(self):
        data = make_mdmp_dump()
        result = AnalysisResult()
        MdmpParser(data).parse(result)
        assert "MDMP" in result.dump_type or "User-mode" in result.dump_type

    def test_extracts_exception_code(self):
        data = make_mdmp_dump(exception_code=0xC0000005)
        result = AnalysisResult()
        MdmpParser(data).parse(result)
        assert result.exception is not None
        assert result.exception["code"] == 0xC0000005

    def test_extracts_exception_address(self):
        addr = 0x00007FF812345678
        data = make_mdmp_dump(exception_addr=addr)
        result = AnalysisResult()
        MdmpParser(data).parse(result)
        assert result.exception["address"] == addr

    def test_extracts_system_info(self):
        data = make_mdmp_dump()
        result = AnalysisResult()
        MdmpParser(data).parse(result)
        assert result.build_number == 22621
        assert "x64" in result.architecture or "AMD64" in result.architecture


# ── DumpAnalyzer Integration Tests ────────────────────────────────────────

class TestDumpAnalyzer:
    def test_analyze_bytes_64bit_kernel(self):
        data = make_kernel64_header(bugcheck_code=0x0000000A)
        analyzer = DumpAnalyzer()
        result = analyzer.analyze_bytes(data)
        # analyze_bytes returns raw AnalysisResult dict (not formatted API response)
        assert result["bugcheck_code"] == 0x0000000A
        assert result["bugcheck_name"] == "IRQL_NOT_LESS_OR_EQUAL"
        assert len(result["errors"]) == 0 or result["dump_type"] != "Unknown"

    def test_analyze_bytes_mdmp(self):
        data = make_mdmp_dump(exception_code=0xC0000005)
        analyzer = DumpAnalyzer()
        result = analyzer.analyze_bytes(data)
        assert result["exception"] is not None
        assert result["exception"]["code"] == 0xC0000005

    def test_analyze_bytes_unknown_format(self):
        data = b"UNKNOWN_FORMAT_GARBAGE_DATA" * 100
        analyzer = DumpAnalyzer()
        result = analyzer.analyze_bytes(data)
        assert len(result["errors"]) > 0
        assert result["dump_type"] == "Unknown"

    def test_analyze_bytes_empty(self):
        analyzer = DumpAnalyzer()
        result = analyzer.analyze_bytes(b"")
        assert len(result["errors"]) > 0

    def test_analyze_bytes_too_small(self):
        analyzer = DumpAnalyzer()
        result = analyzer.analyze_bytes(b"\x00\x01\x02")
        assert len(result["errors"]) > 0

    def test_result_has_required_keys(self):
        data = make_kernel64_header()
        analyzer = DumpAnalyzer()
        result = analyzer.analyze_bytes(data)
        required_keys = [
            "dump_type", "architecture", "os_version", "build_number",
            "bugcheck_code", "bugcheck_name", "bugcheck_description",
            "bugcheck_parameters", "bugcheck_severity",
            "caused_by_driver", "caused_by_address",
            "loaded_modules", "threads", "stack_trace",
            "suggested_fixes", "known_causes",
            "analysis_time", "file_size", "errors", "warnings",
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

    def test_analysis_time_is_positive(self):
        data = make_kernel64_header()
        analyzer = DumpAnalyzer()
        result = analyzer.analyze_bytes(data)
        assert result["analysis_time"] >= 0

    def test_file_size_matches(self):
        data = make_kernel64_header()
        analyzer = DumpAnalyzer()
        result = analyzer.analyze_bytes(data)
        assert result["file_size"] == len(data)


# ── Sample File Tests (if available) ──────────────────────────────────────

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "sample_dumps")


@pytest.mark.skipif(not os.path.exists(SAMPLE_DIR), reason="Sample dumps not generated")
class TestSampleFiles:
    def test_irql_dump(self):
        path = os.path.join(SAMPLE_DIR, "IRQL_NOT_LESS_OR_EQUAL.dmp")
        if not os.path.exists(path):
            pytest.skip("Sample file not found")
        analyzer = DumpAnalyzer()
        result = analyzer.analyze(path)
        assert result["bugcheck_code"] == 0x0000000A
        assert result["bugcheck_name"] == "IRQL_NOT_LESS_OR_EQUAL"

    def test_page_fault_dump(self):
        path = os.path.join(SAMPLE_DIR, "PAGE_FAULT_IN_NONPAGED_AREA.dmp")
        if not os.path.exists(path):
            pytest.skip("Sample file not found")
        analyzer = DumpAnalyzer()
        result = analyzer.analyze(path)
        assert result["bugcheck_code"] == 0x00000050

    def test_user_mode_dump(self):
        path = os.path.join(SAMPLE_DIR, "ACCESS_VIOLATION.dmp")
        if not os.path.exists(path):
            pytest.skip("Sample file not found")
        analyzer = DumpAnalyzer()
        result = analyzer.analyze(path)
        assert result["exception"] is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
