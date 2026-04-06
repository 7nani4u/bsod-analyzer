"""
Create synthetic Windows crash dump files for testing.
These are minimal but structurally valid dump headers.
"""

import struct
import os

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "sample_dumps")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def create_kernel_dump_64bit(
    bugcheck_code: int,
    bugcheck_params: list[int],
    major_version: int = 10,
    minor_version: int = 22621,
    machine_type: int = 0x8664,
    num_processors: int = 8,
    dump_type: int = 4,  # Triage/Minidump
    filename: str = "kernel64.dmp",
) -> str:
    """
    Creates a minimal 64-bit kernel dump header (PAGEDU64).
    Based on _DMP_HEADER64 structure (8192 bytes header).
    """
    header = bytearray(8192)

    # Signature: "PAGEDU64"
    header[0x00:0x08] = b"PAGEDU64"

    # MajorVersion (ULONG at 0x08)
    struct.pack_into("<I", header, 0x08, major_version)

    # MinorVersion / Build number (ULONG at 0x0C)
    struct.pack_into("<I", header, 0x0C, minor_version)

    # DirectoryTableBase (ULONGLONG at 0x10)
    struct.pack_into("<Q", header, 0x10, 0x001AD000)

    # PfnDataBase (ULONGLONG at 0x18)
    struct.pack_into("<Q", header, 0x18, 0xFFFF808000000000)

    # PsLoadedModuleList (ULONGLONG at 0x20)
    struct.pack_into("<Q", header, 0x20, 0xFFFF808001234567)

    # PsActiveProcessHead (ULONGLONG at 0x28)
    struct.pack_into("<Q", header, 0x28, 0xFFFF808001234890)

    # MachineImageType (ULONG at 0x30)
    struct.pack_into("<I", header, 0x30, machine_type)

    # NumberProcessors (ULONG at 0x34)
    struct.pack_into("<I", header, 0x34, num_processors)

    # BugCheckCode (ULONG at 0x38)
    struct.pack_into("<I", header, 0x38, bugcheck_code)

    # BugCheckCodeParameter[4] (ULONGLONG[4] at 0x40)
    for i, param in enumerate(bugcheck_params[:4]):
        struct.pack_into("<Q", header, 0x40 + i * 8, param)

    # KdDebuggerDataBlock (ULONGLONG at 0x80)
    struct.pack_into("<Q", header, 0x80, 0xFFFF808002345678)

    # DumpType (ULONG at 0xF98)
    struct.pack_into("<I", header, 0xF98, dump_type)

    # Comment (128 bytes at 0xFB0)
    comment = b"Test dump created for BSOD Analyzer testing\x00"
    header[0xFB0:0xFB0 + len(comment)] = comment

    # ProductType (ULONG at 0x1040) - 1=Workstation
    struct.pack_into("<I", header, 0x1040, 1)

    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "wb") as f:
        f.write(bytes(header))
    print(f"Created: {path} ({len(header)} bytes)")
    return path


def create_kernel_dump_32bit(
    bugcheck_code: int,
    bugcheck_params: list[int],
    major_version: int = 10,
    minor_version: int = 19045,
    machine_type: int = 0x014C,
    num_processors: int = 4,
    dump_type: int = 4,
    filename: str = "kernel32.dmp",
) -> str:
    """
    Creates a minimal 32-bit kernel dump header (PAGEDUMP).
    Based on _DMP_HEADER structure (4096 bytes header).
    """
    header = bytearray(4096)

    # Signature: "PAGEDUMP"
    header[0x00:0x08] = b"PAGEDUMP"

    # MajorVersion (ULONG at 0x08)
    struct.pack_into("<I", header, 0x08, major_version)

    # MinorVersion (ULONG at 0x0C)
    struct.pack_into("<I", header, 0x0C, minor_version)

    # DirectoryTableBase (ULONG at 0x10)
    struct.pack_into("<I", header, 0x10, 0x001AD000)

    # MachineImageType (ULONG at 0x20)
    struct.pack_into("<I", header, 0x20, machine_type)

    # NumberProcessors (ULONG at 0x24)
    struct.pack_into("<I", header, 0x24, num_processors)

    # BugCheckCode (ULONG at 0x28)
    struct.pack_into("<I", header, 0x28, bugcheck_code)

    # BugCheckCodeParameter[4] (ULONG[4] at 0x2C)
    for i, param in enumerate(bugcheck_params[:4]):
        struct.pack_into("<I", header, 0x2C + i * 4, param & 0xFFFFFFFF)

    # DumpType (ULONG at 0xF88)
    struct.pack_into("<I", header, 0xF88, dump_type)

    # Comment (128 bytes at 0x820)
    comment = b"32-bit test dump for BSOD Analyzer\x00"
    header[0x820:0x820 + len(comment)] = comment

    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "wb") as f:
        f.write(bytes(header))
    print(f"Created: {path} ({len(header)} bytes)")
    return path


def create_mdmp_user_dump(
    exception_code: int = 0xC0000005,
    exception_addr: int = 0x00007FF812345678,
    filename: str = "user_mode.dmp",
) -> str:
    """
    Creates a minimal user-mode MDMP file with system info and exception streams.
    """
    # We'll build the file in sections:
    # 1. MINIDUMP_HEADER (32 bytes)
    # 2. Stream directory entries (3 entries x 12 bytes = 36 bytes)
    # 3. SystemInfo stream
    # 4. Exception stream
    # 5. ModuleList stream (minimal)

    NUM_STREAMS = 3
    HEADER_SIZE = 32
    DIR_SIZE    = NUM_STREAMS * 12

    # --- SystemInfo stream ---
    # MINIDUMP_SYSTEM_INFO: ProcessorArchitecture(2) + ProcessorLevel(2) + ProcessorRevision(2)
    # + NumberOfProcessors(1) + ProductType(1) + MajorVersion(4) + MinorVersion(4)
    # + BuildNumber(4) + PlatformId(4) + CSDVersionRva(4) + SuiteMask(2) + Reserved2(2)
    # + CPU info (12 bytes) = total 48 bytes
    sysinfo_data = bytearray(48)
    struct.pack_into("<H", sysinfo_data, 0,  9)     # ProcessorArchitecture: AMD64
    struct.pack_into("<H", sysinfo_data, 2,  0x0F)  # ProcessorLevel
    struct.pack_into("<H", sysinfo_data, 4,  0x0201) # ProcessorRevision
    sysinfo_data[6] = 8   # NumberOfProcessors
    sysinfo_data[7] = 1   # ProductType: Workstation
    struct.pack_into("<I", sysinfo_data, 8,  10)    # MajorVersion
    struct.pack_into("<I", sysinfo_data, 12, 0)     # MinorVersion
    struct.pack_into("<I", sysinfo_data, 16, 22621) # BuildNumber
    struct.pack_into("<I", sysinfo_data, 20, 2)     # PlatformId: VER_PLATFORM_WIN32_NT
    struct.pack_into("<I", sysinfo_data, 24, 0)     # CSDVersionRva (no SP string)

    # --- Exception stream ---
    # MINIDUMP_EXCEPTION_STREAM: ThreadId(4) + __alignment(4) + ExceptionRecord(varies)
    # MINIDUMP_EXCEPTION: ExceptionCode(4) + ExceptionFlags(4) + ExceptionRecord(8)
    #   + ExceptionAddress(8) + NumberParameters(4) + __unusedAlignment(4)
    #   + ExceptionInformation[15](8 each) = 4+4+8+8+4+4+120 = 152 bytes
    exc_stream = bytearray(8 + 152)
    struct.pack_into("<I", exc_stream, 0, 0x1234)   # ThreadId
    struct.pack_into("<I", exc_stream, 4, 0)         # alignment
    # ExceptionRecord starts at offset 8
    struct.pack_into("<I", exc_stream, 8,  exception_code)  # ExceptionCode
    struct.pack_into("<I", exc_stream, 12, 0)                # ExceptionFlags
    struct.pack_into("<Q", exc_stream, 16, 0)                # ExceptionRecord (nested)
    struct.pack_into("<Q", exc_stream, 24, exception_addr)   # ExceptionAddress
    struct.pack_into("<I", exc_stream, 32, 2)                # NumberParameters
    struct.pack_into("<Q", exc_stream, 40, 0x0000000000000000)  # Param 0: read/write
    struct.pack_into("<Q", exc_stream, 48, exception_addr)      # Param 1: fault address

    # --- ModuleList stream (minimal, 1 module) ---
    # MINIDUMP_MODULE_LIST: NumberOfModules(4) + MINIDUMP_MODULE[N]
    # Each MINIDUMP_MODULE: BaseOfImage(8) + SizeOfImage(4) + CheckSum(4) + TimeDateStamp(4)
    #   + ModuleNameRva(4) + VersionInfo(68) + CvRecord(8) + MiscRecord(8) + Reserved(16) = 108 bytes
    module_name_utf16 = "C:\\Windows\\System32\\ntdll.dll".encode("utf-16-le")
    module_name_rva_placeholder = 0  # Will be filled in after computing offsets

    modlist_data = bytearray(4 + 108)
    struct.pack_into("<I", modlist_data, 0, 1)  # NumberOfModules = 1
    # Module entry at offset 4
    struct.pack_into("<Q", modlist_data, 4,  0x00007FFEF0000000)  # BaseOfImage
    struct.pack_into("<I", modlist_data, 12, 0x001F0000)           # SizeOfImage
    struct.pack_into("<I", modlist_data, 16, 0xABCD1234)           # CheckSum
    struct.pack_into("<I", modlist_data, 20, 0x5F000000)           # TimeDateStamp
    # ModuleNameRva will be set below

    # --- Compute offsets ---
    sysinfo_rva   = HEADER_SIZE + DIR_SIZE
    exc_rva       = sysinfo_rva + len(sysinfo_data)
    modlist_rva   = exc_rva + len(exc_stream)
    modname_rva   = modlist_rva + len(modlist_data)

    # Set module name RVA in module entry
    struct.pack_into("<I", modlist_data, 24, modname_rva)

    # Build module name MINIDUMP_STRING: Length(4) + Buffer
    modname_str = bytearray()
    modname_str += struct.pack("<I", len(module_name_utf16))
    modname_str += module_name_utf16

    # --- MINIDUMP_HEADER ---
    header = bytearray(HEADER_SIZE)
    header[0:4] = b"MDMP"                                  # Signature
    struct.pack_into("<I", header, 4,  0x0000A793)          # Version
    struct.pack_into("<I", header, 8,  NUM_STREAMS)          # NumberOfStreams
    struct.pack_into("<I", header, 12, HEADER_SIZE)          # StreamDirectoryRva
    struct.pack_into("<I", header, 16, 0)                    # CheckSum
    struct.pack_into("<I", header, 20, 0x5F000000)           # TimeDateStamp

    # --- Stream directory ---
    # Entry format: StreamType(4) + DataSize(4) + Rva(4)
    dir_data = bytearray(DIR_SIZE)
    # Stream 0: SystemInfo (type 7)
    struct.pack_into("<I", dir_data, 0,  7)
    struct.pack_into("<I", dir_data, 4,  len(sysinfo_data))
    struct.pack_into("<I", dir_data, 8,  sysinfo_rva)
    # Stream 1: Exception (type 6)
    struct.pack_into("<I", dir_data, 12, 6)
    struct.pack_into("<I", dir_data, 16, len(exc_stream))
    struct.pack_into("<I", dir_data, 20, exc_rva)
    # Stream 2: ModuleList (type 4)
    struct.pack_into("<I", dir_data, 24, 4)
    struct.pack_into("<I", dir_data, 28, len(modlist_data))
    struct.pack_into("<I", dir_data, 32, modlist_rva)

    # Assemble file
    dump_bytes = bytes(header) + bytes(dir_data) + bytes(sysinfo_data) + \
                 bytes(exc_stream) + bytes(modlist_data) + bytes(modname_str)

    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "wb") as f:
        f.write(dump_bytes)
    print(f"Created: {path} ({len(dump_bytes)} bytes)")
    return path


if __name__ == "__main__":
    print("Creating sample dump files for testing...\n")

    # 1. IRQL_NOT_LESS_OR_EQUAL (0x0A) - very common BSOD
    create_kernel_dump_64bit(
        bugcheck_code=0x0000000A,
        bugcheck_params=[0xFFFF808001234567, 0x0000000000000002, 0x0000000000000001, 0xFFFFF80012345678],
        minor_version=22621,
        filename="IRQL_NOT_LESS_OR_EQUAL.dmp",
    )

    # 2. PAGE_FAULT_IN_NONPAGED_AREA (0x50)
    create_kernel_dump_64bit(
        bugcheck_code=0x00000050,
        bugcheck_params=[0xFFFF808001234567, 0x0000000000000000, 0xFFFFF80012345678, 0x0000000000000000],
        minor_version=19045,
        filename="PAGE_FAULT_IN_NONPAGED_AREA.dmp",
    )

    # 3. MEMORY_MANAGEMENT (0x1A)
    create_kernel_dump_64bit(
        bugcheck_code=0x0000001A,
        bugcheck_params=[0x0000000000041790, 0xFFFF808001234567, 0x0000000000000000, 0x0000000000000000],
        minor_version=22000,
        filename="MEMORY_MANAGEMENT.dmp",
    )

    # 4. CRITICAL_PROCESS_DIED (0xEF)
    create_kernel_dump_64bit(
        bugcheck_code=0x000000EF,
        bugcheck_params=[0xFFFF808001234567, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
        minor_version=26100,
        filename="CRITICAL_PROCESS_DIED.dmp",
    )

    # 5. 32-bit IRQL crash
    create_kernel_dump_32bit(
        bugcheck_code=0x0000000A,
        bugcheck_params=[0xC0000005, 0x00000002, 0x00000001, 0x8054321A],
        minor_version=7601,
        filename="IRQL_32bit.dmp",
    )

    # 6. User-mode ACCESS_VIOLATION
    create_mdmp_user_dump(
        exception_code=0xC0000005,
        exception_addr=0x00007FF812345678,
        filename="ACCESS_VIOLATION.dmp",
    )

    # 7. DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xD1)
    create_kernel_dump_64bit(
        bugcheck_code=0x000000D1,
        bugcheck_params=[0xFFFF808001234567, 0x0000000000000002, 0x0000000000000008, 0xFFFFF80012345678],
        minor_version=22621,
        filename="DRIVER_IRQL_NOT_LESS_OR_EQUAL.dmp",
    )

    print("\nAll sample dumps created successfully!")
    print(f"Location: {OUTPUT_DIR}")
