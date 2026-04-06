"""
Windows Bug Check Code Database
Reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
"""

BUGCHECK_CODES: dict[int, dict] = {
    0x00000001: {
        "name": "APC_INDEX_MISMATCH",
        "description": "This stop code indicates a mismatch in the APC (Asynchronous Procedure Call) state index.",
        "causes": ["Kernel-mode driver calling KeEnterCriticalRegion without matching KeLeaveCriticalRegion",
                   "Driver disabling APCs without re-enabling them"],
        "fixes": ["Update or roll back the offending driver", "Check for driver compatibility issues"],
        "severity": "critical"
    },
    0x0000000A: {
        "name": "IRQL_NOT_LESS_OR_EQUAL",
        "description": "A kernel-mode process or driver attempted to access a memory address to which it did not have permission at the IRQL it was running at.",
        "causes": ["Faulty device driver", "Incompatible hardware", "Corrupted system files", "RAM issues"],
        "fixes": ["Update device drivers", "Run Windows Memory Diagnostic", "Check for hardware issues",
                  "Run sfc /scannow in elevated command prompt"],
        "severity": "critical"
    },
    0x0000001A: {
        "name": "MEMORY_MANAGEMENT",
        "description": "A severe memory management error occurred.",
        "causes": ["Faulty RAM modules", "Corrupted page file", "Incompatible memory", "Driver bugs"],
        "fixes": ["Run Windows Memory Diagnostic (mdsched.exe)", "Test RAM with MemTest86",
                  "Check RAM seating and compatibility", "Update memory controller drivers"],
        "severity": "critical"
    },
    0x0000001E: {
        "name": "KMODE_EXCEPTION_NOT_HANDLED",
        "description": "A kernel-mode program generated an exception that the error handler did not catch.",
        "causes": ["Incompatible or corrupted device driver", "Hardware failure", "System file corruption"],
        "fixes": ["Update or reinstall drivers", "Run System File Checker (sfc /scannow)",
                  "Check hardware for failures", "Perform clean boot to isolate the issue"],
        "severity": "critical"
    },
    0x00000023: {
        "name": "FAT_FILE_SYSTEM",
        "description": "A problem occurred in the FAT file system.",
        "causes": ["Disk corruption", "Failing hard drive", "File system errors"],
        "fixes": ["Run CHKDSK on the affected drive", "Check disk health with manufacturer tools",
                  "Consider replacing the drive if errors persist"],
        "severity": "high"
    },
    0x00000024: {
        "name": "NTFS_FILE_SYSTEM",
        "description": "A problem occurred within the NTFS file system driver.",
        "causes": ["Disk corruption", "Failing hard drive", "File system errors", "Antivirus interference"],
        "fixes": ["Run CHKDSK /f /r on the affected drive", "Check disk health",
                  "Temporarily disable antivirus", "Consider drive replacement"],
        "severity": "high"
    },
    0x0000002E: {
        "name": "DATA_BUS_ERROR",
        "description": "A parity error was detected in system memory.",
        "causes": ["Faulty RAM", "Failing hardware", "ECC memory errors"],
        "fixes": ["Test RAM with MemTest86", "Replace faulty RAM modules", "Check hardware connections"],
        "severity": "critical"
    },
    0x0000003B: {
        "name": "SYSTEM_SERVICE_EXCEPTION",
        "description": "An exception happened while executing a routine that transitions from non-privileged code to privileged code.",
        "causes": ["Incompatible driver", "System file corruption", "Hardware issues", "Antivirus conflicts"],
        "fixes": ["Update Windows and drivers", "Run sfc /scannow", "Check for driver conflicts",
                  "Disable third-party antivirus temporarily"],
        "severity": "critical"
    },
    0x0000003D: {
        "name": "INTERRUPT_EXCEPTION_NOT_HANDLED",
        "description": "An interrupt was not handled properly.",
        "causes": ["Hardware driver issues", "Interrupt conflicts"],
        "fixes": ["Update device drivers", "Check for hardware conflicts in Device Manager"],
        "severity": "high"
    },
    0x00000044: {
        "name": "MULTIPLE_IRP_COMPLETE_REQUESTS",
        "description": "A driver completed an IRP (I/O Request Packet) that was already complete.",
        "causes": ["Buggy device driver", "Driver completing the same IRP twice"],
        "fixes": ["Update or roll back the offending driver", "Contact driver vendor"],
        "severity": "critical"
    },
    0x0000004E: {
        "name": "PFN_LIST_CORRUPT",
        "description": "The page frame number (PFN) list is corrupted.",
        "causes": ["Faulty RAM", "Corrupted drivers", "Hardware failure"],
        "fixes": ["Run Windows Memory Diagnostic", "Test RAM with MemTest86", "Update drivers",
                  "Check disk health"],
        "severity": "critical"
    },
    0x00000050: {
        "name": "PAGE_FAULT_IN_NONPAGED_AREA",
        "description": "A page fault occurred in a nonpaged area of memory.",
        "causes": ["Faulty RAM", "Corrupted system files", "Incompatible drivers", "Failing hardware"],
        "fixes": ["Run Windows Memory Diagnostic", "Run sfc /scannow", "Update or roll back drivers",
                  "Check hardware health"],
        "severity": "critical"
    },
    0x00000051: {
        "name": "REGISTRY_ERROR",
        "description": "An I/O error occurred while trying to read or write to the registry.",
        "causes": ["Registry corruption", "Failing hard drive", "I/O subsystem problems"],
        "fixes": ["Run CHKDSK", "Restore registry from backup", "Check disk health",
                  "Perform System Restore"],
        "severity": "critical"
    },
    0x00000058: {
        "name": "FTDISK_INTERNAL_ERROR",
        "description": "A problem occurred with a fault-tolerant disk set.",
        "causes": ["RAID configuration issues", "Disk failures", "Storage driver problems"],
        "fixes": ["Check RAID configuration", "Replace failing disks", "Update storage drivers"],
        "severity": "critical"
    },
    0x0000005A: {
        "name": "CRITICAL_SERVICE_FAILED",
        "description": "A critical system service failed to start.",
        "causes": ["Corrupted system files", "Malware infection", "Failed Windows Update"],
        "fixes": ["Run sfc /scannow", "Run DISM /Online /Cleanup-Image /RestoreHealth",
                  "Perform System Restore", "Consider Windows repair installation"],
        "severity": "critical"
    },
    0x0000005D: {
        "name": "UNSUPPORTED_PROCESSOR",
        "description": "The processor is not supported by this version of Windows.",
        "causes": ["Incompatible CPU", "BIOS/UEFI settings", "Virtualization issues"],
        "fixes": ["Check CPU compatibility", "Update BIOS/UEFI", "Verify virtualization settings"],
        "severity": "critical"
    },
    0x0000006B: {
        "name": "PROCESS1_INITIALIZATION_FAILED",
        "description": "The initialization of the Windows executive or kernel failed.",
        "causes": ["Corrupted system files", "Failed Windows installation", "Disk errors"],
        "fixes": ["Run Startup Repair", "Run sfc /scannow from WinPE", "Reinstall Windows"],
        "severity": "critical"
    },
    0x0000006F: {
        "name": "SESSION3_INITIALIZATION_FAILED",
        "description": "Session Manager initialization failed.",
        "causes": ["Corrupted system files", "Registry issues", "Failed Windows Update"],
        "fixes": ["Run Startup Repair", "Perform System Restore", "Reinstall Windows"],
        "severity": "critical"
    },
    0x00000074: {
        "name": "BAD_SYSTEM_CONFIG_INFO",
        "description": "The SYSTEM registry hive file is missing or corrupt.",
        "causes": ["Registry corruption", "Failed Windows Update", "Disk errors"],
        "fixes": ["Run Startup Repair", "Restore registry hive from backup", "Perform System Restore"],
        "severity": "critical"
    },
    0x0000007A: {
        "name": "KERNEL_DATA_INPAGE_ERROR",
        "description": "The requested page of kernel data from the paging file could not be read into memory.",
        "causes": ["Failing hard drive", "Corrupted page file", "RAM issues", "Virus infection"],
        "fixes": ["Run CHKDSK /f /r", "Test RAM with MemTest86", "Check disk health",
                  "Run antivirus scan"],
        "severity": "critical"
    },
    0x0000007B: {
        "name": "INACCESSIBLE_BOOT_DEVICE",
        "description": "Windows could not access the volume containing the boot files during startup.",
        "causes": ["Storage controller driver issues", "Corrupted boot sector", "BIOS/UEFI settings",
                   "SATA mode change (IDE/AHCI)"],
        "fixes": ["Check BIOS storage mode settings", "Run Startup Repair", "Update storage drivers",
                  "Check disk connections"],
        "severity": "critical"
    },
    0x0000007E: {
        "name": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        "description": "A system thread generated an exception that the error handler did not catch.",
        "causes": ["Incompatible driver", "Hardware failure", "System file corruption"],
        "fixes": ["Boot in Safe Mode and update drivers", "Run sfc /scannow",
                  "Check hardware for failures"],
        "severity": "critical"
    },
    0x0000007F: {
        "name": "UNEXPECTED_KERNEL_MODE_TRAP",
        "description": "A trap was generated by the Intel CPU that the kernel failed to catch.",
        "causes": ["Hardware failure (RAM, CPU, overheating)", "Incompatible drivers", "Overclocking issues"],
        "fixes": ["Check CPU temperature", "Disable overclocking", "Test RAM", "Update drivers"],
        "severity": "critical"
    },
    0x00000080: {
        "name": "NMI_HARDWARE_FAILURE",
        "description": "A hardware malfunction occurred.",
        "causes": ["Hardware failure", "Parity error in RAM", "I/O device failure"],
        "fixes": ["Check all hardware components", "Test RAM", "Check hardware connections"],
        "severity": "critical"
    },
    0x00000096: {
        "name": "INVALID_WORK_QUEUE_ITEM",
        "description": "A work queue item was not properly initialized.",
        "causes": ["Buggy device driver", "Kernel code errors"],
        "fixes": ["Update or roll back drivers", "Contact hardware vendor"],
        "severity": "high"
    },
    0x0000009C: {
        "name": "MACHINE_CHECK_EXCEPTION",
        "description": "A fatal Machine Check Exception has occurred.",
        "causes": ["Hardware failure (CPU, RAM, motherboard)", "Overheating", "Power supply issues"],
        "fixes": ["Check CPU and system temperatures", "Test RAM", "Check power supply",
                  "Update BIOS/UEFI"],
        "severity": "critical"
    },
    0x0000009F: {
        "name": "DRIVER_POWER_STATE_FAILURE",
        "description": "A driver is in an inconsistent or invalid power state.",
        "causes": ["Incompatible power management driver", "Driver not handling power state transitions",
                   "Outdated drivers"],
        "fixes": ["Update all device drivers", "Disable fast startup", "Update power management drivers",
                  "Check for Windows updates"],
        "severity": "critical"
    },
    0x000000A0: {
        "name": "INTERNAL_POWER_ERROR",
        "description": "A fatal error occurred while processing a power event.",
        "causes": ["Power management driver issues", "BIOS/UEFI power settings"],
        "fixes": ["Update BIOS/UEFI", "Update power management drivers", "Check power settings"],
        "severity": "high"
    },
    0x000000BE: {
        "name": "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
        "description": "A driver attempted to write to read-only memory.",
        "causes": ["Buggy device driver", "Kernel code attempting to modify read-only data"],
        "fixes": ["Update or roll back the offending driver", "Contact hardware vendor"],
        "severity": "critical"
    },
    0x000000C2: {
        "name": "BAD_POOL_CALLER",
        "description": "The current thread made a bad pool request.",
        "causes": ["Buggy device driver", "Corrupted memory pool", "Hardware issues"],
        "fixes": ["Update or roll back drivers", "Run Windows Memory Diagnostic",
                  "Check for hardware issues"],
        "severity": "critical"
    },
    0x000000C4: {
        "name": "DRIVER_VERIFIER_DETECTED_VIOLATION",
        "description": "Driver Verifier detected a violation.",
        "causes": ["Driver violating rules detected by Driver Verifier"],
        "fixes": ["Identify the violating driver", "Update or remove the offending driver"],
        "severity": "high"
    },
    0x000000C5: {
        "name": "DRIVER_CORRUPTED_EXPOOL",
        "description": "An attempt was made to access a pageable (or completely invalid) address at an IRQL that is too high.",
        "causes": ["Buggy device driver", "Corrupted memory"],
        "fixes": ["Update or roll back drivers", "Run Windows Memory Diagnostic"],
        "severity": "critical"
    },
    0x000000D1: {
        "name": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        "description": "A kernel-mode driver attempted to access pageable memory at a process IRQL that was too high.",
        "causes": ["Faulty device driver", "Driver accessing memory at wrong IRQL"],
        "fixes": ["Update or roll back the offending driver", "Check for driver conflicts",
                  "Run Driver Verifier"],
        "severity": "critical"
    },
    0x000000D4: {
        "name": "SYSTEM_SCAN_AT_RAISED_IRQL_CAUGHT_IMPROPER_DRIVER_UNLOAD",
        "description": "A driver unloaded without cancelling pending operations.",
        "causes": ["Buggy device driver unloading improperly"],
        "fixes": ["Update or roll back the offending driver"],
        "severity": "high"
    },
    0x000000D8: {
        "name": "DRIVER_USED_EXCESSIVE_PTES",
        "description": "A driver requested too many Page Table Entries (PTEs).",
        "causes": ["Buggy device driver requesting excessive PTEs", "Memory leak in driver"],
        "fixes": ["Update or roll back the offending driver", "Increase virtual memory"],
        "severity": "high"
    },
    0x000000EA: {
        "name": "THREAD_STUCK_IN_DEVICE_DRIVER",
        "description": "A device driver is spinning in an infinite loop, most likely waiting for hardware to become idle.",
        "causes": ["Faulty graphics driver", "Hardware issue with graphics card", "Overheating GPU"],
        "fixes": ["Update graphics drivers", "Check GPU temperature", "Reduce GPU overclock",
                  "Replace graphics card if hardware failure"],
        "severity": "high"
    },
    0x000000EF: {
        "name": "CRITICAL_PROCESS_DIED",
        "description": "A critical system process died.",
        "causes": ["Corrupted system files", "Malware infection", "Hardware issues", "Driver bugs"],
        "fixes": ["Run sfc /scannow", "Run DISM /Online /Cleanup-Image /RestoreHealth",
                  "Run antivirus scan", "Perform System Restore"],
        "severity": "critical"
    },
    0x000000F4: {
        "name": "CRITICAL_OBJECT_TERMINATION",
        "description": "A process or thread crucial to system operation has unexpectedly exited.",
        "causes": ["Failing hard drive", "Corrupted system files", "Malware", "RAM issues"],
        "fixes": ["Check disk health with SMART tools", "Run CHKDSK", "Run antivirus scan",
                  "Test RAM"],
        "severity": "critical"
    },
    0x000000FE: {
        "name": "BUGCODE_USB_DRIVER",
        "description": "A USB driver error occurred.",
        "causes": ["Faulty USB device", "Incompatible USB driver", "USB controller issues"],
        "fixes": ["Disconnect USB devices and test", "Update USB drivers", "Update BIOS/UEFI",
                  "Test with different USB ports"],
        "severity": "high"
    },
    0x00000101: {
        "name": "CLOCK_WATCHDOG_TIMEOUT",
        "description": "An expected clock interrupt was not received on a secondary processor within the allocated interval.",
        "causes": ["CPU overclocking", "Hardware failure", "Multiprocessor configuration issues"],
        "fixes": ["Disable CPU overclocking", "Update BIOS/UEFI", "Check CPU cooling",
                  "Test individual CPU cores"],
        "severity": "critical"
    },
    0x00000109: {
        "name": "CRITICAL_STRUCTURE_CORRUPTION",
        "description": "The kernel detected that critical kernel code or data was corrupted.",
        "causes": ["Rootkit or malware", "Faulty hardware", "Driver bugs"],
        "fixes": ["Run antimalware scan", "Check hardware integrity", "Update drivers",
                  "Reinstall Windows if malware is suspected"],
        "severity": "critical"
    },
    0x0000010D: {
        "name": "WDF_VIOLATION",
        "description": "The kernel detected an error in a framework-based driver.",
        "causes": ["WDF (Windows Driver Framework) driver violation"],
        "fixes": ["Update the offending WDF driver", "Contact hardware vendor"],
        "severity": "high"
    },
    0x00000116: {
        "name": "VIDEO_TDR_FAILURE",
        "description": "An attempt to reset the display driver and recover from a timeout failed.",
        "causes": ["Outdated or corrupted graphics driver", "Overheating GPU", "Faulty graphics card",
                   "Insufficient power supply"],
        "fixes": ["Update graphics drivers", "Check GPU temperature", "Reduce GPU overclock",
                  "Check power supply adequacy", "Replace graphics card if necessary"],
        "severity": "high"
    },
    0x0000011A: {
        "name": "EM_INITIALIZATION_FAILURE",
        "description": "The Errata Manager failed to initialize.",
        "causes": ["Hardware compatibility issues", "BIOS/UEFI problems"],
        "fixes": ["Update BIOS/UEFI", "Check hardware compatibility"],
        "severity": "high"
    },
    0x00000122: {
        "name": "WHEA_INTERNAL_ERROR",
        "description": "A Windows Hardware Error Architecture (WHEA) internal error occurred.",
        "causes": ["Hardware failure", "BIOS/UEFI issues"],
        "fixes": ["Update BIOS/UEFI", "Check hardware health", "Run hardware diagnostics"],
        "severity": "critical"
    },
    0x00000124: {
        "name": "WHEA_UNCORRECTABLE_ERROR",
        "description": "A fatal hardware error has occurred.",
        "causes": ["CPU error", "RAM error", "Motherboard failure", "Overheating"],
        "fixes": ["Check CPU and system temperatures", "Test RAM", "Update BIOS/UEFI",
                  "Check hardware connections", "Run hardware diagnostics"],
        "severity": "critical"
    },
    0x0000012B: {
        "name": "FAULTY_HARDWARE_CORRUPTED_PAGE",
        "description": "A hardware memory error was detected.",
        "causes": ["Faulty RAM", "Memory controller issues"],
        "fixes": ["Test RAM with MemTest86", "Replace faulty RAM modules"],
        "severity": "critical"
    },
    0x00000133: {
        "name": "DPC_WATCHDOG_VIOLATION",
        "description": "A DPC (Deferred Procedure Call) watchdog timeout occurred.",
        "causes": ["Outdated drivers", "Hardware issues", "SSD firmware issues"],
        "fixes": ["Update all drivers", "Update SSD firmware", "Check hardware health",
                  "Disable fast startup"],
        "severity": "high"
    },
    0x00000139: {
        "name": "KERNEL_SECURITY_CHECK_FAILURE",
        "description": "A kernel security check failed.",
        "causes": ["Corrupted system files", "Incompatible drivers", "Malware"],
        "fixes": ["Run sfc /scannow", "Update drivers", "Run antimalware scan",
                  "Perform clean Windows installation if persistent"],
        "severity": "critical"
    },
    0x0000013A: {
        "name": "KERNEL_MODE_HEAP_CORRUPTION",
        "description": "The kernel mode heap manager detected corruption.",
        "causes": ["Buggy device driver", "Memory corruption"],
        "fixes": ["Update or roll back drivers", "Run Driver Verifier to identify the culprit"],
        "severity": "critical"
    },
    0x00000141: {
        "name": "VIDEO_ENGINE_TIMEOUT_DETECTED",
        "description": "The display driver failed to respond in time.",
        "causes": ["Outdated graphics driver", "GPU overheating", "Faulty graphics card"],
        "fixes": ["Update graphics drivers", "Check GPU temperature", "Reduce GPU overclock"],
        "severity": "high"
    },
    0x00000143: {
        "name": "PROCESSOR_DRIVER_INTERNAL",
        "description": "A processor driver internal error occurred.",
        "causes": ["CPU driver issues", "Hardware problems"],
        "fixes": ["Update processor drivers", "Update BIOS/UEFI"],
        "severity": "high"
    },
    0x00000154: {
        "name": "UNEXPECTED_STORE_EXCEPTION",
        "description": "An unexpected exception was received from a store component.",
        "causes": ["SSD/NVMe firmware issues", "Storage driver problems", "Faulty storage device"],
        "fixes": ["Update SSD/NVMe firmware", "Update storage drivers", "Check drive health",
                  "Replace storage device if failing"],
        "severity": "critical"
    },
    0x0000015A: {
        "name": "SDBUS_INTERNAL_ERROR",
        "description": "An SD bus internal error occurred.",
        "causes": ["SD card reader driver issues", "Faulty SD card"],
        "fixes": ["Update SD card reader drivers", "Remove SD card and test"],
        "severity": "medium"
    },
    0x00000160: {
        "name": "WIN32K_ATOMIC_CHECK_FAILURE",
        "description": "A Win32k atomic check failure occurred.",
        "causes": ["Graphics driver issues", "Win32k subsystem bugs"],
        "fixes": ["Update graphics drivers", "Run Windows Update"],
        "severity": "high"
    },
    0x0000017E: {
        "name": "MICROCODE_REVISION_MISMATCH",
        "description": "A microcode revision mismatch was detected.",
        "causes": ["CPU microcode update issues", "BIOS/UEFI update problems"],
        "fixes": ["Update BIOS/UEFI", "Check CPU microcode compatibility"],
        "severity": "critical"
    },
    0x00000190: {
        "name": "WIN32K_CRITICAL_FAILURE_LIVEDUMP",
        "description": "A Win32k critical failure was detected.",
        "causes": ["Graphics subsystem issues", "Win32k driver bugs"],
        "fixes": ["Update graphics drivers", "Run Windows Update"],
        "severity": "high"
    },
    0xC0000005: {
        "name": "ACCESS_VIOLATION",
        "description": "An access violation occurred - code attempted to access memory it doesn't have permission to access.",
        "causes": ["Buggy application or driver", "Memory corruption", "Null pointer dereference"],
        "fixes": ["Update the offending application or driver", "Run memory diagnostics"],
        "severity": "high"
    },
    0xDEADDEAD: {
        "name": "MANUALLY_INITIATED_CRASH1",
        "description": "The user deliberately initiated a crash dump from the keyboard.",
        "causes": ["Manual crash initiated by user or administrator"],
        "fixes": ["This is intentional - no fix required unless crash was unintentional"],
        "severity": "low"
    },
    0xE2: {
        "name": "MANUALLY_INITIATED_CRASH",
        "description": "The user deliberately initiated a crash dump.",
        "causes": ["Manual crash initiated by user or administrator"],
        "fixes": ["This is intentional - no fix required unless crash was unintentional"],
        "severity": "low"
    },
}


def get_bugcheck_info(code: int) -> dict:
    """
    Returns information about a bug check code.
    Falls back to a generic entry if the code is not in the database.
    """
    if code in BUGCHECK_CODES:
        return BUGCHECK_CODES[code]

    # Try to find partial matches for known prefixes
    return {
        "name": f"UNKNOWN_BUGCHECK_0x{code:08X}",
        "description": f"An unknown or undocumented bug check code (0x{code:08X}) was encountered.",
        "causes": ["Unknown cause - this bug check code is not in the database",
                   "Possible hardware or driver issue"],
        "fixes": ["Search Microsoft documentation for bug check 0x{:08X}".format(code),
                  "Check Windows Event Viewer for additional information",
                  "Update all device drivers",
                  "Run Windows Memory Diagnostic"],
        "severity": "unknown"
    }


# Known Windows system modules and their descriptions
KNOWN_MODULES: dict[str, dict] = {
    "ntoskrnl.exe": {
        "description": "Windows NT OS Kernel",
        "type": "kernel",
        "vendor": "Microsoft Corporation",
        "note": "Core Windows kernel - crash may indicate hardware issues or kernel-mode driver bugs"
    },
    "ntkrnlmp.exe": {
        "description": "Windows NT OS Kernel (Multiprocessor)",
        "type": "kernel",
        "vendor": "Microsoft Corporation",
        "note": "Multiprocessor kernel variant"
    },
    "ntkrnlpa.exe": {
        "description": "Windows NT OS Kernel (PAE)",
        "type": "kernel",
        "vendor": "Microsoft Corporation",
        "note": "PAE-enabled kernel variant"
    },
    "hal.dll": {
        "description": "Hardware Abstraction Layer",
        "type": "kernel",
        "vendor": "Microsoft Corporation",
        "note": "Hardware abstraction - crash may indicate hardware compatibility issues"
    },
    "win32k.sys": {
        "description": "Windows Win32 Kernel-Mode Driver",
        "type": "kernel",
        "vendor": "Microsoft Corporation",
        "note": "Windows graphics/user interface kernel component"
    },
    "win32kbase.sys": {
        "description": "Windows Win32 Base Kernel Driver",
        "type": "kernel",
        "vendor": "Microsoft Corporation",
        "note": "Base Win32 kernel component"
    },
    "win32kfull.sys": {
        "description": "Windows Win32 Full Kernel Driver",
        "type": "kernel",
        "vendor": "Microsoft Corporation",
        "note": "Full Win32 kernel component"
    },
    "dxgkrnl.sys": {
        "description": "DirectX Graphics Kernel",
        "type": "graphics",
        "vendor": "Microsoft Corporation",
        "note": "DirectX kernel - crash often related to GPU driver issues"
    },
    "dxgmms1.sys": {
        "description": "DirectX Graphics MMS",
        "type": "graphics",
        "vendor": "Microsoft Corporation",
        "note": "DirectX memory management - update graphics drivers"
    },
    "dxgmms2.sys": {
        "description": "DirectX Graphics MMS 2",
        "type": "graphics",
        "vendor": "Microsoft Corporation",
        "note": "DirectX memory management v2 - update graphics drivers"
    },
    "nvlddmkm.sys": {
        "description": "NVIDIA Windows Kernel Mode Driver",
        "type": "graphics",
        "vendor": "NVIDIA Corporation",
        "note": "NVIDIA GPU driver - update from nvidia.com or use DDU to clean reinstall"
    },
    "nvkflt.sys": {
        "description": "NVIDIA Kernel Filter Driver",
        "type": "graphics",
        "vendor": "NVIDIA Corporation",
        "note": "NVIDIA filter driver - update NVIDIA drivers"
    },
    "atikmdag.sys": {
        "description": "AMD Radeon Kernel Mode Driver",
        "type": "graphics",
        "vendor": "Advanced Micro Devices",
        "note": "AMD GPU driver - update from amd.com or use DDU to clean reinstall"
    },
    "amdkmdag.sys": {
        "description": "AMD Kernel Mode Driver",
        "type": "graphics",
        "vendor": "Advanced Micro Devices",
        "note": "AMD GPU driver - update from amd.com"
    },
    "igdkmd64.sys": {
        "description": "Intel Graphics Kernel Mode Driver",
        "type": "graphics",
        "vendor": "Intel Corporation",
        "note": "Intel integrated graphics driver - update from intel.com"
    },
    "igdkmdn64.sys": {
        "description": "Intel Graphics Kernel Mode Driver (N)",
        "type": "graphics",
        "vendor": "Intel Corporation",
        "note": "Intel integrated graphics driver"
    },
    "storport.sys": {
        "description": "Microsoft Storage Port Driver",
        "type": "storage",
        "vendor": "Microsoft Corporation",
        "note": "Storage subsystem - check disk health and storage drivers"
    },
    "storahci.sys": {
        "description": "Microsoft Standard SATA AHCI Controller",
        "type": "storage",
        "vendor": "Microsoft Corporation",
        "note": "AHCI storage driver - check SATA connections and drive health"
    },
    "stornvme.sys": {
        "description": "Microsoft Standard NVMe Device Driver",
        "type": "storage",
        "vendor": "Microsoft Corporation",
        "note": "NVMe SSD driver - update NVMe firmware and driver"
    },
    "ndis.sys": {
        "description": "Network Driver Interface Specification",
        "type": "network",
        "vendor": "Microsoft Corporation",
        "note": "Network subsystem - check network adapter drivers"
    },
    "tcpip.sys": {
        "description": "TCP/IP Protocol Driver",
        "type": "network",
        "vendor": "Microsoft Corporation",
        "note": "TCP/IP stack - network configuration or driver issue"
    },
    "acpi.sys": {
        "description": "ACPI Driver for NT",
        "type": "system",
        "vendor": "Microsoft Corporation",
        "note": "ACPI power management - update BIOS/UEFI firmware"
    },
    "pci.sys": {
        "description": "NT Plug and Play PCI Enumerator",
        "type": "system",
        "vendor": "Microsoft Corporation",
        "note": "PCI bus driver - check hardware connections"
    },
    "usbhub.sys": {
        "description": "Default USB Hub Driver",
        "type": "usb",
        "vendor": "Microsoft Corporation",
        "note": "USB hub driver - disconnect USB devices and test"
    },
    "usbxhci.sys": {
        "description": "USB xHCI Compliant Host Controller",
        "type": "usb",
        "vendor": "Microsoft Corporation",
        "note": "USB 3.x controller driver - update USB drivers"
    },
    "fltmgr.sys": {
        "description": "Microsoft Filesystem Filter Manager",
        "type": "filesystem",
        "vendor": "Microsoft Corporation",
        "note": "File system filter manager - check antivirus and security software"
    },
    "ntfs.sys": {
        "description": "NT File System Driver",
        "type": "filesystem",
        "vendor": "Microsoft Corporation",
        "note": "NTFS file system driver - run CHKDSK"
    },
    "cng.sys": {
        "description": "Kernel Cryptography, Next Generation",
        "type": "security",
        "vendor": "Microsoft Corporation",
        "note": "Cryptography driver"
    },
    "ksecdd.sys": {
        "description": "Kernel Security Support Provider Interface",
        "type": "security",
        "vendor": "Microsoft Corporation",
        "note": "Security support provider"
    },
}


def get_module_info(module_name: str) -> dict:
    """Returns information about a known Windows module."""
    name_lower = module_name.lower()
    if name_lower in KNOWN_MODULES:
        return KNOWN_MODULES[name_lower]

    # Check for partial matches
    for known_name, info in KNOWN_MODULES.items():
        if known_name in name_lower or name_lower in known_name:
            return info

    return {
        "description": f"Unknown module: {module_name}",
        "type": "unknown",
        "vendor": "Unknown",
        "note": "This module is not in the known modules database. It may be a third-party driver."
    }
