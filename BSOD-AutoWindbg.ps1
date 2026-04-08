param ()

<#
.SYNOPSIS
    Find minidumps, analyze them using an existing WinDbg installation, and automatically upload the analysis log.

.DESCRIPTION
    This script automates the following tasks:
    1. Prompts the user to select a minidump (.dmp) file via a file dialog.
    2. Searches for an existing WinDbg installation (Preview or Windows Kits).
    3. Runs WinDbg in CLI mode to analyze the selected dump file using a custom script.
    4. Automatically uploads the resulting log files to the BSOD Analyzer web service.

.EXAMPLE
    .\BSOD-AutoWindbg.ps1

.NOTES
    Exit Codes:
      4 - Script must be run as administrator
      6 - WinDbg installation not found
#>

# Show help if -help or /help is passed
if ($args -contains '-help' -or $args -contains '/help') {
    Get-Help -Full $MyInvocation.MyCommand.Path
    exit 0
}

# Hide the initial PowerShell window if it's visible (useful when not elevated yet)
$window = Add-Type -memberDefinition @"
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
[DllImport("kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
"@ -name "Win32ShowWindowAsync" -namespace Win32Functions -passThru
$window::ShowWindow($window::GetConsoleWindow(), 0) | Out-Null

# Ensure script is running as administrator or relaunch with elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Elevating script to run as Administrator..."
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", "`"$PSCommandPath`"")
    Start-Process powershell -ArgumentList $argList -Verb RunAs
    exit 0
}


# Enforce exclusive use of Day or Hour
if ($Day -gt 0 -and $Hour -gt 0) {
    Write-Error "Cannot use both -Day and -Hour parameters simultaneously. Use only one."
    exit 3
}

# Script Variables
$windbgCli = "C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2402.24001.0_x64__8wekyb3d8bbwe\DbgX.Shell.exe" # This is a placeholder path, you might need a dynamic way to find it if it's already installed. Let's use a simpler approach.

# Let's try to find WinDbg in the default installation paths if it exists.
$windbgPaths = @(
    "C:\Program Files\WindowsApps\Microsoft.WinDbg_*_x64__8wekyb3d8bbwe\DbgX.Shell.exe",
    "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe",
    "C:\Program Files (x86)\Windows Kits\11\Debuggers\x64\windbg.exe"
)

$windbgCli = $null
foreach ($path in $windbgPaths) {
    $foundPath = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($foundPath) {
        $windbgCli = $foundPath.FullName
        break
    }
}

if (-not $windbgCli) {
    Write-Error "WinDbg not found. Please ensure WinDbg is installed."
    exit 6
}

Write-Host "Using WinDbg at: $windbgCli"

$logDir = "C:\temp\debugged"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

# Step 1: Ask user to select a dump file
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.Title = "Select a Minidump File (.dmp)"
$OpenFileDialog.Filter = "Minidump Files (*.dmp)|*.dmp|All Files (*.*)|*.*"
$OpenFileDialog.InitialDirectory = "$env:SystemRoot\Minidump"

if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $selectedFile = Get-Item $OpenFileDialog.FileName
    $WindowsFileset = @($selectedFile)
    Write-Host "Selected file: $($selectedFile.FullName)"
} else {
    Write-Host "No file selected. Exiting."
    exit 0
}

# Step 2: Filter and debug older dumps (kept for structural consistency, though we only have one file now)
$now = Get-Date

if ($WindowsFileset.Count -eq 0) {
    Write-Host "No dump files matched the specified age criteria."
} else {
    foreach ($file in $WindowsFileset) {
        $logFile = "$logDir\$($file.BaseName).txt"
        Write-Host "Analyzing: $($file.FullName)"
        # Modified to use the requested script command exactly as specified.
        # Notice: $$>a< is a WinDbg command, but in PowerShell, $$ is a special variable.
        # We escape $ with backtick `$ to prevent PowerShell from parsing it before passing it to WinDbg.
        # We also pass -WindowStyle Hidden to start WinDbg maximized/hidden if applicable, 
        # though the CLI will inherit the hidden console state.
        # Adding ; qq at the end of the WinDbg command ensures WinDbg fully quits.
        # Sometimes 'q' just stops the debugging session, while 'qq' forcefully quits the entire WinDbg instance.
        # If the script uses .logclose, we can also use 'qqd' to quit and detach. Let's stick with 'qq' for now.
        
        # Record the start time before running WinDbg to help find the correct log file later
        # Subtracting a few seconds just in case of slight clock differences
        $analysisStartTime = (Get-Date).AddSeconds(-5)

        # Start WinDbg without -Wait so the script can proceed to monitor the output
        # Appending ; qqd (quit and detach) instead of qq to see if it cleanly exits the engine
        $windbgProcess = Start-Process -FilePath $windbgCli -ArgumentList "/z `"$($file.FullName)`" /c `"`$`$>a< C:\Temp\DumpAnalysis_v18.txt; qqd`"" -WindowStyle Hidden -PassThru
        
        Write-Host "Waiting for WinDbg to generate the log file..."
        $logPattern = "Dump_Analysis_*.txt"
        $logDirectory = "C:\Temp"
        $uploadFile = $null
        
        # Wait up to 180 seconds for the log file to be created and finalized
        $timeoutSeconds = 180
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        while ($stopwatch.Elapsed.TotalSeconds -lt $timeoutSeconds) {
            $recentLogs = Get-ChildItem -Path $logDirectory -Filter $logPattern -ErrorAction SilentlyContinue | 
                          Where-Object { $_.CreationTime -ge $analysisStartTime } | 
                          Sort-Object CreationTime -Descending
            
            if ($recentLogs.Count -gt 0) {
                $potentialLog = $recentLogs[0].FullName
                
                # Check if the file is still locked by WinDbg (meaning it's still writing)
                try {
                    $stream = [System.IO.File]::Open($potentialLog, 'Open', 'Read', 'ReadWrite')
                    $stream.Close()
                    
                    # We should also ensure the file isn't empty and WinDbg has actually finished writing.
                    # A file size > 0 indicates it has at least started writing.
                    # Crucially, check if the file content contains "quit:" or ".logclose" which indicates completion
                    if ((Get-Item $potentialLog).Length -gt 0) {
                        $content = Get-Content -Path $potentialLog -Tail 20 -ErrorAction SilentlyContinue
                        if ($content -match "Closing open log file" -or $content -match "quit:") {
                            # Wait an extra 2 seconds after finding the completion marker to be very sure the .logclose has fully flushed.
                            Start-Sleep -Seconds 2
                            $uploadFile = $potentialLog
                            Write-Host "Log file generated and released: $uploadFile"
                            break
                        }
                    }
                } catch {
                    # File is locked, WinDbg is still writing. Wait a bit.
                }
            }
            Start-Sleep -Milliseconds 500
        }
        $stopwatch.Stop()
        
        # Forcefully kill WinDbg now that we have the file or timed out
        Write-Host "Closing WinDbg..."
        if ($windbgProcess -and -not $windbgProcess.HasExited) {
            $windbgProcess | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        Get-Process -Name "DbgX.Shell" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Get-Process -Name "windbg" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        
        if (-not $uploadFile) {
            Write-Error "Could not find a matching analysis log file generated after $analysisStartTime or WinDbg timed out."
        }
        
        if ($uploadFile -and (Test-Path $uploadFile)) {
            Write-Host "Proceeding with browser automation..."
            
            # Additional check: ensure the file isn't completely empty before uploading
            if ((Get-Item $uploadFile).Length -eq 0) {
                Write-Error "Upload skipped: The generated log file is empty."
            } else {
                try {
                    $frontendUrl = "https://bsod-analyzer-v2.vercel.app/"
                    Write-Host "Opening browser: $frontendUrl"
                    Start-Process $frontendUrl
                    
                    Write-Host "Wait for the browser to open and load the page..."
                    Start-Sleep -Seconds 3
                    
                    # Ensure the file path is copied to clipboard so the user can easily paste it
                    $uploadFile | Set-Clipboard
                    Write-Host "The file path has been copied to your clipboard:"
                    Write-Host "-> $uploadFile"
                    Write-Host "Please press 'Enter' or 'Space' on the website, then paste (Ctrl+V) the path."
                    
                } catch {
                    Write-Error "Failed to open browser`: $_"
                    Start-Process "explorer.exe" -ArgumentList "/select,`"$uploadFile`""
                }
            }
        } else {
            Write-Error "Upload skipped: Invalid or missing file path ($uploadFile)"
        }
    }
    Write-Host "All dump files processed."
}
