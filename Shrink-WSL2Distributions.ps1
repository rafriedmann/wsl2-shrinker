<#
.SYNOPSIS
    Shrinks all WSL2 distribution VHDX files to reclaim disk space.

.DESCRIPTION
    This script finds all WSL2 distributions, shuts down WSL, and compacts
    the virtual disk files (ext4.vhdx) to reclaim unused space.
    Designed for deployment via Microsoft Intune.

.NOTES
    Author: IT Admin
    Version: 1.0
    Requires: Windows 10/11 with WSL2, Hyper-V PowerShell module or diskpart

    Intune Deployment:
    - Install command: powershell.exe -ExecutionPolicy Bypass -File Shrink-WSL2Distributions.ps1
    - Uninstall command: N/A (cleanup script)
    - Install behavior: System or User (User recommended for user-specific distros)
    - Detection: Check for log file or registry key
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [string]$LogPath = "$env:ProgramData\WSL2Shrinker\Logs",

    [Parameter()]
    [switch]$Force
)

# Script configuration
$ErrorActionPreference = "Stop"
$Script:ExitCode = 0

#region Functions

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Level = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Create log directory if it doesn't exist
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }

    $logFile = Join-Path $LogPath "WSL2Shrinker_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logMessage -Encoding UTF8

    switch ($Level) {
        "Info"    { Write-Host $logMessage }
        "Warning" { Write-Warning $Message }
        "Error"   { Write-Error $Message }
    }
}

function Test-WSLInstalled {
    $wslPath = Get-Command wsl.exe -ErrorAction SilentlyContinue
    return $null -ne $wslPath
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WSLDistributions {
    <#
    .SYNOPSIS
        Gets all WSL2 distributions and their VHDX file paths
    #>

    $distributions = @()

    # Get list of distributions from WSL
    $wslOutput = wsl.exe --list --verbose 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Failed to get WSL distributions list" -Level Warning
        return $distributions
    }

    # Parse WSL output (skip header line)
    $lines = $wslOutput -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -Skip 1

    foreach ($line in $lines) {
        # Remove default marker (*) and parse
        $cleanLine = $line -replace '^\s*\*?\s*', ''
        $parts = $cleanLine -split '\s+' | Where-Object { $_ }

        if ($parts.Count -ge 2) {
            $distroName = $parts[0]
            $state = $parts[1]
            $version = if ($parts.Count -ge 3) { $parts[2] } else { "Unknown" }

            # Only process WSL2 distributions
            if ($version -eq "2") {
                $distributions += [PSCustomObject]@{
                    Name    = $distroName
                    State   = $state
                    Version = $version
                }
            }
        }
    }

    return $distributions
}

function Find-VHDXFiles {
    <#
    .SYNOPSIS
        Finds all WSL2 VHDX files on the system
    #>

    $vhdxFiles = @()

    # Common locations for WSL2 VHDX files
    $searchPaths = @()

    # User-specific paths (for user context deployment)
    if ($env:LOCALAPPDATA) {
        $searchPaths += "$env:LOCALAPPDATA\Packages"
        $searchPaths += "$env:LOCALAPPDATA\Docker\wsl"
    }

    # System-wide search for all users (for system context deployment)
    if (Test-IsElevated) {
        $usersPath = Split-Path $env:USERPROFILE -Parent
        Get-ChildItem -Path $usersPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $userLocalAppData = Join-Path $_.FullName "AppData\Local"
            if (Test-Path $userLocalAppData) {
                $searchPaths += "$userLocalAppData\Packages"
                $searchPaths += "$userLocalAppData\Docker\wsl"
            }
        }
    }

    # Also check registry for custom installation paths
    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Lxss"
    )

    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | ForEach-Object {
                $basePath = (Get-ItemProperty -Path $_.PSPath -Name BasePath -ErrorAction SilentlyContinue).BasePath
                if ($basePath -and (Test-Path $basePath)) {
                    $vhdxPath = Join-Path $basePath "ext4.vhdx"
                    if (Test-Path $vhdxPath) {
                        $distroName = (Get-ItemProperty -Path $_.PSPath -Name DistributionName -ErrorAction SilentlyContinue).DistributionName
                        $vhdxFiles += [PSCustomObject]@{
                            Path       = $vhdxPath
                            DistroName = $distroName
                            SizeBefore = (Get-Item $vhdxPath).Length
                        }
                    }
                }
            }
        }
    }

    # Search in package directories for store-installed distributions
    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath) {
            Get-ChildItem -Path $searchPath -Recurse -Filter "ext4.vhdx" -ErrorAction SilentlyContinue | ForEach-Object {
                # Avoid duplicates
                if ($vhdxFiles.Path -notcontains $_.FullName) {
                    $vhdxFiles += [PSCustomObject]@{
                        Path       = $_.FullName
                        DistroName = ($_.Directory.Parent.Name -replace 'CanonicalGroupLimited\.|\..*$', '')
                        SizeBefore = $_.Length
                    }
                }
            }
        }
    }

    return $vhdxFiles
}

function Stop-WSL {
    <#
    .SYNOPSIS
        Shuts down all WSL instances
    #>

    Write-Log "Shutting down WSL..."

    $result = wsl.exe --shutdown 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Warning during WSL shutdown: $result" -Level Warning
    }

    # Wait for WSL to fully shut down
    Start-Sleep -Seconds 5

    # Verify shutdown
    $runningDistros = Get-WSLDistributions | Where-Object { $_.State -eq "Running" }
    if ($runningDistros) {
        Write-Log "Some distributions still running after shutdown attempt" -Level Warning
        return $false
    }

    Write-Log "WSL shutdown complete"
    return $true
}

function Optimize-VHDX {
    param(
        [Parameter(Mandatory)]
        [string]$VHDXPath
    )

    if (-not (Test-Path $VHDXPath)) {
        Write-Log "VHDX file not found: $VHDXPath" -Level Warning
        return $false
    }

    $sizeBefore = (Get-Item $VHDXPath).Length
    Write-Log "Optimizing: $VHDXPath (Current size: $([math]::Round($sizeBefore / 1GB, 2)) GB)"

    # Try using Hyper-V cmdlet first (more reliable)
    $hyperVAvailable = Get-Command Optimize-VHD -ErrorAction SilentlyContinue

    if ($hyperVAvailable) {
        try {
            Write-Log "Using Hyper-V Optimize-VHD cmdlet..."
            Optimize-VHD -Path $VHDXPath -Mode Full
            $sizeAfter = (Get-Item $VHDXPath).Length
            $savedSpace = $sizeBefore - $sizeAfter
            Write-Log "Optimization complete. New size: $([math]::Round($sizeAfter / 1GB, 2)) GB (Saved: $([math]::Round($savedSpace / 1MB, 2)) MB)"
            return $true
        }
        catch {
            Write-Log "Hyper-V optimization failed: $_" -Level Warning
            Write-Log "Falling back to diskpart method..."
        }
    }

    # Fallback to diskpart
    try {
        $diskpartScript = @"
select vdisk file="$VHDXPath"
attach vdisk readonly
compact vdisk
detach vdisk
"@

        $tempScriptPath = Join-Path $env:TEMP "wsl2_compact_$(Get-Random).txt"
        $diskpartScript | Out-File -FilePath $tempScriptPath -Encoding ASCII

        Write-Log "Using diskpart for optimization..."
        $diskpartResult = diskpart.exe /s $tempScriptPath 2>&1

        Remove-Item -Path $tempScriptPath -Force -ErrorAction SilentlyContinue

        if ($LASTEXITCODE -ne 0) {
            Write-Log "Diskpart returned error: $diskpartResult" -Level Warning
            return $false
        }

        $sizeAfter = (Get-Item $VHDXPath).Length
        $savedSpace = $sizeBefore - $sizeAfter
        Write-Log "Optimization complete. New size: $([math]::Round($sizeAfter / 1GB, 2)) GB (Saved: $([math]::Round($savedSpace / 1MB, 2)) MB)"
        return $true
    }
    catch {
        Write-Log "Diskpart optimization failed: $_" -Level Error
        return $false
    }
}

function Set-RegistryMarker {
    <#
    .SYNOPSIS
        Sets a registry marker for Intune detection
    #>

    $regPath = "HKLM:\SOFTWARE\WSL2Shrinker"

    try {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }

        Set-ItemProperty -Path $regPath -Name "LastRun" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Set-ItemProperty -Path $regPath -Name "Version" -Value "1.0"

        Write-Log "Registry marker set for Intune detection"
    }
    catch {
        Write-Log "Failed to set registry marker: $_" -Level Warning
    }
}

#endregion Functions

#region Main Execution

try {
    Write-Log "========== WSL2 Disk Shrinker Started =========="
    Write-Log "Running as: $env:USERNAME"
    Write-Log "Elevated: $(Test-IsElevated)"

    # Check if WSL is installed
    if (-not (Test-WSLInstalled)) {
        Write-Log "WSL is not installed on this system. Exiting." -Level Warning
        $Script:ExitCode = 0  # Not an error for Intune - just skip
        exit $Script:ExitCode
    }

    # Check for admin rights (required for diskpart/Optimize-VHD)
    if (-not (Test-IsElevated)) {
        Write-Log "Script requires administrator privileges for VHDX optimization" -Level Warning
        # Continue anyway for user context - might have limited success
    }

    # Get current distributions
    $distributions = Get-WSLDistributions
    Write-Log "Found $($distributions.Count) WSL2 distribution(s)"

    foreach ($distro in $distributions) {
        Write-Log "  - $($distro.Name) (State: $($distro.State), Version: $($distro.Version))"
    }

    # Find all VHDX files
    $vhdxFiles = Find-VHDXFiles
    Write-Log "Found $($vhdxFiles.Count) VHDX file(s) to optimize"

    if ($vhdxFiles.Count -eq 0) {
        Write-Log "No VHDX files found. Nothing to optimize."
        $Script:ExitCode = 0
        exit $Script:ExitCode
    }

    # Calculate total size before
    $totalSizeBefore = ($vhdxFiles | Measure-Object -Property SizeBefore -Sum).Sum
    Write-Log "Total VHDX size before optimization: $([math]::Round($totalSizeBefore / 1GB, 2)) GB"

    # Shut down WSL
    if (-not (Stop-WSL)) {
        if (-not $Force) {
            Write-Log "Failed to shut down WSL. Use -Force to attempt optimization anyway." -Level Error
            $Script:ExitCode = 1
            exit $Script:ExitCode
        }
        Write-Log "Proceeding with optimization despite shutdown warning (Force mode)"
    }

    # Optimize each VHDX
    $successCount = 0
    $failCount = 0

    foreach ($vhdx in $vhdxFiles) {
        Write-Log "Processing: $($vhdx.DistroName)"

        if (Optimize-VHDX -VHDXPath $vhdx.Path) {
            $successCount++
        }
        else {
            $failCount++
        }
    }

    # Calculate total size after
    $totalSizeAfter = 0
    foreach ($vhdx in $vhdxFiles) {
        if (Test-Path $vhdx.Path) {
            $totalSizeAfter += (Get-Item $vhdx.Path).Length
        }
    }

    $totalSaved = $totalSizeBefore - $totalSizeAfter

    Write-Log "========== Optimization Summary =========="
    Write-Log "VHDX files processed: $($vhdxFiles.Count)"
    Write-Log "Successful: $successCount"
    Write-Log "Failed: $failCount"
    Write-Log "Total size before: $([math]::Round($totalSizeBefore / 1GB, 2)) GB"
    Write-Log "Total size after: $([math]::Round($totalSizeAfter / 1GB, 2)) GB"
    Write-Log "Total space saved: $([math]::Round($totalSaved / 1GB, 2)) GB ($([math]::Round($totalSaved / 1MB, 2)) MB)"

    # Set registry marker for Intune detection
    if (Test-IsElevated) {
        Set-RegistryMarker
    }

    if ($failCount -gt 0 -and $successCount -eq 0) {
        $Script:ExitCode = 1
    }
    else {
        $Script:ExitCode = 0
    }

    Write-Log "========== WSL2 Disk Shrinker Completed =========="
}
catch {
    Write-Log "Unexpected error: $_" -Level Error
    Write-Log $_.ScriptStackTrace -Level Error
    $Script:ExitCode = 1
}
finally {
    exit $Script:ExitCode
}

#endregion Main Execution
