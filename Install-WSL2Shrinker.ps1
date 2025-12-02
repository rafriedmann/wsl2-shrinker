<#
.SYNOPSIS
    Intune installer wrapper for WSL2 Shrinker

.DESCRIPTION
    This script is the entry point for Intune deployment.
    It executes the main shrink script with appropriate parameters.

.NOTES
    Intune Win32 App Configuration:

    OPTION A - User-Friendly (Notifies user, 30s grace period):
    - Install command: powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File Install-WSL2Shrinker.ps1

    OPTION B - Non-Disruptive (Skips if WSL is running):
    - Install command: powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File Install-WSL2Shrinker.ps1 -SkipIfRunning

    OPTION C - Silent (No notification, immediate shutdown):
    - Install command: powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File Install-WSL2Shrinker.ps1 -Silent

    Common settings:
    - Uninstall command: reg.exe delete "HKLM\SOFTWARE\WSL2Shrinker" /f
    - Install behavior: System
    - Device restart behavior: No specific action
    - Detection rules: Use custom detection script (Detect-WSL2Shrinker.ps1)
#>

param(
    [switch]$SkipIfRunning,
    [switch]$Silent,
    [int]$GracePeriod = 30
)

$ErrorActionPreference = "Stop"

try {
    # Get the directory where this script is located
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

    # Path to the main script
    $mainScript = Join-Path $scriptDir "Shrink-WSL2Distributions.ps1"

    if (-not (Test-Path $mainScript)) {
        Write-Error "Main script not found: $mainScript"
        exit 1
    }

    # Build parameters
    $params = @{
        Force = $true
    }

    if ($SkipIfRunning) {
        $params.SkipIfRunning = $true
    }

    if (-not $Silent) {
        $params.NotifyUser = $true
        $params.ShutdownGracePeriod = $GracePeriod
    }

    # Execute the main script
    & $mainScript @params

    exit $LASTEXITCODE
}
catch {
    Write-Error "Installation failed: $_"
    exit 1
}
