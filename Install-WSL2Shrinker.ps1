<#
.SYNOPSIS
    Intune installer wrapper for WSL2 Shrinker

.DESCRIPTION
    This script is the entry point for Intune deployment.
    It executes the main shrink script with appropriate parameters.

.NOTES
    Intune Win32 App Configuration:
    - Install command: powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File Install-WSL2Shrinker.ps1
    - Uninstall command: powershell.exe -Command "Remove-Item 'HKLM:\SOFTWARE\WSL2Shrinker' -Force -ErrorAction SilentlyContinue"
    - Install behavior: System
    - Device restart behavior: No specific action
    - Detection rules: Use custom detection script (Detect-WSL2Shrinker.ps1)
#>

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

    # Execute the main script
    & $mainScript -Force

    exit $LASTEXITCODE
}
catch {
    Write-Error "Installation failed: $_"
    exit 1
}
