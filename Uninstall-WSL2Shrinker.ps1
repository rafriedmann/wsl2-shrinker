<#
.SYNOPSIS
    Uninstalls WSL2 Shrinker by removing the registry detection key.
#>

$LogPath = "$env:ProgramData\WSL2Shrinker\Logs"
$regPath = "HKLM:\SOFTWARE\WSL2Shrinker"

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

    Write-Host $logMessage
}

try {
    Write-Log "========== WSL2 Disk Shrinker Uninstall Started =========="
    Write-Log "Running as: $env:USERNAME"

    if (Test-Path $regPath) {
        $lastRun = (Get-ItemProperty -Path $regPath -Name "LastRun" -ErrorAction SilentlyContinue).LastRun
        $lastSaved = (Get-ItemProperty -Path $regPath -Name "LastSpaceSavedMB" -ErrorAction SilentlyContinue).LastSpaceSavedMB

        Write-Log "Found existing installation:"
        Write-Log "  Last run: $lastRun"
        Write-Log "  Last space saved: $lastSaved MB"

        Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
        Write-Log "Registry key removed: $regPath"
    }
    else {
        Write-Log "Registry key not found (already uninstalled): $regPath"
    }

    Write-Log "========== WSL2 Disk Shrinker Uninstall Completed =========="
    exit 0
}
catch {
    Write-Log "Error during uninstall: $_" -Level Error
    Write-Log "========== WSL2 Disk Shrinker Uninstall Failed =========="
    exit 0  # Still return success - best effort uninstall
}
