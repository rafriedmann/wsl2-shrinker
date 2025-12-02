<#
.SYNOPSIS
    Uninstalls WSL2 Shrinker by removing the registry detection key.
#>

$regPath = "HKLM:\SOFTWARE\WSL2Shrinker"

try {
    if (Test-Path $regPath) {
        Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
        Write-Host "WSL2Shrinker registry key removed."
    }
    else {
        Write-Host "WSL2Shrinker registry key not found (already uninstalled)."
    }
    exit 0
}
catch {
    Write-Host "Error removing registry key: $_"
    exit 0  # Still return success - best effort uninstall
}
