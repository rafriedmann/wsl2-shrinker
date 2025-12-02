<#
.SYNOPSIS
    Intune detection script for WSL2 Shrinker

.DESCRIPTION
    Checks if WSL2 Shrinker registry key exists.
    Returns exit code 0 if detected (installed), 1 if not detected.

.NOTES
    Use this as the detection script in Intune Win32 app configuration.
    Adjust $MaxAgeDays to control how often the shrink operation should run.
#>

# Configuration: Consider "installed" if ran within this many days
$MaxAgeDays = 30

# Check registry marker - this is the ONLY detection method
$regPath = "HKLM:\SOFTWARE\WSL2Shrinker"

if (Test-Path $regPath) {
    $lastRun = Get-ItemProperty -Path $regPath -Name "LastRun" -ErrorAction SilentlyContinue

    if ($lastRun.LastRun) {
        $lastRunDate = [DateTime]::Parse($lastRun.LastRun)
        $daysSinceRun = (Get-Date) - $lastRunDate

        if ($daysSinceRun.Days -le $MaxAgeDays) {
            Write-Host "WSL2 Shrinker last ran: $($lastRun.LastRun) ($([math]::Round($daysSinceRun.Days)) days ago)"
            exit 0  # Detected - installed
        }
        else {
            Write-Host "WSL2 Shrinker last ran more than $MaxAgeDays days ago - needs to run again"
            exit 1  # Not detected - needs to run again
        }
    }
}

Write-Host "WSL2 Shrinker registry key not found"
exit 1  # Not detected
