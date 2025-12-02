<#
.SYNOPSIS
    Intune detection script for WSL2 Shrinker

.DESCRIPTION
    Checks if WSL2 Shrinker has run within the specified timeframe.
    Returns exit code 0 if detected (installed), 1 if not detected.

.NOTES
    Use this as the detection script in Intune Win32 app configuration.
    Adjust $MaxAgeDays to control how often the shrink operation should run.
#>

# Configuration: Consider "installed" if ran within this many days
$MaxAgeDays = 30

# Check registry marker
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
            Write-Host "WSL2 Shrinker last ran more than $MaxAgeDays days ago"
            exit 1  # Not detected - needs to run again
        }
    }
}

# Also check log file as fallback
$logPath = "$env:ProgramData\WSL2Shrinker\Logs"
if (Test-Path $logPath) {
    $latestLog = Get-ChildItem -Path $logPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($latestLog) {
        $daysSinceLog = (Get-Date) - $latestLog.LastWriteTime

        if ($daysSinceLog.Days -le $MaxAgeDays) {
            Write-Host "WSL2 Shrinker log found: $($latestLog.Name)"
            exit 0  # Detected
        }
    }
}

Write-Host "WSL2 Shrinker not detected or too old"
exit 1  # Not detected
