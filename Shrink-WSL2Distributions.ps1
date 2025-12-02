<#
.SYNOPSIS
    Shrinks all WSL2 distribution VHDX files to reclaim disk space.

.DESCRIPTION
    This script finds all WSL2 distributions, shuts down WSL, and compacts
    the virtual disk files (ext4.vhdx) to reclaim unused space.
    Designed for deployment via Microsoft Intune.

.PARAMETER LogPath
    Path to store log files. Default: C:\ProgramData\WSL2Shrinker\Logs

.PARAMETER Force
    Force optimization even if shutdown verification fails.

.PARAMETER SkipIfRunning
    Skip optimization if WSL is currently running (non-disruptive mode).
    Useful for Intune deployments where you don't want to interrupt users.

.PARAMETER NotifyUser
    Show Windows toast notification to user before and after optimization.

.PARAMETER ShutdownGracePeriod
    Seconds to wait after notifying user before shutting down WSL. Default: 30

.NOTES
    Author: IT Admin
    Version: 1.1
    Requires: Windows 10/11 with WSL2, Hyper-V PowerShell module or diskpart

    Intune Deployment:
    - Install command: powershell.exe -ExecutionPolicy Bypass -File Shrink-WSL2Distributions.ps1 -NotifyUser
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
    [switch]$Force,

    [Parameter()]
    [switch]$SkipIfRunning,

    [Parameter()]
    [switch]$NotifyUser,

    [Parameter()]
    [int]$ShutdownGracePeriod = 30
)

# Script configuration
$ErrorActionPreference = "Stop"
$Script:ExitCode = 0
$Script:SpaceSaved = 0

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

function Show-ToastNotification {
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet("Info", "Warning", "Success")]
        [string]$Type = "Info"
    )

    try {
        # Try BurntToast module first (if available)
        if (Get-Module -ListAvailable -Name BurntToast -ErrorAction SilentlyContinue) {
            Import-Module BurntToast -ErrorAction SilentlyContinue
            New-BurntToastNotification -Text $Title, $Message -ErrorAction SilentlyContinue
            return
        }

        # Fallback to Windows native toast notification
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

        $template = @"
<toast>
    <visual>
        <binding template="ToastText02">
            <text id="1">$Title</text>
            <text id="2">$Message</text>
        </binding>
    </visual>
</toast>
"@

        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml($template)

        $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("WSL2 Disk Shrinker")
        $notifier.Show($toast)
    }
    catch {
        # If toast fails, try balloon tip as last resort
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            $balloon = New-Object System.Windows.Forms.NotifyIcon
            $balloon.Icon = [System.Drawing.SystemIcons]::Information
            $balloon.BalloonTipTitle = $Title
            $balloon.BalloonTipText = $Message
            $balloon.Visible = $true
            $balloon.ShowBalloonTip(10000)
            Start-Sleep -Seconds 1
            $balloon.Dispose()
        }
        catch {
            Write-Log "Could not display notification: $Title - $Message" -Level Warning
        }
    }
}

function Test-WSLInstalled {
    # Method 1: Check if wsl.exe exists in common locations
    $wslPaths = @(
        "C:\Windows\System32\wsl.exe",
        "C:\Windows\SysWOW64\wsl.exe",
        "$env:SystemRoot\System32\wsl.exe"
    )

    foreach ($path in $wslPaths) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            Write-Log "WSL found: $path"
            return $true
        }
    }

    # Method 2: Check for VHDX files in C:\Users (hardcoded, works for SYSTEM)
    if (Test-Path "C:\Users") {
        $vhdxFiles = Get-ChildItem -Path "C:\Users" -Recurse -Filter "ext4.vhdx" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($vhdxFiles) {
            Write-Log "VHDX found: $($vhdxFiles.FullName)"
            return $true
        }
    }

    return $false
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-WSLRunning {
    <#
    .SYNOPSIS
        Checks if any WSL distribution is currently running
    #>
    $distributions = Get-WSLDistributions
    $running = $distributions | Where-Object { $_.State -eq "Running" }
    return @{
        IsRunning = ($null -ne $running -and $running.Count -gt 0)
        RunningDistros = $running
        AllDistros = $distributions
    }
}

function Get-WSLDistributions {
    <#
    .SYNOPSIS
        Gets all WSL2 distributions and their VHDX file paths
    #>

    $distributions = @()

    # Try wsl.exe first (works when running as user)
    $wslExe = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if (-not $wslExe) {
        $wslExe = "$env:SystemRoot\System32\wsl.exe"
    }

    if ($wslExe -and (Test-Path $wslExe -ErrorAction SilentlyContinue)) {
        $wslOutput = & $wslExe --list --verbose 2>&1
        if ($LASTEXITCODE -eq 0 -and $wslOutput) {
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
        }
    }

    # If running as SYSTEM and no distributions found via wsl.exe,
    # try to get info from registry (all users)
    if ($distributions.Count -eq 0) {
        Write-Log "WSL command not available or returned no results, scanning registry..."

        # Scan HKLM for WSL distributions
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss"
        if (Test-Path $regPath) {
            Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | ForEach-Object {
                $distroName = (Get-ItemProperty -Path $_.PSPath -Name DistributionName -ErrorAction SilentlyContinue).DistributionName
                $version = (Get-ItemProperty -Path $_.PSPath -Name Version -ErrorAction SilentlyContinue).Version

                if ($distroName -and $version -eq 2) {
                    $distributions += [PSCustomObject]@{
                        Name    = $distroName
                        State   = "Unknown"  # Can't determine state without wsl.exe
                        Version = "2"
                    }
                }
            }
        }

        # Also scan each user's registry hive
        $usersPath = Split-Path $env:USERPROFILE -Parent
        Get-ChildItem -Path $usersPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $ntUserDat = Join-Path $_.FullName "NTUSER.DAT"
            $userName = $_.Name

            # Try to load user hive if not already loaded
            $hivePath = "HKU:\$userName-WSLCheck"
            $hiveLoaded = $false

            try {
                if (Test-Path $ntUserDat) {
                    $null = reg load "HKU\$userName-WSLCheck" $ntUserDat 2>&1
                    $hiveLoaded = $true
                }
            }
            catch {
                # Hive might already be loaded or inaccessible
            }

            # Check both potentially loaded hive and standard HKU paths
            $userRegPaths = @(
                "Registry::HKU\$userName-WSLCheck\Software\Microsoft\Windows\CurrentVersion\Lxss",
                "Registry::HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Lxss"
            )

            foreach ($userRegPath in $userRegPaths) {
                if (Test-Path $userRegPath -ErrorAction SilentlyContinue) {
                    Get-ChildItem -Path $userRegPath -ErrorAction SilentlyContinue | ForEach-Object {
                        $distroName = (Get-ItemProperty -Path $_.PSPath -Name DistributionName -ErrorAction SilentlyContinue).DistributionName
                        $version = (Get-ItemProperty -Path $_.PSPath -Name Version -ErrorAction SilentlyContinue).Version

                        if ($distroName -and $version -eq 2) {
                            # Avoid duplicates
                            if ($distributions.Name -notcontains $distroName) {
                                $distributions += [PSCustomObject]@{
                                    Name    = $distroName
                                    State   = "Unknown"
                                    Version = "2"
                                }
                            }
                        }
                    }
                }
            }

            # Unload hive if we loaded it
            if ($hiveLoaded) {
                try {
                    [gc]::Collect()
                    $null = reg unload "HKU\$userName-WSLCheck" 2>&1
                }
                catch { }
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
    # Use C:\Users directly - $env:USERPROFILE is wrong for SYSTEM context
    if (Test-IsElevated -and (Test-Path "C:\Users")) {
        Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } |
            ForEach-Object {
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
        Shuts down all WSL instances with optional user notification
    #>
    param(
        [switch]$Notify,
        [int]$GracePeriod = 30
    )

    # Find wsl.exe
    $wslExe = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if (-not $wslExe) {
        $wslExe = "$env:SystemRoot\System32\wsl.exe"
        if (-not (Test-Path $wslExe)) {
            Write-Log "wsl.exe not found, cannot shut down WSL" -Level Warning
            return $true  # Continue anyway, VHDX files might still be accessible
        }
    }
    else {
        $wslExe = $wslExe.Source
    }

    # Check if WSL is running
    $wslStatus = Test-WSLRunning

    if ($wslStatus.IsRunning) {
        $runningNames = ($wslStatus.RunningDistros | ForEach-Object { $_.Name }) -join ", "
        Write-Log "WSL is currently running: $runningNames"

        if ($Notify) {
            Show-ToastNotification -Title "WSL2 Disk Optimizer" `
                -Message "WSL will shut down in $GracePeriod seconds to optimize disk space. Running: $runningNames" `
                -Type Warning

            Write-Log "Waiting $GracePeriod seconds before shutdown (grace period)..."
            Start-Sleep -Seconds $GracePeriod
        }
    }

    Write-Log "Shutting down WSL using: $wslExe"

    $result = & $wslExe --shutdown 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Warning during WSL shutdown: $result" -Level Warning
    }

    # Wait for WSL to fully shut down
    $maxWait = 30
    $waited = 0
    while ($waited -lt $maxWait) {
        Start-Sleep -Seconds 2
        $waited += 2

        $stillRunning = Test-WSLRunning
        if (-not $stillRunning.IsRunning) {
            Write-Log "WSL shutdown complete (took $waited seconds)"
            return $true
        }
        Write-Log "Waiting for WSL to shut down... ($waited/$maxWait seconds)"
    }

    # Final check
    $finalCheck = Test-WSLRunning
    if ($finalCheck.IsRunning) {
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
            $Script:SpaceSaved += $savedSpace
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
        $Script:SpaceSaved += $savedSpace
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
    param(
        [long]$SpaceSaved = 0
    )

    $regPath = "HKLM:\SOFTWARE\WSL2Shrinker"

    try {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }

        Set-ItemProperty -Path $regPath -Name "LastRun" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Set-ItemProperty -Path $regPath -Name "Version" -Value "1.1"
        Set-ItemProperty -Path $regPath -Name "LastSpaceSavedMB" -Value ([math]::Round($SpaceSaved / 1MB, 2))

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
    Write-Log "Parameters: Force=$Force, SkipIfRunning=$SkipIfRunning, NotifyUser=$NotifyUser"

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

    # Check if WSL is running and handle SkipIfRunning mode
    $wslStatus = Test-WSLRunning

    if ($wslStatus.IsRunning -and $SkipIfRunning) {
        $runningNames = ($wslStatus.RunningDistros | ForEach-Object { $_.Name }) -join ", "
        Write-Log "WSL is currently running ($runningNames). SkipIfRunning is enabled - exiting without optimization." -Level Warning

        if ($NotifyUser) {
            Show-ToastNotification -Title "WSL2 Disk Optimizer - Skipped" `
                -Message "Disk optimization skipped because WSL is in use. Will retry later." `
                -Type Info
        }

        $Script:ExitCode = 0  # Not an error - just skipped
        exit $Script:ExitCode
    }

    # Get current distributions
    $distributions = Get-WSLDistributions
    Write-Log "Found $($distributions.Count) WSL2 distribution(s)"

    foreach ($distro in $distributions) {
        $stateIcon = if ($distro.State -eq "Running") { "[RUNNING]" } else { "[Stopped]" }
        Write-Log "  - $($distro.Name) $stateIcon (Version: $($distro.Version))"
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

    # Notify user if enabled
    if ($NotifyUser) {
        Show-ToastNotification -Title "WSL2 Disk Optimizer Starting" `
            -Message "Optimizing $($vhdxFiles.Count) virtual disk(s). WSL will be temporarily shut down." `
            -Type Info
    }

    # Shut down WSL
    if (-not (Stop-WSL -Notify:$NotifyUser -GracePeriod $ShutdownGracePeriod)) {
        if (-not $Force) {
            Write-Log "Failed to shut down WSL. Use -Force to attempt optimization anyway." -Level Error

            if ($NotifyUser) {
                Show-ToastNotification -Title "WSL2 Disk Optimizer - Failed" `
                    -Message "Could not shut down WSL. Optimization cancelled." `
                    -Type Warning
            }

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

    # Notify user of completion
    if ($NotifyUser) {
        $savedGB = [math]::Round($totalSaved / 1GB, 2)
        if ($totalSaved -gt 0) {
            Show-ToastNotification -Title "WSL2 Disk Optimizer Complete" `
                -Message "Optimization finished! Reclaimed $savedGB GB of disk space." `
                -Type Success
        }
        else {
            Show-ToastNotification -Title "WSL2 Disk Optimizer Complete" `
                -Message "Optimization finished. Disks were already compact - no space reclaimed." `
                -Type Info
        }
    }

    # Set registry marker for Intune detection
    if (Test-IsElevated) {
        Set-RegistryMarker -SpaceSaved $totalSaved
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

    if ($NotifyUser) {
        Show-ToastNotification -Title "WSL2 Disk Optimizer - Error" `
            -Message "An error occurred during optimization. Check logs for details." `
            -Type Warning
    }

    $Script:ExitCode = 1
}
finally {
    exit $Script:ExitCode
}

#endregion Main Execution
