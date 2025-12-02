<p align="center">
  <img src="icon.svg" alt="WSL2 Shrinker Logo" width="150"/>
</p>

<h1 align="center">WSL2 Disk Shrinker</h1>

<p align="center">
  <strong>Because Tux doesn't need all that empty space!</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#intune-deployment">Intune Deployment</a> •
  <a href="#troubleshooting">Troubleshooting</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-blue?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/WSL-2-orange?style=flat-square" alt="WSL2"/>
  <img src="https://img.shields.io/badge/Intune-Ready-green?style=flat-square" alt="Intune Ready"/>
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square" alt="License"/>
</p>

---

## The Problem

WSL2 uses VHDX (Virtual Hard Disk) files that **grow automatically** as you use them, but **never shrink** when you delete files. Over time, these virtual disks can consume tens of gigabytes of unnecessary space on your drive.

**This tool fixes that** by automatically compacting all WSL2 VHDX files across all users on a machine.

## Features

- **Auto-discovery** - Finds all WSL2 distributions (Microsoft Store & custom installations)
- **Multi-user support** - Scans all user profiles when running as SYSTEM
- **Dual optimization** - Uses Hyper-V `Optimize-VHD` with `diskpart` fallback
- **Intune-ready** - Pre-packaged `.intunewin` file included
- **Detailed logging** - Full audit trail in `C:\ProgramData\WSL2Shrinker\Logs\`
- **Safe execution** - Gracefully handles edge cases and missing prerequisites
- **User notifications** - Toast notifications before/after optimization
- **Non-disruptive mode** - Option to skip if WSL is actively running
- **Grace period** - Configurable warning time before WSL shutdown (default: 30s)

## Quick Start

### Option 1: Download Pre-built Package
Download [`Install-WSL2Shrinker.intunewin`](output/Install-WSL2Shrinker.intunewin) and deploy via Intune.

### Option 2: Run Manually
```powershell
# Run as Administrator
.\Shrink-WSL2Distributions.ps1
```

### Option 3: Build Your Own Package
```cmd
IntuneWinAppUtil.exe -c ".\\" -s Install-WSL2Shrinker.ps1 -o ".\output"
```

---

## Intune Deployment

### Step 1: Download the Package

Download the pre-built package from this repository:
- [`output/Install-WSL2Shrinker.intunewin`](output/Install-WSL2Shrinker.intunewin)

Or build it yourself using the [Microsoft Win32 Content Prep Tool](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool).

### Step 2: Create Win32 App in Intune

1. Navigate to **Microsoft Intune admin center**
2. Go to **Apps** → **Windows** → **Add**
3. Select **Windows app (Win32)** and click **Select**

### Step 3: App Information

| Field | Value |
|-------|-------|
| Name | `WSL2 Disk Shrinker` |
| Description | `Automatically compacts WSL2 VHDX files to reclaim disk space. Runs silently and logs results.` |
| Publisher | `IT Department` |
| App Version | `1.0` |
| Category | `Computer Management` |
| Information URL | `https://github.com/rafriedmann/wsl2-shrinker` |
| Privacy URL | *(optional)* |
| Developer | *(optional)* |
| Owner | *(optional)* |
| Notes | `Reclaims unused disk space from WSL2 virtual disks` |
| Logo | Upload `icon.png` from this repository |

### Step 4: Program Settings

Choose ONE of the following install command options based on your needs:

#### Option A: User-Friendly Mode (Recommended)
Shows toast notification, gives user 30 seconds warning before WSL shutdown.
```
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File Install-WSL2Shrinker.ps1
```

#### Option B: Non-Disruptive Mode
Skips optimization if WSL is currently running. Will retry on next Intune sync.
```
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File Install-WSL2Shrinker.ps1 -SkipIfRunning
```

#### Option C: Silent Mode
No notifications, immediate shutdown. Use for off-hours deployment.
```
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File Install-WSL2Shrinker.ps1 -Silent
```

| Field | Value |
|-------|-------|
| Install command | *(Choose from options above)* |
| Uninstall command | `reg.exe delete "HKLM\SOFTWARE\WSL2Shrinker" /f` |
| Install behavior | **System** |
| Device restart behavior | **No specific action** |
| Return codes | Use defaults (0 = Success, 1707 = Success, 3010 = Soft reboot, 1641 = Hard reboot, 1618 = Retry) |

### Step 5: Requirements

| Field | Value |
|-------|-------|
| Operating system architecture | **64-bit** |
| Minimum operating system | **Windows 10 1903** |
| Disk space required | No |
| Physical memory required | No |
| Minimum number of logical processors | No |
| Minimum CPU speed required | No |

**Optional Requirement Script** (to only target devices with WSL installed):
```powershell
# Check if WSL is installed
if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
    Write-Output "WSL is installed"
    exit 0
} else {
    Write-Output "WSL is not installed"
    exit 1
}
```

### Step 6: Detection Rules

| Field | Value |
|-------|-------|
| Rules format | **Use a custom detection script** |
| Script file | Upload `Detect-WSL2Shrinker.ps1` |
| Run script as 32-bit process | **No** |
| Enforce script signature check | **No** |

The detection script checks if the tool ran within the last **30 days**. Modify `$MaxAgeDays` in the script to change this interval.

### Step 7: Dependencies & Supersedence

- **Dependencies**: None required
- **Supersedence**: None required

### Step 8: Assignments

Assign to your target groups:

| Assignment Type | Recommendation |
|-----------------|----------------|
| **Required** | Assign to device groups with developer machines |
| **Available** | Make available in Company Portal for self-service |
| **Exclude** | Exclude servers or machines without WSL |

**Recommended Filter** (optional):
```
(device.deviceOwnership -eq "Corporate") and (device.operatingSystemVersion -contains "10.0.1")
```

---

## Files Included

| File | Description |
|------|-------------|
| `Shrink-WSL2Distributions.ps1` | Main PowerShell script that performs the optimization |
| `Install-WSL2Shrinker.ps1` | Intune installer wrapper |
| `Detect-WSL2Shrinker.ps1` | Intune detection script (checks 30-day interval) |
| `output/Install-WSL2Shrinker.intunewin` | Pre-built Intune package |
| `icon.svg` / `icon.png` | Application icons |

---

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    WSL2 Disk Shrinker                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 🔍 Discover all WSL2 distributions                      │
│     └─ Registry scan + Package folder search                │
│                                                             │
│  2. 📁 Locate VHDX files                                    │
│     └─ %LOCALAPPDATA%\Packages\*\LocalState\ext4.vhdx      │
│     └─ Custom paths from HKCU/HKLM Lxss registry           │
│                                                             │
│  3. 🛑 Shutdown WSL                                         │
│     └─ wsl.exe --shutdown                                   │
│                                                             │
│  4. 📦 Compact each VHDX                                    │
│     └─ Primary: Optimize-VHD -Mode Full                     │
│     └─ Fallback: diskpart compact vdisk                     │
│                                                             │
│  5. 📝 Log results & set registry marker                    │
│     └─ HKLM:\SOFTWARE\WSL2Shrinker\LastRun                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Scheduling Options

### Option 1: Intune Re-evaluation (Recommended)

The detection script returns "not installed" after 30 days, triggering a reinstall:

```powershell
# In Detect-WSL2Shrinker.ps1
$MaxAgeDays = 30  # Change this value to adjust frequency
```

### Option 2: Scheduled Task

Deploy a separate scheduled task for more frequent execution:

```powershell
$Action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Scripts\Shrink-WSL2Distributions.ps1"
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
$Settings = New-ScheduledTaskSettingsSet -RunOnlyIfIdle -IdleDuration 00:10:00
Register-ScheduledTask -TaskName "WSL2 Disk Shrinker" -Action $Action `
    -Trigger $Trigger -Settings $Settings -User "SYSTEM" -RunLevel Highest
```

---

## Logging

**Log Location:** `C:\ProgramData\WSL2Shrinker\Logs\`

**Log Format:** `WSL2Shrinker_YYYYMMDD.log`

**Sample Log Output:**
```
[2024-01-15 10:30:00] [Info] ========== WSL2 Disk Shrinker Started ==========
[2024-01-15 10:30:00] [Info] Running as: SYSTEM
[2024-01-15 10:30:00] [Info] Elevated: True
[2024-01-15 10:30:01] [Info] Found 3 WSL2 distribution(s)
[2024-01-15 10:30:01] [Info]   - Ubuntu (State: Stopped, Version: 2)
[2024-01-15 10:30:01] [Info]   - Debian (State: Stopped, Version: 2)
[2024-01-15 10:30:01] [Info]   - docker-desktop-data (State: Stopped, Version: 2)
[2024-01-15 10:30:02] [Info] Found 3 VHDX file(s) to optimize
[2024-01-15 10:30:02] [Info] Total VHDX size before optimization: 45.32 GB
[2024-01-15 10:30:02] [Info] Shutting down WSL...
[2024-01-15 10:30:07] [Info] WSL shutdown complete
[2024-01-15 10:30:07] [Info] Processing: Ubuntu
[2024-01-15 10:30:07] [Info] Optimizing: C:\Users\john\AppData\Local\...\ext4.vhdx (Current size: 15.20 GB)
[2024-01-15 10:30:45] [Info] Optimization complete. New size: 8.50 GB (Saved: 6860.00 MB)
...
[2024-01-15 10:32:15] [Info] ========== Optimization Summary ==========
[2024-01-15 10:32:15] [Info] Total space saved: 18.45 GB
[2024-01-15 10:32:15] [Info] ========== WSL2 Disk Shrinker Completed ==========
```

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Windows 10 version 1903+ or Windows 11 |
| **WSL** | WSL2 (not WSL1) |
| **Privileges** | Administrator / SYSTEM |
| **Optimization Tool** | Hyper-V PowerShell module OR diskpart.exe |

### Enabling Hyper-V PowerShell Module (Recommended)

For best results, enable the Hyper-V PowerShell module:

```powershell
# Windows 10/11 Pro, Enterprise, Education
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell

# Or via DISM
DISM /Online /Enable-Feature /All /FeatureName:Microsoft-Hyper-V-Management-PowerShell
```

> **Note:** The script falls back to `diskpart` if Hyper-V is unavailable.

---

## Troubleshooting

### No VHDX files found

- Verify WSL2 is installed: `wsl --list --verbose`
- Ensure distributions are WSL **version 2** (not 1)
- Check if running as SYSTEM can access user profile directories

### Optimization failed

- Ensure WSL is completely shut down: `wsl --shutdown`
- Check if another process is locking the VHDX file
- Verify Hyper-V tools or diskpart are available
- Review logs: `C:\ProgramData\WSL2Shrinker\Logs\`

### Detection always fails

- Ensure script runs with admin rights to write registry
- Check registry: `HKLM:\SOFTWARE\WSL2Shrinker\LastRun`
- Verify system clock is correct

### Script runs but no space saved

- WSL2 disks may already be compact
- Run `wsl --shutdown` and manually delete unused files inside WSL first
- Consider running `fstrim` inside WSL before optimization:
  ```bash
  sudo fstrim -av
  ```

---

## License

MIT License - Feel free to use, modify, and distribute.

---

<p align="center">
  <sub>Made with 🐧 for IT admins tired of bloated VHDX files</sub>
</p>
