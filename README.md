<p align="center">
  <img src="icon.svg" alt="WSL2 Shrinker Logo" width="150"/>
</p>

# WSL2 Disk Shrinker for Intune

> *Because Tux doesn't need all that empty space!*

Automatically shrinks WSL2 distribution VHDX files to reclaim disk space. Designed for deployment via Microsoft Intune.

## Files

| File | Purpose |
|------|---------|
| `Shrink-WSL2Distributions.ps1` | Main script that performs the optimization |
| `Install-WSL2Shrinker.ps1` | Intune installer wrapper |
| `Detect-WSL2Shrinker.ps1` | Intune detection script |

## How It Works

1. Enumerates all WSL2 distributions on the system
2. Locates VHDX files (virtual disks) for each distribution
3. Shuts down WSL completely
4. Compacts each VHDX using Hyper-V cmdlets or diskpart
5. Logs results and sets registry marker for detection

## Intune Deployment

### Package the App

1. Download the [Microsoft Win32 Content Prep Tool](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool)

2. Place all three scripts in a source folder (e.g., `C:\Source\WSL2Shrinker\`)

3. Create the `.intunewin` package:
   ```cmd
   IntuneWinAppUtil.exe -c "C:\Source\WSL2Shrinker" -s Install-WSL2Shrinker.ps1 -o "C:\Output"
   ```

### Configure in Intune

1. Go to **Microsoft Intune admin center** > **Apps** > **Windows** > **Add**

2. Select **Windows app (Win32)**

3. Upload the `.intunewin` file

4. **App Information**:
   - Name: `WSL2 Disk Shrinker`
   - Description: `Automatically shrinks WSL2 VHDX files to reclaim disk space`
   - Publisher: `IT Department`

5. **Program**:
   - Install command:
     ```
     powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File Install-WSL2Shrinker.ps1
     ```
   - Uninstall command:
     ```
     powershell.exe -Command "Remove-Item 'HKLM:\SOFTWARE\WSL2Shrinker' -Force -ErrorAction SilentlyContinue"
     ```
   - Install behavior: **System**
   - Device restart behavior: **No specific action**

6. **Requirements**:
   - Operating system architecture: **64-bit**
   - Minimum operating system: **Windows 10 1903** (or later)

7. **Detection Rules**:
   - Rules format: **Use a custom detection script**
   - Script file: Upload `Detect-WSL2Shrinker.ps1`
   - Run script as 32-bit process: **No**
   - Enforce script signature check: **No** (or Yes if signed)

8. **Assignments**:
   - Assign to appropriate device groups
   - Consider using a filter for devices with WSL installed

## Scheduled Execution

To run this periodically, you can either:

### Option 1: Redeploy via Intune
- The detection script checks if the last run was within 30 days
- Modify `$MaxAgeDays` in `Detect-WSL2Shrinker.ps1` to change frequency
- Intune will reinstall when detection fails

### Option 2: Scheduled Task (Alternative)
Deploy a scheduled task separately to run the script weekly/monthly.

## Logging

Logs are written to: `C:\ProgramData\WSL2Shrinker\Logs\`

Log files are named: `WSL2Shrinker_YYYYMMDD.log`

## Requirements

- Windows 10/11 with WSL2 enabled
- Administrator privileges
- One of the following for VHDX optimization:
  - Hyper-V PowerShell module (preferred)
  - diskpart.exe (fallback)

## Troubleshooting

### No VHDX files found
- Ensure WSL2 distributions are installed (not WSL1)
- Check if running as SYSTEM can access user profile directories

### Optimization failed
- Verify WSL is completely shut down
- Check if Hyper-V role/tools are installed
- Review logs in `C:\ProgramData\WSL2Shrinker\Logs\`

### Detection always fails
- Ensure script runs with admin rights to write registry key
- Check `HKLM:\SOFTWARE\WSL2Shrinker` for the LastRun value
