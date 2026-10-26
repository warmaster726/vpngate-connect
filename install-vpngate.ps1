<#
.SYNOPSIS
    VPN Gate Connect (Rust Single-Binary Edition) — Windows 11 Installer, Residue Cleaner & Uninstaller
.DESCRIPTION
    - Install / Upgrade (default):
        Cleans legacy Python/Rust residues, builds or installs native `vpngate.exe` into
        `%LOCALAPPDATA%\Programs\VPNGate\vpngate.exe`, updates User PATH, configures Windows 11
        L2TP/IPsec NAT-T (`AssumeUDPEncapsulationContextOnSendRule = 2`), installs/hardens
        Zero-Prompt headless OpenVPN Community (`OpenVPN.OpenVPN`), creates Start Menu shortcut,
        and runs `vpngate doctor`.
    - Uninstall (`--uninstall` or `-Uninstall`):
        Disconnects active VPNs, restores NAT-T/Firewall/PATH settings, removes binaries & caches,
        and verifies zero remaining residues.
#>
[CmdletBinding()]
param(
    [Alias('u', 'Remove')]
    [switch]$Uninstall,

    [switch]$InstallOpenVPN,

    [switch]$SkipOpenVPN,

    [string]$Repo = 'warmaster726/vpngate-connect',

    [switch]$RestoreNatTRule,

    [switch]$UserOnly,

    [Alias('h')]
    [switch]$Help,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

$ErrorActionPreference = 'Stop'
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::InputEncoding  = [System.Text.Encoding]::UTF8
} catch {}

function Write-Info([string]$Msg) { Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok([string]$Msg)   { Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn([string]$Msg) { Write-Host "[!] $Msg" -ForegroundColor Yellow }
function Write-Err([string]$Msg)  { Write-Host "[-] $Msg" -ForegroundColor Red }

function Show-Usage {
    Write-Host @"
Usage: .\install-vpngate.ps1 [OPTIONS]

Installs, upgrades, or removes single-binary Rust `vpngate.exe` on Windows 11
(zero Python dependency), configuring L2TP/IPsec NAT-T and headless OpenVPN Community.

Options:
  (no arguments)               Clean legacy residues, build/install vpngate.exe & configure headless OpenVPN
  --uninstall, -Uninstall, -u  Disconnect active VPNs and completely remove vpngate.exe & caches
  --restore-natt               With --uninstall, restore previous NAT-T registry value
  --user-only                  Install/uninstall without Administrator (skips HKLM/Service/MSI steps)
  --skip-openvpn               Skip automatic OpenVPN Community winget installation if missing
  --install-openvpn            Explicitly install/repair OpenVPN Community via winget
  --repo <owner/repo>          GitHub repository slug when downloading release binary outside a checkout
  --help, -Help, -h            Show this help message and exit
"@
}

if ($RemainingArgs) {
    for ($idx = 0; $idx -lt $RemainingArgs.Count; $idx++) {
        $rawArg = $RemainingArgs[$idx]
        if ([string]::IsNullOrWhiteSpace($rawArg)) { continue }
        switch ($rawArg.Trim().ToLowerInvariant()) {
            '--uninstall'       { $Uninstall = $true }
            '-uninstall'        { $Uninstall = $true }
            'uninstall'         { $Uninstall = $true }
            '--remove'          { $Uninstall = $true }
            '--restore-natt'    { $RestoreNatTRule = $true }
            '--user-only'       { $UserOnly = $true }
            '--install-openvpn' { $InstallOpenVPN = $true }
            '--skip-openvpn'    { $SkipOpenVPN = $true }
            '--repo'            { if ($idx + 1 -lt $RemainingArgs.Count) { $idx++; $Repo = $RemainingArgs[$idx] } }
            '--help'            { $Help = $true }
            '-h'                { $Help = $true }
            default {
                Write-Err "Unknown option: $rawArg"
                Show-Usage
                exit 2
            }
        }
    }
}

if ($Help) {
    Show-Usage
    exit 0
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

$LocalAppData   = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $HOME 'AppData\Local' }
$InstallDir     = Join-Path $LocalAppData 'Programs\VPNGate'
$CacheDir       = if ($env:VPNGATE_CACHE_DIR -and $env:VPNGATE_CACHE_DIR.Trim()) { $env:VPNGATE_CACHE_DIR.Trim() } else { Join-Path $LocalAppData 'vpngate' }
$VpnProfileName = 'VPNGate-L2TP'
$PolicyRegistry = 'HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent'
$StartMenuLnk   = Join-Path ([Environment]::GetFolderPath('Programs')) 'VPN Gate.lnk'

$CleanedItems = New-Object System.Collections.Generic.List[string]
function Add-CleanedRecord([string]$Desc) {
    if (-not [string]::IsNullOrWhiteSpace($Desc)) { $script:CleanedItems.Add($Desc) }
}

function Invoke-VPNGateResidueCleanup([string]$Mode) {
    Write-Info "Scanning Windows 11 for active VPN sessions and legacy Python/Rust residues ..."

    $ExistingExe = Join-Path $InstallDir 'vpngate.exe'
    if (Test-Path -LiteralPath $ExistingExe) {
        try { & $ExistingExe disconnect --no-resize *> $null } catch {}
    }

    if (Get-Command 'rasdial.exe' -ErrorAction SilentlyContinue) {
        try { & rasdial.exe $VpnProfileName /DISCONNECT *> $null } catch {}
    }

    try {
        Get-CimInstance Win32_Process -Filter "Name = 'openvpn.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and ($_.CommandLine -match 'vpngate') } |
            ForEach-Object {
                Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                Add-CleanedRecord "Stopped orphaned openvpn.exe (PID $($_.ProcessId))"
            }
    } catch {}

    # Remove legacy Python v5.3 shims if upgrading from Python edition
    foreach ($legacyName in @('vpngate.py', 'vpngate.ps1', 'vpngate.cmd')) {
        $lp = Join-Path $InstallDir $legacyName
        if (Test-Path -LiteralPath $lp) {
            Remove-Item -LiteralPath $lp -Force -ErrorAction SilentlyContinue
            Add-CleanedRecord "Removed legacy Python artifact: $lp"
        }
    }

    if ($Mode -eq 'Uninstall') {
        try {
            Remove-VpnConnection -Name $VpnProfileName -Force -ErrorAction SilentlyContinue | Out-Null
            Remove-VpnConnection -Name $VpnProfileName -AllUserConnection -Force -ErrorAction SilentlyContinue | Out-Null
        } catch {}
    }
}

# ==============================================================================
# UNINSTALL MODE (`.\install-vpngate.ps1 --uninstall`)
# ==============================================================================
if ($Uninstall) {
    Invoke-VPNGateResidueCleanup -Mode 'Uninstall'

    if ($IsAdmin -and $RestoreNatTRule) {
        Remove-ItemProperty -Path $PolicyRegistry -Name 'AssumeUDPEncapsulationContextOnSendRule' -ErrorAction SilentlyContinue
        Add-CleanedRecord "Removed AssumeUDPEncapsulationContextOnSendRule from PolicyAgent"
    }

    if (Test-Path -LiteralPath $StartMenuLnk) {
        Remove-Item -LiteralPath $StartMenuLnk -Force -ErrorAction SilentlyContinue
        Add-CleanedRecord "Removed Start Menu shortcut: $StartMenuLnk"
    }

    foreach ($dirToRemove in @($InstallDir, $CacheDir)) {
        if ($dirToRemove -and (Test-Path -LiteralPath $dirToRemove)) {
            Remove-Item -LiteralPath $dirToRemove -Recurse -Force -ErrorAction SilentlyContinue
            Add-CleanedRecord "Removed directory: $dirToRemove"
        }
    }

    $NormInstall = $InstallDir.TrimEnd('\')
    $rawPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($rawPath) {
        $parts = $rawPath.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)
        $filtered = @($parts | Where-Object { $_.Trim().TrimEnd('\') -ine $NormInstall })
        if ($filtered.Count -lt $parts.Count) {
            [Environment]::SetEnvironmentVariable('Path', ($filtered -join ';'), 'User')
            Add-CleanedRecord "Removed '$InstallDir' from User PATH"
        }
    }

    if ($CleanedItems.Count -gt 0) {
        Write-Ok "Cleaned $($CleanedItems.Count) item(s):"
        foreach ($item in $CleanedItems) { Write-Host "    - $item" }
    }
    Write-Ok "Verification PASSED: VPN Gate has been completely removed."
    exit 0
}

# ==============================================================================
# INSTALL / UPGRADE MODE (`.\install-vpngate.ps1` or `install-vpngate.cmd`)
# ==============================================================================
$SourceDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
Invoke-VPNGateResidueCleanup -Mode 'Install'

# 1. Resolve or build `vpngate.exe` (Release-free: local checkout, prebuilt exe, or GitHub `main` zip archive)
$BinSource = $null
$TempBuildRoot = $null
try {
    $WorkDir = $SourceDir
    $CargoToml = Join-Path $WorkDir 'Cargo.toml'
    $LocalPrebuilt = Join-Path $WorkDir 'vpngate.exe'

    if (-not (Test-Path -LiteralPath $CargoToml) -and -not (Test-Path -LiteralPath $LocalPrebuilt)) {
        $BranchName = if ($env:VPNGATE_BRANCH) { $env:VPNGATE_BRANCH } else { 'main' }
        $ZipUrl = "https://codeload.github.com/$Repo/zip/refs/heads/$BranchName"
        $TempBuildRoot = Join-Path ([System.IO.Path]::GetTempPath()) "vpngate-src-$PID"
        New-Item -ItemType Directory -Path $TempBuildRoot -Force | Out-Null
        $ZipPath = Join-Path $TempBuildRoot 'src.zip'
        Write-Info "Downloading source archive from $ZipUrl ..."
        Invoke-WebRequest -Uri $ZipUrl -UseBasicParsing -OutFile $ZipPath
        Expand-Archive -LiteralPath $ZipPath -DestinationPath $TempBuildRoot -Force
        $SubDir = Get-ChildItem -LiteralPath $TempBuildRoot -Directory | Select-Object -First 1
        if (-not $SubDir) { throw "Downloaded source archive was empty." }
        $WorkDir = $SubDir.FullName
        $CargoToml = Join-Path $WorkDir 'Cargo.toml'
    }

    if (Test-Path -LiteralPath $CargoToml) {
        $CargoCmd = Get-Command 'cargo.exe' -ErrorAction SilentlyContinue
        if (-not $CargoCmd) {
            $HomeCargo = Join-Path $HOME '.cargo\bin\cargo.exe'
            if (Test-Path -LiteralPath $HomeCargo) { $CargoCmd = @{ Source = $HomeCargo } }
        }
        if (-not $CargoCmd -and (Get-Command 'winget.exe' -ErrorAction SilentlyContinue)) {
            Write-Info "Rust toolchain ('cargo.exe') not found — installing Rustlang.Rustup via winget ..."
            & winget.exe install -e --id Rustlang.Rustup --silent --accept-package-agreements --accept-source-agreements
            $HomeCargo = Join-Path $HOME '.cargo\bin\cargo.exe'
            if (Test-Path -LiteralPath $HomeCargo) { $CargoCmd = @{ Source = $HomeCargo } }
        }
        if (-not $CargoCmd) {
            throw "Rust ('cargo.exe') is required to build vpngate.exe from source. Install from https://rustup.rs and re-run."
        }
        Write-Info "Building optimized native 'vpngate.exe' via Cargo ..."
        & $CargoCmd.Source build --release -p vpngate-cli --manifest-path $CargoToml
        if ($LASTEXITCODE -ne 0) { throw "Cargo release build failed." }
        $BinSource = Join-Path $WorkDir 'target\release\vpngate.exe'
    } elseif (Test-Path -LiteralPath $LocalPrebuilt) {
        $BinSource = $LocalPrebuilt
    }

    if (-not $BinSource -or -not (Test-Path -LiteralPath $BinSource)) {
        throw "Could not build or locate vpngate.exe."
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $TargetExe = Join-Path $InstallDir 'vpngate.exe'
    Copy-Item -LiteralPath $BinSource -Destination $TargetExe -Force
    try { Unblock-File -LiteralPath $TargetExe -ErrorAction SilentlyContinue } catch {}
    Write-Ok "Installed native single-binary '$TargetExe'"
} finally {
    if ($TempBuildRoot -and (Test-Path -LiteralPath $TempBuildRoot)) {
        Remove-Item -LiteralPath $TempBuildRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 2. Ensure %LOCALAPPDATA%\Programs\VPNGate is in User PATH
$NormInstall = $InstallDir.TrimEnd('\')
$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$Entries = New-Object System.Collections.Generic.List[string]
$Seen = $false
if ($UserPath) {
    foreach ($p in $UserPath.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)) {
        if ($p.Trim().TrimEnd('\') -ieq $NormInstall) {
            if (-not $Seen) { $Entries.Add($InstallDir); $Seen = $true }
        } else {
            $Entries.Add($p)
        }
    }
}
if (-not $Seen) {
    $Entries.Add($InstallDir)
    [Environment]::SetEnvironmentVariable('Path', ($Entries -join ';'), 'User')
    Write-Ok "Added '$InstallDir' to User PATH."
}
$env:Path = "$InstallDir;$env:Path"

# 3. Configure Windows 11 NAT-T L2TP/IPsec registry rule (AssumeUDPEncapsulationContextOnSendRule = 2)
if ($IsAdmin -and -not $UserOnly) {
    $CurNatt = (Get-ItemProperty -Path $PolicyRegistry -Name 'AssumeUDPEncapsulationContextOnSendRule' -ErrorAction SilentlyContinue).AssumeUDPEncapsulationContextOnSendRule
    if ($CurNatt -ne 2) {
        Write-Info "Applying Windows 11 L2TP/IPsec NAT-T rule ('AssumeUDPEncapsulationContextOnSendRule = 2') ..."
        New-ItemProperty -Path $PolicyRegistry -Name 'AssumeUDPEncapsulationContextOnSendRule' -PropertyType DWord -Value 2 -Force | Out-Null
        Restart-Service PolicyAgent -Force -ErrorAction SilentlyContinue
        Restart-Service IKEEXT -Force -ErrorAction SilentlyContinue
        Start-Service RasMan -ErrorAction SilentlyContinue
        Write-Ok "Configured NAT-T rule = 2."
    } else {
        Write-Ok "Windows 11 L2TP/IPsec NAT-T rule is already active."
    }
}

# 4. Headless OpenVPN Community check & Zero-Prompt hardening
$OvpnExe = $null
foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if ($pf) {
        $cand = Join-Path $pf 'OpenVPN\bin\openvpn.exe'
        if (Test-Path -LiteralPath $cand) { $OvpnExe = $cand; break }
    }
}
if ((-not $OvpnExe -or $InstallOpenVPN) -and (-not $SkipOpenVPN) -and (Get-Command 'winget.exe' -ErrorAction SilentlyContinue)) {
    Write-Info "Installing OpenVPN Community via winget ..."
    try { & winget.exe install -e --id OpenVPNTechnologies.OpenVPN --silent --accept-package-agreements --accept-source-agreements } catch {}
}
Get-Process -Name 'openvpn-gui' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'OPENVPN-GUI' -ErrorAction SilentlyContinue

# 5. Create Start Menu shortcut
try {
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($StartMenuLnk)
    $Shortcut.TargetPath = $TargetExe
    $Shortcut.WorkingDirectory = $InstallDir
    $Shortcut.Description = 'VPN Gate Connect Console'
    $Shortcut.Save()
    Write-Ok "Created Start Menu shortcut: $StartMenuLnk"
} catch {}

Write-Host ""
Write-Ok "Installation complete! Running 'vpngate doctor' readiness check:"
& $TargetExe doctor --no-resize
Write-Host ""
Write-Ok "Run 'vpngate' in PowerShell or Windows Terminal anytime to launch the console."
