<#
.SYNOPSIS
    VPN Gate Connect (Rust Single-Binary Edition) - Windows 11 Installer, Residue Cleaner & Uninstaller
.DESCRIPTION
    - Install / Upgrade (default):
        Cleans legacy Python/Rust residues, builds or installs native `vpngate.exe` into
        `%LOCALAPPDATA%\Programs\VPNGate\vpngate.exe` using an isolated temporary build root,
        wipes all temporary Cargo/source/toolchain staging artifacts, updates User PATH,
        configures Windows 11 L2TP/IPsec NAT-T (`AssumeUDPEncapsulationContextOnSendRule = 2`),
        installs/hardens Zero-Prompt headless OpenVPN Community (`OpenVPN.OpenVPN`), creates
        Start Menu shortcut, verifies host environment cleanliness, and runs `vpngate doctor`.
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

    [switch]$KeepToolchain,

    [string]$Repo = 'warmaster726/vpngate-connect',

    [switch]$RestoreNatTRule,

    [switch]$UserOnly,

    [switch]$ElevatedChild,

    [string]$TargetInstallDir = '',

    [string]$TargetCacheDir = '',

    [string]$TargetStartMenuLnk = '',

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
(zero Python dependency), configuring L2TP/IPsec NAT-T and headless OpenVPN Community
while keeping the host environment free of temporary build caches.

Options:
  (no arguments)               Clean legacy residues, build/install vpngate.exe, wipe temp build cache & configure OpenVPN
  --uninstall, -Uninstall, -u  Disconnect active VPNs and completely remove vpngate.exe & caches
  --restore-natt               With --uninstall, restore previous NAT-T registry value
  --user-only                  Install/uninstall without Administrator (skips HKLM/Service/MSI steps)
  --skip-openvpn               Skip automatic OpenVPN Community winget installation if missing
  --install-openvpn            Explicitly install/repair OpenVPN Community via winget
  --keep-toolchain             If Rust (`cargo.exe`) must be bootstrapped on a clean PC, keep `.rustup` & `.cargo`
  --repo <owner/repo>          GitHub repository slug when downloading source archive outside a checkout
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
            '--keep-toolchain'  { $KeepToolchain = $true }
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
$InstallDir     = if ($TargetInstallDir -and $TargetInstallDir.Trim()) { $TargetInstallDir.Trim() } else { Join-Path $LocalAppData 'Programs\VPNGate' }
$CacheDir       = if ($TargetCacheDir -and $TargetCacheDir.Trim()) { $TargetCacheDir.Trim() } elseif ($env:VPNGATE_CACHE_DIR -and $env:VPNGATE_CACHE_DIR.Trim()) { $env:VPNGATE_CACHE_DIR.Trim() } else { Join-Path $LocalAppData 'vpngate' }
$VpnProfileName = 'VPNGate-L2TP'
$OvpnFwInRule   = 'VPNGate-OpenVPN-In'
$OvpnFwOutRule  = 'VPNGate-OpenVPN-Out'
$PolicyRegistry = 'HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent'
$StartMenuLnk   = if ($TargetStartMenuLnk -and $TargetStartMenuLnk.Trim()) { $TargetStartMenuLnk.Trim() } else { Join-Path ([Environment]::GetFolderPath('Programs')) 'VPN Gate.lnk' }

# Automatically elevate via Windows UAC when invoked from a non-Admin PowerShell session
if ((-not $IsAdmin) -and (-not $UserOnly) -and (-not $ElevatedChild) -and $PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) {
    Write-Info "Administrator privileges are required on Windows 11 for NAT-T, OpenVPN & Firewall setup."
    Write-Info "Requesting Windows UAC elevation ..."
    $PsHostExe = if ($PSVersionTable.PSEdition -eq 'Core' -and (Get-Command 'pwsh.exe' -ErrorAction SilentlyContinue)) {
        (Get-Command 'pwsh.exe').Source
    } else {
        Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    $CallerWorkDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $FwdArgs = New-Object System.Collections.Generic.List[string]
    $FwdArgs.Add('-NoProfile')
    $FwdArgs.Add('-ExecutionPolicy')
    $FwdArgs.Add('Bypass')
    $FwdArgs.Add('-File')
    $FwdArgs.Add($PSCommandPath)
    $FwdArgs.Add('-ElevatedChild')
    $FwdArgs.Add('-TargetInstallDir')
    $FwdArgs.Add($InstallDir)
    $FwdArgs.Add('-TargetCacheDir')
    $FwdArgs.Add($CacheDir)
    $FwdArgs.Add('-TargetStartMenuLnk')
    $FwdArgs.Add($StartMenuLnk)
    if ($Uninstall)       { $FwdArgs.Add('-Uninstall') }
    if ($RestoreNatTRule) { $FwdArgs.Add('-RestoreNatTRule') }
    if ($InstallOpenVPN)  { $FwdArgs.Add('-InstallOpenVPN') }
    if ($SkipOpenVPN)     { $FwdArgs.Add('-SkipOpenVPN') }
    if ($KeepToolchain)   { $FwdArgs.Add('-KeepToolchain') }
    if ($Repo)            { $FwdArgs.Add('-Repo'); $FwdArgs.Add($Repo) }

    try {
        $ElevProc = Start-Process -FilePath $PsHostExe -ArgumentList $FwdArgs.ToArray() -WorkingDirectory $CallerWorkDir -Verb RunAs -Wait -PassThru
    } catch {
        Write-Err "Windows UAC elevation was cancelled or blocked ($($_.Exception.Message))."
        Write-Host "    Right-click PowerShell -> 'Run as Administrator' and re-run .\install-vpngate.ps1" -ForegroundColor Yellow
        Write-Host "    (or pass --user-only to skip HKLM/NAT-T/Firewall steps)." -ForegroundColor DarkGray
        exit 1
    }

    $ElevExit = if ($null -ne $ElevProc) { $ElevProc.ExitCode } else { 1 }
    $NormCallerInstall = $InstallDir.TrimEnd('\')
    if ($ElevExit -eq 0) {
        if ($Uninstall) {
            $uRaw = [Environment]::GetEnvironmentVariable('Path', 'User')
            if ($uRaw) {
                $uParts = $uRaw.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)
                $uFilt = @($uParts | Where-Object { $_.Trim().TrimEnd('\') -ine $NormCallerInstall })
                if ($uFilt.Count -lt $uParts.Count) {
                    [Environment]::SetEnvironmentVariable('Path', ($uFilt -join ';'), 'User')
                }
            }
            $env:Path = (($env:Path -split ';') | Where-Object { $_ -and ($_.Trim().TrimEnd('\') -ine $NormCallerInstall) }) -join ';'
            Write-Ok "VPN Gate has been completely uninstalled."
        } else {
            $uRaw = [Environment]::GetEnvironmentVariable('Path', 'User')
            $uSeen = $false
            if ($uRaw) {
                foreach ($entry in $uRaw.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)) {
                    if ($entry.Trim().TrimEnd('\') -ieq $NormCallerInstall) { $uSeen = $true; break }
                }
            }
            if (-not $uSeen) {
                $newUserPath = if ($uRaw) { "$uRaw;$InstallDir" } else { $InstallDir }
                [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
            }
            if ($env:Path -notlike "*$NormCallerInstall*") {
                $env:Path = "$InstallDir;$env:Path"
            }
            Write-Ok "Installation complete! Run 'vpngate' anytime to launch the console."
        }
    } else {
        Write-Err "Elevated installer exited with code $ElevExit."
    }
    exit $ElevExit
}

$CleanedItems = New-Object System.Collections.Generic.List[string]
function Add-CleanedRecord([string]$Desc) {
    if (-not [string]::IsNullOrWhiteSpace($Desc)) { $script:CleanedItems.Add($Desc) }
}

function Invoke-VPNGateResidueCleanup([string]$Mode) {
    Write-Info "Scanning Windows 11 for active VPN sessions and legacy Python/Rust residues ..."

    $ExistingExe = Join-Path $InstallDir 'vpngate.exe'
    if ($IsAdmin -and (Test-Path -LiteralPath $ExistingExe)) {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { & $ExistingExe --uac-elevated --cache-dir $CacheDir disconnect --no-resize *> $null } catch {}
        $ErrorActionPreference = $prevEap
    }

    if (Get-Command 'rasdial.exe' -ErrorAction SilentlyContinue) {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { & rasdial.exe $VpnProfileName /DISCONNECT *> $null } catch {}
        $ErrorActionPreference = $prevEap
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
            if ($IsAdmin) {
                Remove-VpnConnection -Name $VpnProfileName -AllUserConnection -Force -ErrorAction SilentlyContinue | Out-Null
            }
        } catch {}
        if ($IsAdmin) {
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            foreach ($fwRule in @($OvpnFwInRule, $OvpnFwOutRule, 'VPNGate-IPv6-Guard')) {
                try { & netsh.exe advfirewall firewall delete rule "name=$fwRule" *> $null } catch {}
            }
            $ErrorActionPreference = $prevEap
        }
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

# 1. Resolve or build `vpngate.exe` inside an isolated temporary root so zero build bloat remains
$BinSource = $null
$TargetExe = Join-Path $InstallDir 'vpngate.exe'
$TempInstallRoot = Join-Path ([System.IO.Path]::GetTempPath()) "vpngate-install-$PID"
$HadLocalTarget = Test-Path -LiteralPath (Join-Path $SourceDir 'target')
$CallerCargoTargetDir = $env:CARGO_TARGET_DIR
$OrigRustupHome = $env:RUSTUP_HOME
$OrigCargoHome = $env:CARGO_HOME
$HadExistingCargo = $false
$UsedEphemeralRustup = $false

New-Item -ItemType Directory -Path $TempInstallRoot -Force | Out-Null

try {
    $WorkDir = $SourceDir
    $CargoToml = Join-Path $WorkDir 'Cargo.toml'
    $LocalPrebuilt = Join-Path $WorkDir 'vpngate.exe'

    if (-not (Test-Path -LiteralPath $CargoToml) -and -not (Test-Path -LiteralPath $LocalPrebuilt)) {
        $BranchName = if ($env:VPNGATE_BRANCH) { $env:VPNGATE_BRANCH } else { 'main' }
        $ZipUrl = "https://codeload.github.com/$Repo/zip/refs/heads/$BranchName"
        $SrcStageDir = Join-Path $TempInstallRoot 'src'
        New-Item -ItemType Directory -Path $SrcStageDir -Force | Out-Null
        $ZipPath = Join-Path $SrcStageDir 'src.zip'
        Write-Info "Downloading source archive from $ZipUrl ..."
        Invoke-WebRequest -Uri $ZipUrl -UseBasicParsing -OutFile $ZipPath
        Expand-Archive -LiteralPath $ZipPath -DestinationPath $SrcStageDir -Force
        Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
        $SubDir = Get-ChildItem -LiteralPath $SrcStageDir -Directory | Select-Object -First 1
        if (-not $SubDir) { throw "Downloaded source archive was empty." }
        $WorkDir = $SubDir.FullName
        $CargoToml = Join-Path $WorkDir 'Cargo.toml'
    }

    if (Test-Path -LiteralPath $CargoToml) {
        $DefaultCargoBinDir = Join-Path $HOME '.cargo\bin'
        if ((Test-Path -LiteralPath (Join-Path $DefaultCargoBinDir 'cargo.exe')) -and ($env:Path -notlike "*$DefaultCargoBinDir*")) {
            $env:Path = "$DefaultCargoBinDir;$env:Path"
        }

        # Detect whether Visual Studio C++ Build Tools (MSVC cl.exe/link.exe) are present;
        # if not, use lightweight MinGW-w64 (`x86_64-pc-windows-gnu`) so users never need a 6 GB Visual Studio install.
        $HasMsvc = $false
        if (Get-Command 'cl.exe' -ErrorAction SilentlyContinue) {
            $HasMsvc = $true
        } else {
            $VsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
            if (Test-Path -LiteralPath $VsWhere) {
                $VsVc = & $VsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
                if ($VsVc) { $HasMsvc = $true }
            }
        }

        $CargoCmd = Get-Command 'cargo.exe' -ErrorAction SilentlyContinue
        if ($CargoCmd) {
            $HadExistingCargo = $true
        } else {
            $RustupInit = Join-Path $TempInstallRoot 'rustup-init.exe'
            $DefaultHost = if ($HasMsvc) { 'x86_64-pc-windows-msvc' } else { 'x86_64-pc-windows-gnu' }
            Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -UseBasicParsing -OutFile $RustupInit

            if ($KeepToolchain) {
                Write-Info "Rust toolchain not found - installing minimal Rust ($DefaultHost) via rustup.rs (--keep-toolchain) ..."
                & $RustupInit -y --profile minimal --default-host $DefaultHost
                $ActiveCargoBinDir = $DefaultCargoBinDir
            } else {
                $UsedEphemeralRustup = $true
                $env:RUSTUP_HOME = Join-Path $TempInstallRoot 'rustup'
                $env:CARGO_HOME  = Join-Path $TempInstallRoot 'cargo'
                New-Item -ItemType Directory -Path $env:RUSTUP_HOME -Force | Out-Null
                New-Item -ItemType Directory -Path $env:CARGO_HOME -Force | Out-Null
                Write-Info "Rust toolchain not found - bootstrapping ephemeral minimal Rust ($DefaultHost, auto-removed after build) ..."
                & $RustupInit -y --profile minimal --no-modify-path --default-host $DefaultHost
                $ActiveCargoBinDir = Join-Path $env:CARGO_HOME 'bin'
            }

            Remove-Item -LiteralPath $RustupInit -Force -ErrorAction SilentlyContinue
            if ($env:Path -notlike "*$ActiveCargoBinDir*") {
                $env:Path = "$ActiveCargoBinDir;$env:Path"
            }
            $CargoCmd = Get-Command 'cargo.exe' -ErrorAction SilentlyContinue
        }

        if (-not $CargoCmd) {
            throw "Rust ('cargo.exe') is required to build vpngate.exe from source. Install from https://rustup.rs and re-run."
        }

        $EffectiveTargetDir = if ($CallerCargoTargetDir -and $CallerCargoTargetDir.Trim()) {
            $CallerCargoTargetDir.Trim()
        } else {
            Join-Path $TempInstallRoot 'target'
        }

        $BuildArgs = @('build', '--release')
        if (Test-Path -LiteralPath (Join-Path $WorkDir 'Cargo.lock')) {
            $BuildArgs += '--locked'
        }
        $BuildArgs += @('-p', 'vpngate-cli', '--manifest-path', $CargoToml, '--target-dir', $EffectiveTargetDir)

        if ($HasMsvc) {
            Write-Info "Building optimized native 'vpngate.exe' via Cargo (MSVC toolchain) ..."
            & $CargoCmd.Source @BuildArgs
            if ($LASTEXITCODE -ne 0) { throw "Cargo release build failed." }
            $BinSource = Join-Path $EffectiveTargetDir 'release\vpngate.exe'
        } else {
            # Ensure gcc.exe / MinGW-w64 is present for `x86_64-pc-windows-gnu` (`ring` C objects + linking)
            if (-not (Get-Command 'gcc.exe' -ErrorAction SilentlyContinue)) {
                foreach ($candGccDir in @(
                    "$env:LOCALAPPDATA\Microsoft\WinGet\Packages",
                    'C:\msys64\ucrt64\bin',
                    'C:\msys64\mingw64\bin',
                    'C:\mingw64\bin'
                )) {
                    if (Test-Path -LiteralPath $candGccDir) {
                        $foundGcc = Get-ChildItem -LiteralPath $candGccDir -Filter 'gcc.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($foundGcc) {
                            $env:Path = "$($foundGcc.DirectoryName);$env:Path"
                            break
                        }
                    }
                }
            }
            if (-not (Get-Command 'gcc.exe' -ErrorAction SilentlyContinue) -and (Get-Command 'winget.exe' -ErrorAction SilentlyContinue)) {
                Write-Info "MSVC linker not present - installing lightweight MinGW-w64 ('gcc.exe') via winget ..."
                & winget.exe install -e --id BrechtSanders.WinLibs.POSIX.UCRT --silent --accept-package-agreements --accept-source-agreements
                $foundGcc = Get-ChildItem -LiteralPath "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Filter 'gcc.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($foundGcc) {
                    $env:Path = "$($foundGcc.DirectoryName);$env:Path"
                }
            }
            $RustupDir = Split-Path -Parent $CargoCmd.Source
            $RustupExe = Join-Path $RustupDir 'rustup.exe'
            if (Test-Path -LiteralPath $RustupExe) {
                & $RustupExe toolchain install stable-x86_64-pc-windows-gnu --profile minimal --no-self-update
            }
            Write-Info "Building optimized native 'vpngate.exe' via Cargo (x86_64-pc-windows-gnu toolchain) ..."
            $GnuArgs = @('+stable-x86_64-pc-windows-gnu') + $BuildArgs + @('--target', 'x86_64-pc-windows-gnu')
            & $CargoCmd.Source @GnuArgs
            if ($LASTEXITCODE -ne 0) { throw "Cargo GNU release build failed." }
            $BinSource = Join-Path $EffectiveTargetDir 'x86_64-pc-windows-gnu\release\vpngate.exe'
        }
    } elseif (Test-Path -LiteralPath $LocalPrebuilt) {
        $BinSource = $LocalPrebuilt
    }

    if (-not $BinSource -or -not (Test-Path -LiteralPath $BinSource)) {
        throw "Could not build or locate vpngate.exe."
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -LiteralPath $BinSource -Destination $TargetExe -Force
    try { Unblock-File -LiteralPath $TargetExe -ErrorAction SilentlyContinue } catch {}
    Write-Ok "Installed native single-binary '$TargetExe'"
} finally {
    $env:RUSTUP_HOME = $OrigRustupHome
    $env:CARGO_HOME  = $OrigCargoHome
    if ($UsedEphemeralRustup) {
        $EphBin = Join-Path (Join-Path $TempInstallRoot 'cargo') 'bin'
        $env:Path = (($env:Path -split ';') | Where-Object { $_ -and ($_.TrimEnd('\') -ine $EphBin.TrimEnd('\')) }) -join ';'
    }
    if ($TempInstallRoot -and (Test-Path -LiteralPath $TempInstallRoot)) {
        Remove-Item -LiteralPath $TempInstallRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Verify post-build host environment cleanliness
$PostCleanIssues = New-Object System.Collections.Generic.List[string]
if ($TempInstallRoot -and (Test-Path -LiteralPath $TempInstallRoot)) {
    $PostCleanIssues.Add($TempInstallRoot)
}
if ((-not $HadLocalTarget) -and (-not $CallerCargoTargetDir) -and (Test-Path -LiteralPath (Join-Path $SourceDir 'target'))) {
    $PostCleanIssues.Add((Join-Path $SourceDir 'target'))
}
if ((-not $HadExistingCargo) -and $UsedEphemeralRustup) {
    foreach ($ephUserDir in @((Join-Path $HOME '.rustup'), (Join-Path $HOME '.cargo'))) {
        if (Test-Path -LiteralPath $ephUserDir) { $PostCleanIssues.Add($ephUserDir) }
    }
}
if ($PostCleanIssues.Count -eq 0) {
    Write-Ok "Post-install cleanup verified: temporary build & staging artifacts removed (Windows environment clean)."
} else {
    Write-Warn "Post-install check noticed leftover temporary path(s): $($PostCleanIssues -join ', ')"
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
if ($env:Path -notlike "*$NormInstall*") {
    $env:Path = "$InstallDir;$env:Path"
}

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
$HeadlessMsiOverride = '/qn /norestart ADDLOCAL=OpenVPN,OpenVPN.Service,Drivers,Drivers.OvpnDco,Drivers.TAPWindows6 REMOVE=OpenVPN.GUI,OpenVPN.GUI.OnLogon'
$OvpnExe = $null
foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if ($pf) {
        $cand = Join-Path $pf 'OpenVPN\bin\openvpn.exe'
        if (Test-Path -LiteralPath $cand) { $OvpnExe = $cand; break }
    }
}
if ((-not $OvpnExe -or $InstallOpenVPN) -and (-not $SkipOpenVPN) -and (Get-Command 'winget.exe' -ErrorAction SilentlyContinue)) {
    Write-Info "Installing headless OpenVPN Community via winget ..."
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($IsAdmin) {
            & winget.exe install -e --id OpenVPNTechnologies.OpenVPN --silent --accept-package-agreements --accept-source-agreements --override $HeadlessMsiOverride
        } else {
            & winget.exe install -e --id OpenVPNTechnologies.OpenVPN --silent --accept-package-agreements --accept-source-agreements
        }
    } catch {}
    $ErrorActionPreference = $prevEap
    foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($pf) {
            $cand = Join-Path $pf 'OpenVPN\bin\openvpn.exe'
            if (Test-Path -LiteralPath $cand) { $OvpnExe = $cand; break }
        }
    }
}
Get-Process -Name 'openvpn-gui' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'OPENVPN-GUI' -ErrorAction SilentlyContinue
if ($IsAdmin) {
    foreach ($rk in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Software\Microsoft\Windows\CurrentVersion\Run')) {
        if (Test-Path -LiteralPath $rk) {
            Remove-ItemProperty -Path $rk -Name 'OPENVPN-GUI' -ErrorAction SilentlyContinue
        }
    }
    try {
        $nnKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff'
        if (-not (Test-Path -LiteralPath $nnKey)) { New-Item -Path $nnKey -Force | Out-Null }
    } catch {}
    if ($OvpnExe -and (Test-Path -LiteralPath $OvpnExe)) {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & netsh.exe advfirewall firewall delete rule "name=$OvpnFwInRule" *> $null
            & netsh.exe advfirewall firewall delete rule "name=$OvpnFwOutRule" *> $null
            & netsh.exe advfirewall firewall add rule "name=$OvpnFwInRule" dir=in action=allow "program=$OvpnExe" enable=yes profile=any *> $null
            & netsh.exe advfirewall firewall add rule "name=$OvpnFwOutRule" dir=out action=allow "program=$OvpnExe" enable=yes profile=any *> $null
            $TapCtl = Join-Path (Split-Path -Parent $OvpnExe) 'tapctl.exe'
            $ShowAd = (& $OvpnExe --show-adapters 2>&1 | Out-String)
            if ((Test-Path -LiteralPath $TapCtl) -and ($ShowAd -notmatch '(?im)\btap-windows6\b')) {
                & $TapCtl create --hwid 'root\tap0901' --name 'VPNGate TAP' *> $null
            }
        } catch {}
        $ErrorActionPreference = $prevEap
    }
}

# 5. Create Start Menu shortcut (configured with SLDF_RUNAS_USER so Start Menu launches elevated)
$WshShell = $null
$Shortcut = $null
try {
    $LnkParent = Split-Path -Parent $StartMenuLnk
    if ($LnkParent -and -not (Test-Path -LiteralPath $LnkParent)) {
        New-Item -ItemType Directory -Path $LnkParent -Force | Out-Null
    }
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($StartMenuLnk)
    $Shortcut.TargetPath = $TargetExe
    $Shortcut.WorkingDirectory = $InstallDir
    $Shortcut.Description = 'VPN Gate Connect Console'
    $Shortcut.Save()
    if (-not $UserOnly -and (Test-Path -LiteralPath $StartMenuLnk)) {
        $LnkBytes = [System.IO.File]::ReadAllBytes($StartMenuLnk)
        if ($LnkBytes.Length -gt 0x15) {
            $LnkBytes[0x15] = $LnkBytes[0x15] -bor 0x20
            [System.IO.File]::WriteAllBytes($StartMenuLnk, $LnkBytes)
        }
    }
    Write-Ok "Created Start Menu shortcut: $StartMenuLnk"
} catch {} finally {
    if ($Shortcut) { try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Shortcut) | Out-Null } catch {} }
    if ($WshShell) { try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($WshShell) | Out-Null } catch {} }
}

Write-Host ""
Write-Ok "Installation complete! Running 'vpngate doctor' readiness check:"
$prevEapDoc = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & $TargetExe --cache-dir $CacheDir doctor --no-resize
} finally {
    $ErrorActionPreference = $prevEapDoc
}
Write-Host ""
Write-Ok "Run 'vpngate' in PowerShell or Windows Terminal anytime to launch the console."
if ($ElevatedChild) {
    Start-Sleep -Seconds 2
}
