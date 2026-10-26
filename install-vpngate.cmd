@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
title VPN Gate Connect - Windows 11 Installer

:: Detect if double-clicked from File Explorer (`cmd.exe /c ...`)
set "VG_PAUSE_ON_EXIT=0"
echo !CMDCMDLINE! | findstr /i /c:"/c" >nul 2>&1 && set "VG_PAUSE_ON_EXIT=1"

set "VG_PS_SCRIPT=%~dp0install-vpngate.ps1"
if not exist "!VG_PS_SCRIPT!" (
    echo [-] Could not find install-vpngate.ps1 in "%~dp0"
    if "!VG_PAUSE_ON_EXIT!"=="1" pause
    exit /b 1
)

:: Request Administrator privileges via UAC if not already elevated
net session >nul 2>&1
if not "!ERRORLEVEL!"=="0" (
    echo [*] Requesting Administrator privileges via Windows UAC ...
    set "VG_FWD=%*"
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
        "$ps = $env:VG_PS_SCRIPT; $pause = ($env:VG_PAUSE_ON_EXIT -eq '1'); $raw = $env:VG_FWD; " ^
        "$scriptCmd = '& \"' + ($ps -replace '\"','`\"') + '\" ' + $raw; " ^
        "if ($pause) { $scriptCmd += '; Write-Host \"\"; Read-Host \"Press Enter to close\"' }; " ^
        "$bytes = [System.Text.Encoding]::Unicode.GetBytes($scriptCmd); " ^
        "$enc = [Convert]::ToBase64String($bytes); " ^
        "Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc)"
    exit /b !ERRORLEVEL!
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "!VG_PS_SCRIPT!" %*
set "EXIT_CODE=!ERRORLEVEL!"

if "!VG_PAUSE_ON_EXIT!"=="1" (
    echo.
    pause
)
exit /b !EXIT_CODE!
