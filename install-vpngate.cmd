@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
title VPN Gate Connect - Windows 11 x64 Installer

:: Detect if double-clicked from File Explorer (`cmd.exe /c ...`)
set "VG_PAUSE_ON_EXIT=0"
echo !CMDCMDLINE! | findstr /i /c:"/c" >nul 2>&1 && set "VG_PAUSE_ON_EXIT=1"

set "VG_PS_SCRIPT=%~dp0install-vpngate.ps1"
if not exist "!VG_PS_SCRIPT!" (
    echo [-] Could not find install-vpngate.ps1 in "%~dp0"
    if "!VG_PAUSE_ON_EXIT!"=="1" pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "!VG_PS_SCRIPT!" %*
set "EXIT_CODE=!ERRORLEVEL!"

if "!VG_PAUSE_ON_EXIT!"=="1" (
    echo.
    pause
)
exit /b !EXIT_CODE!
