@echo off
setlocal
cd /d "%~dp0"
title IP Investigator - Build Windows Standalone

echo ============================================================
echo   IP Investigator - Gerador do EXE standalone para Windows
echo ============================================================
echo.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0packaging\windows\build_windows.ps1"
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" (
  echo BUILD FALHOU. Codigo: %RC%
  echo Revise a mensagem acima.
) else (
  echo BUILD CONCLUIDO.
  echo Arquivo: %~dp0dist\IP-Investigator.exe
)
echo.
pause
exit /b %RC%
