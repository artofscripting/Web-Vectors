@echo off
REM WebVectors Security Scanner - Windows Launcher
REM Usage: webvectors.bat [URL] [options]

if "%1"=="" (
    echo.
    echo WebVectors Security Scanner
    echo ===========================
    echo.
    echo Usage: %0 [URL] [options]
    echo.
    echo Examples:
    echo   %0 https://example.com
    echo   %0 https://example.com -v --open
    echo   %0 https://example.com -o my_report.html
    echo.
    echo For full help: %0 --help
    echo.
    pause
    goto :eof
)

REM Change to the directory containing the executable
cd /d "%~dp0dist"

REM Run WebVectors with all passed arguments
WebVectors.exe %*

REM Pause to see results if run from double-click
if "%2"=="" pause