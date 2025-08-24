@echo off
echo HexStrike AI Tools Checker - Improved Version
echo =============================================
echo.
echo This script will run the improved HexStrike Tools checker
echo Make sure you have Git Bash, WSL, or similar bash environment installed
echo.
echo Running improved script...
echo.

REM Try to run with bash if available
bash HexStrike.Tools.Improved.sh

REM If bash is not available, show instructions
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Bash not found! Please install one of the following:
    echo 1. Git Bash: https://git-scm.com/download/win
    echo 2. WSL (Windows Subsystem for Linux)
    echo 3. Cygwin
    echo.
    echo Or run the script in a Linux environment
    echo.
    pause
)
