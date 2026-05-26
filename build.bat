@echo off
REM ===================================================================
REM  Build NetScanner into a single standalone Windows .exe
REM
REM  Run this ONCE on your Windows machine. It produces:
REM      dist\NetScanner.exe
REM  which you can copy anywhere and run by double-clicking - no Python
REM  required on that machine.
REM
REM  Requires Python 3.8+ with internet access (to fetch PyInstaller).
REM ===================================================================
setlocal
cd /d "%~dp0"

set PY=python
where py >nul 2>nul && set PY=py

echo Installing PyInstaller (if needed)...
%PY% -m pip install --upgrade pyinstaller || goto :fail

echo.
echo Building NetScanner.exe ...
REM --add-data bundles the UI into the exe (Windows uses ; as the separator).
%PY% -m PyInstaller --onefile --name NetScanner --console --add-data "ui.html;." netscanner.py || goto :fail

echo.
echo ===================================================================
echo  Done!  Your standalone app is here:
echo     %~dp0dist\NetScanner.exe
echo ===================================================================
echo.
pause
goto :eof

:fail
echo.
echo  Build failed. Make sure Python and pip are installed and on PATH.
echo.
pause
