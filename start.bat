@echo off
rem Camera Bridge launcher: double-click this file.
rem First run: creates the Python environment and installs the packages.
rem Every run: starts Camera Bridge. Extra options are passed on, e.g.  start.bat --fit crop
setlocal
cd /d "%~dp0"
title Camera Bridge

rem Reuse the environment if it works; rebuild it if Python was removed or updated.
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import sys" >nul 2>&1 && goto deps
    echo The Python environment is broken, rebuilding it...
    rmdir /s /q .venv
)

echo Setting up Camera Bridge for the first time (this takes a minute)...
set "PYCMD="
rem Python 3.10 - 3.14 (pyvirtualcam has no build for newer versions yet).
for %%v in (3.14 3.13 3.12 3.11 3.10) do (
    if not defined PYCMD (
        py -%%v -c "import sys" >nul 2>&1 && set "PYCMD=py -%%v"
    )
)
if not defined PYCMD (
    python -c "import sys; sys.exit(0 if (3, 10) <= sys.version_info[:2] <= (3, 14) else 1)" >nul 2>&1 && set "PYCMD=python"
)
if not defined PYCMD (
    echo.
    echo [X] Python 3.10 - 3.14 was not found.
    echo     Install Python 3.14 from https://www.python.org/downloads/
    echo     then run this file again.
    goto fail
)
echo Using: %PYCMD%
%PYCMD% -m venv .venv || goto fail

:deps
rem Install packages on first run, and again only when requirements.txt changes.
fc /b requirements.txt ".venv\requirements.installed" >nul 2>&1
if errorlevel 1 (
    echo Installing packages...
    ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt || goto fail
    copy /y requirements.txt ".venv\requirements.installed" >nul
)

".venv\Scripts\python.exe" camera_bridge.py %*
if errorlevel 1 goto fail
exit /b 0

:fail
echo.
echo Camera Bridge stopped with an error. Read the messages above.
pause
exit /b 1
