@echo off
rem Build dist\InetGateway.exe (one file, no console window, unsigned). Run from anywhere.
rem Needs: Python 3.9+ with pip. PyInstaller is installed from requirements-build.txt (pinned).
setlocal
cd /d "%~dp0\..\.."
py -3 -m pip install --quiet -r requirements-build.txt || goto :fail
py -3 -m PyInstaller --noconfirm --clean --onefile --noconsole --name InetGateway ^
  --icon packaging\icons\inetgateway.ico inetgateway.py || goto :fail
echo.
echo Built dist\InetGateway.exe  (not code-signed: Windows SmartScreen will warn on first run)
if not defined CI pause
exit /b 0
:fail
echo Build failed.
if not defined CI pause
exit /b 1
