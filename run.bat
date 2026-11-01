@echo off
rem InetGateway launcher. For raw-socket capture, right-click this file and choose "Run as administrator".
cd /d "%~dp0"
where py >nul 2>nul && (py -3 inetgateway.py %* & goto :eof)
where python >nul 2>nul && (python inetgateway.py %* & goto :eof)
echo Python 3.12 or newer was not found. Install it from python.org and tick "Add python.exe to PATH".
pause
