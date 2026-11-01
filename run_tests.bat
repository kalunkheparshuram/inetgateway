@echo off
rem Run the tests (GUI tests need a desktop session; Linux-only capture tests are skipped on Windows).
cd /d "%~dp0"
py -3 -m unittest discover -s tests -v
pause
