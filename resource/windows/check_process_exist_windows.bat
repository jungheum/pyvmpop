@echo off
set pid=%1
tasklist /FI "PID eq %pid%" 2>NUL | findstr /i %pid% > NUL
echo %ERRORLEVEL%
