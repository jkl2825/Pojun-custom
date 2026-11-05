@echo off
REM Pojun disk guard - scheduled task entry (runs every 30 min via schtasks)
REM Real logic lives in ops/disk-guard.sh; this wrapper only switches to Git Bash.
REM Flags: --quiet (only print on alert), --auto-pause (pause tasks when disk >= 96%%)
"F:\Git\bin\bash.exe" -lc "cd '/c/Users/Administrator/WorkBuddy/2026-11-04-11-04-59/Pojun' && bash ops/disk-guard.sh --quiet --auto-pause"
exit /b %ERRORLEVEL%
