@echo off
title NoTrace - Secure Message Encryption
echo Starting NoTrace GUI...
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" "src\notrace_gui.py"
) else (
    python "src\notrace_gui.py"
)
pause
