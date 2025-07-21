@echo off
echo Testing NoTrace executable...
echo.

if not exist "dist\NoTrace.exe" (
    echo Error: NoTrace.exe not found in dist folder!
    echo Please run scripts\build_exe.bat first.
    pause
    exit /b 1
)

echo NoTrace.exe found in dist folder.
echo File size:
dir "dist\NoTrace.exe" | find "NoTrace.exe"
echo.

echo Starting NoTrace...
echo (Application will open in a new window)
echo.

start "" "dist\NoTrace.exe"

echo.
echo NoTrace has been launched successfully!
echo Check for the application window.
echo.
pause
