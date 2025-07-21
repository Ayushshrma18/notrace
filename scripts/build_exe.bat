@echo off
title NoTrace - Build Executable
echo ===============================================
echo           NoTrace - Build Executable
echo ===============================================
echo.

REM Clean previous builds
echo Cleaning previous builds...
if exist "build" rmdir /s /q "build" 2>nul
if exist "dist\NoTrace.exe" del "dist\NoTrace.exe" 2>nul
echo.

REM Build the executable
echo Building NoTrace executable...
echo This may take a few minutes...
echo.

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m PyInstaller --onefile --windowed --name "NoTrace" --distpath "dist" "src\notrace_gui.py"
) else (
    python -m PyInstaller --onefile --windowed --name "NoTrace" --distpath "dist" "src\notrace_gui.py"
)

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Cleaning up build files...
    rmdir /s /q "build" 2>nul
    del "NoTrace.spec" 2>nul
    
    echo.
    echo ========================================
    echo           BUILD SUCCESSFUL!
    echo ========================================
    echo.
    echo NoTrace.exe has been created in dist\ folder.
    echo File size: ~14.6 MB
    echo.
    echo You can now:
    echo - Run dist\NoTrace.exe directly
    echo - Distribute this single file to others
    echo - No Python installation required on target machines
    echo.
) else (
    echo.
    echo ========================================
    echo             BUILD FAILED!
    echo ========================================
    echo Please check the error messages above.
    echo.
)

echo.
pause
