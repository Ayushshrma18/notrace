@echo off
REM NoTrace Mobile APK Builder for Windows
REM This script requires Windows Subsystem for Linux (WSL) to be installed

echo 🚀 NoTrace Mobile APK Builder for Windows
echo ==========================================

echo.
echo ⚠️  PREREQUISITES:
echo    1. Windows Subsystem for Linux (WSL) must be installed
echo    2. Ubuntu or similar Linux distribution in WSL
echo.

set /p proceed="Do you have WSL installed? (y/n): "
if /i "%proceed%" neq "y" (
    echo.
    echo 📖 To install WSL:
    echo    1. Open PowerShell as Administrator
    echo    2. Run: wsl --install
    echo    3. Restart your computer
    echo    4. Run this script again
    pause
    exit /b
)

echo.
echo 📂 Copying files to WSL environment...

REM Copy mobile app files to WSL
wsl mkdir -p /home/%USERNAME%/notrace-mobile
wsl cp main.py /home/%USERNAME%/notrace-mobile/
wsl cp requirements.txt /home/%USERNAME%/notrace-mobile/
wsl cp buildozer.spec /home/%USERNAME%/notrace-mobile/
wsl cp build_apk.sh /home/%USERNAME%/notrace-mobile/

echo ✅ Files copied to WSL

echo.
echo 🏗️ Starting APK build process in WSL...
echo    This may take 20-30 minutes for the first build...

REM Execute the build script in WSL
wsl cd /home/%USERNAME%/notrace-mobile && chmod +x build_apk.sh && ./build_apk.sh

echo.
echo 📱 Copying APK back to Windows...
if exist "bin" rmdir /s /q bin
mkdir bin
wsl cp /home/%USERNAME%/notrace-mobile/bin/*.apk bin/ 2>nul

if exist "bin\*.apk" (
    echo ✅ APK successfully built and copied to bin folder!
    echo 📱 Install on Android device: 
    echo    1. Enable Developer Options and USB Debugging on your phone
    echo    2. Connect phone to computer
    echo    3. Run: adb install bin\NoTrace-2.0-arm64-v8a_armeabi-v7a-debug.apk
) else (
    echo ❌ APK build failed. Check the output above for errors.
)

echo.
pause
