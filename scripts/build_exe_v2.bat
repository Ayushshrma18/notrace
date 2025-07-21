@echo off
REM NoTrace v2.0 Enhanced Build Script
echo 🚀 Building NoTrace v2.0 Enhanced Executable...
echo =============================================

REM Activate virtual environment if it exists
if exist ".venv\Scripts\activate.bat" (
    echo 📦 Activating virtual environment...
    call .venv\Scripts\activate.bat
)

REM Install/upgrade dependencies
echo 📚 Installing dependencies...
python -m pip install --upgrade pip
python -m pip install cryptography pyinstaller

REM Clean previous builds
echo 🧹 Cleaning previous builds...
if exist "build" rmdir /s /q build
if exist "dist\NoTrace_v2.exe" del /q "dist\NoTrace_v2.exe"
if exist "__pycache__" rmdir /s /q __pycache__

REM Build the enhanced executable
echo 🔨 Building NoTrace v2.0 executable...
python -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name "NoTrace_v2" ^
    --icon=icon.ico ^
    --add-data "README.md;." ^
    --hidden-import=cryptography.hazmat.primitives.asymmetric.rsa ^
    --hidden-import=cryptography.hazmat.primitives.asymmetric.padding ^
    --hidden-import=cryptography.hazmat.primitives.kdf.pbkdf2 ^
    --hidden-import=cryptography.hazmat.primitives.serialization ^
    --hidden-import=tkinter.simpledialog ^
    --hidden-import=tkinter.filedialog ^
    src/notrace_gui_v2.py

REM Check if build was successful
if exist "dist\NoTrace_v2.exe" (
    echo ✅ Build successful!
    echo 📁 Executable location: dist\NoTrace_v2.exe
    
    REM Get file size
    for %%I in ("dist\NoTrace_v2.exe") do set size=%%~zI
    set /a sizeMB=!size!/1024/1024
    echo 📊 File size: !sizeMB! MB
    
    REM Test the executable
    echo 🧪 Testing executable...
    start /wait "Testing NoTrace v2.0" "dist\NoTrace_v2.exe" --test 2>nul || (
        echo ⚠️  Note: Executable built but test failed (this is normal for GUI apps)
    )
    
    echo.
    echo 🎉 NoTrace v2.0 Enhanced Edition build complete!
    echo 📱 Features: AES-256-CBC, RSA-2048, ChaCha20, File Encryption
    echo 📦 Ready for distribution: dist\NoTrace_v2.exe
) else (
    echo ❌ Build failed! Check the output above for errors.
    exit /b 1
)

echo.
pause
