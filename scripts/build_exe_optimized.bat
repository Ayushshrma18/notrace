@echo off
title NoTrace v2.0 - Optimized Build
echo 🚀 Building Optimized NoTrace v2.0 Executable...
echo ================================================

REM Activate virtual environment
call .venv\Scripts\activate

REM Clean previous builds
if exist build rmdir /s /q build
if exist dist\NoTrace_v2_Optimized.exe del dist\NoTrace_v2_Optimized.exe

echo 🔧 Building with performance optimizations...

REM Build with optimizations for faster startup
python -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name NoTrace_v2_Optimized ^
    --optimize=2 ^
    --strip ^
    --noupx ^
    --exclude-module tkinter.dnd ^
    --exclude-module tkinter.scrolledtext ^
    --exclude-module tkinter.tix ^
    --exclude-module tkinter.ttk ^
    --exclude-module tkinter.constants ^
    --exclude-module unittest ^
    --exclude-module doctest ^
    --exclude-module pdb ^
    --exclude-module pydoc ^
    --exclude-module bdb ^
    --exclude-module inspect ^
    --exclude-module difflib ^
    --exclude-module test ^
    --exclude-module email ^
    --exclude-module xml ^
    --exclude-module urllib ^
    --exclude-module http ^
    --exclude-module html ^
    --exclude-module multiprocessing ^
    --hidden-import=cryptography.hazmat.primitives.asymmetric.rsa ^
    --hidden-import=cryptography.hazmat.primitives.asymmetric.padding ^
    --hidden-import=cryptography.hazmat.primitives.kdf.pbkdf2 ^
    --hidden-import=cryptography.hazmat.primitives.serialization ^
    --hidden-import=cryptography.hazmat.primitives.ciphers.algorithms ^
    --hidden-import=cryptography.hazmat.primitives.ciphers.modes ^
    --hidden-import=tkinter.simpledialog ^
    --hidden-import=tkinter.filedialog ^
    --hidden-import=tkinter.messagebox ^
    src/notrace_gui_v2.py

if %ERRORLEVEL% EQU 0 (
    echo ✅ Optimized build completed successfully!
    echo 📁 Location: dist\NoTrace_v2_Optimized.exe
    
    REM Show file size comparison
    if exist dist\NoTrace_v2.exe (
        echo 📊 Size Comparison:
        for %%f in (dist\NoTrace_v2.exe) do echo    Original: %%~zf bytes
        for %%f in (dist\NoTrace_v2_Optimized.exe) do echo    Optimized: %%~zf bytes
    )
) else (
    echo ❌ Build failed!
    pause
    exit /b 1
)

echo 🎉 NoTrace v2.0 Optimized is ready!
pause
