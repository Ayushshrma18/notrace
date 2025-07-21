# NoTrace - Secure Message Encryption

![NoTrace](https://img.shields.io/badge/NoTrace-v1.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-green.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)

## Overview
NoTrace is a modern, secure message encryption application that provides military-grade encryption with an intuitive user interface. Built with Python and featuring a sleek dark theme, it offers 2-layer security with AES-256-CBC encryption and PIN protection.

## 🚀 Features
- **🔐 2-Layer Security**: AES-256-CBC encryption + 4-digit PIN protection
- **🎨 Modern UI**: Beautiful dark theme with Helvetica fonts
- **👤 User-Friendly**: Simple tabs for encoding and decoding
- **🛡️ Secure**: SHA-256 hash verification for message integrity
- **🌍 Cross-Platform**: Works on Windows, macOS, and Linux
- **📦 Portable**: Standalone executable available

## 📁 Project Structure
```
NoTrace/
├── src/                    # Source code
│   ├── notrace.py         # Command-line version
│   └── notrace_gui.py     # GUI version
├── scripts/               # Build and utility scripts
│   ├── build_exe.bat     # Build executable
│   ├── run_notrace.bat   # Run Python version
│   └── test_exe.bat      # Test executable
├── docs/                  # Documentation
│   └── DISTRIBUTION.md   # Distribution info
├── dist/                  # Built executables
│   └── NoTrace.exe       # Standalone executable
├── README.md             # This file
└── .gitignore           # Git ignore rules
```

## 📸 Screenshots

### Main Interface
![NoTrace Interface](https://via.placeholder.com/800x600/0d1117/58a6ff?text=NoTrace+GUI+Interface)

### Encoding Process
![Encoding](https://via.placeholder.com/800x400/161b22/3fb950?text=Message+Encoding+Process)

### Decoding Process
![Decoding](https://via.placeholder.com/800x400/161b22/7dd3fc?text=Message+Decoding+Process)

## 🔒 Security Specifications
- **Encryption**: AES-256-CBC (Advanced Encryption Standard)
- **Key Size**: 256-bit (32 bytes) for maximum security
- **PIN Protection**: 4-digit random PIN per message
- **Hash Function**: SHA-256 for integrity verification
- **Randomization**: Cryptographically secure random IV per encryption

## 🎨 UI Improvements (Latest Version)
- **Professional Design**: GitHub-inspired dark theme
- **Enhanced Typography**: Helvetica font family throughout
- **Better Colors**: 
  - Primary: Deep space blue (#0d1117)
  - Secondary: Charcoal gray (#161b22)
  - Accent: Bright blue (#58a6ff)
  - Success: Green (#3fb950)
- **Improved UX**: 
  - Sectioned layouts with visual separation
  - Better spacing and padding
  - Enhanced button styling with hover effects
  - Emojis for better visual guidance
  - Detailed success/error messages

## 📝 How to Use

### Encoding a Message
1. Open the "🔐 Encode Message" tab
2. Type your message in the text area
3. Click "🔒 Encode Message"
4. Share the encryption key and PIN securely with recipient
5. Send the encoded message

### Decoding a Message
1. Open the "🔓 Decode Message" tab
2. Paste the encoded message
3. Enter the encryption key
4. Enter the 4-digit PIN
5. Click "🔓 Decode Message"

## Files
- `src/notrace.py` - Command-line version
- `src/notrace_gui.py` - GUI version with enhanced design
- `dist/NoTrace.exe` - Standalone executable (no Python required)
- `scripts/run_notrace.bat` - Windows launcher script for Python version
- `scripts/build_exe.bat` - Script to rebuild the executable

## 🚀 Installation & Launch

### Option 1: Standalone Executable (Recommended)
- **Download**: `dist/NoTrace.exe` (14.6 MB)
- **Run**: Double-click `NoTrace.exe`
- **Requirements**: None - works on any Windows system
- **Benefits**: No Python installation needed, portable

### Option 2: Python Version
- **Requirements**: Python 3.7+ and cryptography library
- **Install**: `pip install cryptography`
- **Run**: `python src/notrace_gui.py` or use `scripts/run_notrace.bat`

### Option 3: Build Your Own Executable
1. Install requirements: `pip install cryptography pyinstaller`
2. Run: `scripts/build_exe.bat` or `python -m PyInstaller --onefile --windowed src/notrace_gui.py`
3. Find executable in `dist/` folder

## Security Notes
- Always share keys and PINs through separate secure channels
- Each message generates a unique PIN for maximum security
- Messages are protected against tampering with hash verification
- No data is stored or transmitted - everything is local
- The executable is portable and works without installation

## Technical Details
- **Executable Size**: ~14.6 MB (includes Python runtime and dependencies)
- **Startup Time**: 2-3 seconds (loading embedded Python)
- **Memory Usage**: ~50-80 MB RAM
- **Compatibility**: Windows 7/8/10/11 (64-bit)
- **No Registry Changes**: Fully portable application

## 🤝 Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author
**Ayush Sharma** - [@Ayushshrma18](https://github.com/Ayushshrma18)

## 🙏 Acknowledgments
- Built with Python and tkinter
- Uses the `cryptography` library for secure encryption
- Inspired by modern security applications
- Thanks to the open-source community

## 📈 Roadmap
- [ ] Add more encryption algorithms (RSA, ChaCha20)
- [ ] File encryption support
- [ ] Network communication features
- [ ] Mobile application version
- [ ] Browser extension

---
⭐ If you found this project helpful, please give it a star!
