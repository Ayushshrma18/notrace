# NoTrace - Secure Message Encryption

![NoTrace](https://img.shields.io/badge/NoTrace-v2.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Android-lightgrey.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-green.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)
![Mobile](https://img.shields.io/badge/mobile-Android%20APK-green.svg)

## Overview
NoTrace is a modern, secure message encryption application that provides military-grade encryption with an intuitive user interface. Available for both desktop and mobile platforms, it features a sleek dark theme and offers multi-layer security with advanced encryption algorithms including AES-256-CBC, RSA, and ChaCha20 with PIN protection.

## 🚀 Features
- **🔐 Multi-Layer Security**: AES-256-CBC, RSA-2048, ChaCha20 encryption + 4-digit PIN protection
- **📱 Cross-Platform**: Desktop (Windows/macOS/Linux) + Mobile (Android APK)
- **🎨 Modern UI**: Beautiful dark theme with Material Design (mobile) and Helvetica fonts (desktop)
- **� File Encryption**: Encrypt/decrypt files of any type and size
- **🌐 Network Sharing**: Secure peer-to-peer message transmission
- **�👤 User-Friendly**: Simple tabs for encoding and decoding
- **🛡️ Secure**: SHA-256 hash verification for message integrity
- **📦 Portable**: Standalone executables available (Windows EXE + Android APK)
- **� Advanced Options**: Multiple encryption algorithms, key derivation, and secure random generation

## 📁 Project Structure
```
NoTrace/
├── src/                    # Desktop source code
│   ├── notrace.py         # Command-line version
│   └── notrace_gui.py     # Desktop GUI version
├── mobile/                 # Mobile Android app
│   ├── main.py            # Mobile app source
│   ├── requirements.txt   # Mobile dependencies
│   ├── buildozer.spec     # APK build config
│   ├── build_apk.sh       # Linux build script
│   ├── build_apk_windows.bat # Windows build script
│   └── README.md          # Mobile documentation
├── scripts/               # Build and utility scripts
│   ├── build_exe.bat     # Build desktop executable
│   ├── run_notrace.bat   # Run Python version
│   └── test_exe.bat      # Test executable
├── docs/                  # Documentation
│   └── DISTRIBUTION.md   # Distribution info
├── dist/                  # Built executables
│   ├── NoTrace.exe       # Windows executable
│   └── NoTrace.apk       # Android APK (after build)
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
- **Encryption Algorithms**: 
  - AES-256-CBC (Advanced Encryption Standard)
  - RSA-2048 (Asymmetric encryption)
  - ChaCha20 (Stream cipher)
- **Key Sizes**: 256-bit (AES), 2048-bit (RSA), 256-bit (ChaCha20)
- **PIN Protection**: 4-digit random PIN per message
- **Hash Functions**: SHA-256, SHA-512 for integrity verification
- **Key Derivation**: PBKDF2, Argon2 for password-based keys
- **Randomization**: Cryptographically secure random IV/nonce per encryption
- **File Support**: Any file type with chunked encryption for large files

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

### Option 1: Windows Desktop Executable (Recommended)
- **Download**: `dist/NoTrace.exe` (14.6 MB)
- **Run**: Double-click `NoTrace.exe`
- **Requirements**: None - works on any Windows system
- **Benefits**: No Python installation needed, portable

### Option 2: Android Mobile App
- **Download**: `mobile/bin/NoTrace.apk` (after building)
- **Requirements**: Android 7.0+ (API level 24+)
- **Build**: Use `mobile/build_apk_windows.bat` or `mobile/build_apk.sh`
- **Features**: Full encryption compatibility with desktop version

### Option 3: Python Version (Cross-Platform)
- **Requirements**: Python 3.7+ and dependencies
- **Install**: `pip install cryptography kivy kivymd` (for mobile features)
- **Run**: `python src/notrace_gui.py` or use `scripts/run_notrace.bat`

### Option 4: Build Your Own Executables
1. **Desktop**: Install requirements: `pip install cryptography pyinstaller`
2. **Desktop**: Run: `scripts/build_exe.bat` 
3. **Mobile**: Install WSL (Windows) or use Linux
4. **Mobile**: Run: `mobile/build_apk_windows.bat`
5. Find executables in `dist/` folder

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

### ✅ Completed Features (v2.0)
- [x] Multiple encryption algorithms (AES-256-CBC, RSA-2048, ChaCha20)
- [x] Mobile application (Android APK)
- [x] File encryption support
- [x] Enhanced security with multiple hash functions
- [x] Cross-platform compatibility (Windows/Android)

### 🚧 In Development (v2.1)
- [ ] Network communication features (P2P messaging)
- [ ] Key exchange protocols (Diffie-Hellman)
- [ ] Secure file sharing over network
- [ ] Group messaging with shared keys

### 🔮 Future Enhancements (v3.0+)
- [ ] Browser extension for web-based encryption
- [ ] iOS mobile application
- [ ] Hardware security module (HSM) support
- [ ] Quantum-resistant encryption algorithms
- [ ] Steganography features (hide messages in images)
- [ ] Multi-factor authentication (MFA)
- [ ] Encrypted voice/video calling
- [ ] Blockchain-based key verification
- [ ] Enterprise features (user management, audit logs)
- [ ] Integration with cloud storage providers

### 📱 Mobile Enhancements
- [ ] Biometric authentication (fingerprint/face unlock)
- [ ] QR code sharing for keys and messages
- [ ] Offline message queue
- [ ] Contact management system
- [ ] Message expiration/self-destruct
- [ ] Dark/light theme toggle
- [ ] Tablet optimization

### 🔒 Security Improvements
- [ ] Zero-knowledge architecture
- [ ] Perfect forward secrecy
- [ ] Secure key backup/recovery
- [ ] Advanced threat protection
- [ ] Side-channel attack resistance
- [ ] Formal security verification
- [ ] Bug bounty program

---
⭐ If you found this project helpful, please give it a star!
