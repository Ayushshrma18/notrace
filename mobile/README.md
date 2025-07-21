# NoTrace Mobile - Android APK

This directory contains the mobile version of NoTrace built with Kivy and KivyMD for Android devices.

## 📱 Features

- **Same Encryption**: Uses identical AES-256-CBC + PIN protection as desktop version
- **Mobile-Optimized UI**: Touch-friendly interface with Material Design
- **Dark Theme**: Consistent with desktop version styling
- **Responsive Layout**: Adapts to different screen sizes
- **Offline Operation**: No internet required for encryption/decryption

## 🏗️ Building the APK

### Option 1: Windows with WSL (Recommended)

1. **Install WSL** (if not already installed):
   ```powershell
   # Run as Administrator
   wsl --install
   # Restart computer
   ```

2. **Run the build script**:
   ```cmd
   build_apk_windows.bat
   ```

### Option 2: Linux/WSL Manual Build

1. **Install dependencies**:
   ```bash
   sudo apt update
   sudo apt install -y python3-pip python3-venv git openjdk-17-jdk unzip
   ```

2. **Set up Android SDK**:
   ```bash
   # Download and install Android command line tools
   cd ~
   wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
   unzip commandlinetools-linux-9477386_latest.zip
   mkdir -p android-sdk/cmdline-tools
   mv cmdline-tools android-sdk/cmdline-tools/latest
   
   # Set environment variables
   export ANDROID_HOME=$HOME/android-sdk
   export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin
   
   # Accept licenses and install NDK
   yes | sdkmanager --licenses
   sdkmanager "ndk;25.1.8937393"
   sdkmanager "platforms;android-33"
   sdkmanager "build-tools;33.0.0"
   ```

3. **Build the APK**:
   ```bash
   python3 -m venv mobile_env
   source mobile_env/bin/activate
   pip install -r requirements.txt
   buildozer android debug
   ```

## 📲 Installation

1. **Enable Developer Options** on your Android device:
   - Go to Settings > About Phone
   - Tap "Build Number" 7 times
   - Go to Settings > Developer Options
   - Enable "USB Debugging"

2. **Install the APK**:
   ```bash
   adb install bin/NoTrace-2.0-arm64-v8a_armeabi-v7a-debug.apk
   ```

## 📱 App Structure

- **Material Design UI**: Modern Android-style interface
- **Two Tabs**: Encode and Decode functionality
- **Touch Optimized**: Large buttons and text fields
- **Error Handling**: User-friendly error messages
- **Responsive**: Works on phones and tablets

## 🔧 Development

### File Structure
```
mobile/
├── main.py                 # Main Kivy app
├── requirements.txt        # Python dependencies
├── buildozer.spec         # Android build configuration
├── build_apk.sh           # Linux build script
├── build_apk_windows.bat  # Windows build script
└── README.md              # This file
```

### Key Dependencies
- **Kivy 2.3.0**: Cross-platform UI framework
- **KivyMD 1.2.0**: Material Design components
- **cryptography 45.0.5**: Same encryption library as desktop
- **buildozer 1.5.0**: Android packaging tool

### Testing
- Test on Android 7.0+ (API level 24+)
- Verify encryption compatibility with desktop version
- Test on different screen sizes

## 🚀 Future Enhancements

- [ ] File encryption support
- [ ] QR code sharing for keys
- [ ] Biometric authentication
- [ ] Contact management
- [ ] Message history (encrypted storage)
- [ ] Network sharing features

## ⚠️ Security Notes

- Same security model as desktop version
- Keys and PINs stored temporarily in memory only
- No data transmitted over network
- Full offline operation
- Compatible with desktop-encrypted messages

## 🐛 Troubleshooting

### Build Issues
- Ensure Java 17 is installed
- Verify Android SDK/NDK paths
- Check WSL2 if using Windows
- Increase WSL memory if build fails

### Runtime Issues
- Check Android version (7.0+ required)
- Verify app permissions
- Clear app data if encryption fails
- Ensure sufficient storage space

## 📄 License

Same MIT license as the main NoTrace project.
