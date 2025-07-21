# 📱 NoTrace APK Build Guide - Get Your App on Phone!

## 🚀 Quick Start (After Ubuntu WSL Installation)

### Step 1: Open WSL Ubuntu Terminal
```bash
# After Ubuntu installation completes, open WSL terminal:
wsl
```

### Step 2: Navigate to Your Project
```bash
cd /mnt/e/Code\ -\ Projects/NoTrace/mobile/
```

### Step 3: Run the APK Builder
```bash
chmod +x build_apk_ubuntu.sh
./build_apk_ubuntu.sh
```

### Step 4: Transfer APK to Phone
The APK will be created at:
```
/mnt/e/Code - Projects/NoTrace/mobile/bin/notrace-0.1-armeabi-v7a-debug.apk
```

## 📲 Installing on Your Phone

### Method 1: Direct Install
1. **Enable Developer Options** on your Android phone:
   - Go to Settings > About Phone
   - Tap "Build Number" 7 times
   - Go back to Settings > Developer Options
   - Enable "USB Debugging"

2. **Copy APK to Phone**:
   - Connect phone to PC via USB
   - Copy the APK file to your phone's Downloads folder
   - Use any file manager app to install the APK

### Method 2: ADB Install (if you have ADB)
```bash
# In WSL terminal:
sudo apt install android-tools-adb
adb install bin/notrace-0.1-armeabi-v7a-debug.apk
```

## 🎯 Alternative Quick Options

### Option A: Online APK Builder (No Setup Required)
1. Visit: https://appetize.io or similar online builders
2. Upload your `mobile/` folder
3. Build APK online

### Option B: Use Replit (Cloud-based)
1. Create account at replit.com
2. Upload your mobile code
3. Use their Linux environment to build

### Option C: Virtual Machine
1. Download VirtualBox + Ubuntu ISO
2. Create Ubuntu VM
3. Run the build script inside VM

## ⚡ Expected Results

Your NoTrace mobile app will have:
- 🔐 **Same encryption features** as desktop version
- 📱 **Touch-optimized interface** with Material Design
- 🌙 **Dark theme** for better mobile experience
- 🔒 **AES-256-CBC encryption** with PIN protection
- 📊 **Message integrity verification**
- 💫 **Professional mobile UI** with cards and animations

## 🔧 Troubleshooting

**If build fails:**
1. Make sure you have stable internet (downloads Android SDK)
2. Check if you have enough disk space (need ~2GB)
3. Run: `buildozer android clean` and try again

**If APK won't install:**
1. Enable "Install from Unknown Sources" in phone settings
2. Make sure APK file isn't corrupted during transfer
3. Try different file manager app

## 📝 APK Specifications
- **Target**: Android 7.0+ (API 24+)
- **Architecture**: ARM64 + x86_64
- **Size**: ~15-20 MB
- **Permissions**: Internet, Storage access
- **Features**: Full encryption suite with mobile UI

Your NoTrace app will be ready to encrypt messages securely on your phone! 🚀
