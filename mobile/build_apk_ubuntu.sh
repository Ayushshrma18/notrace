#!/bin/bash
# NoTrace APK Builder Script - Simplified Version
# Run this script in WSL Ubuntu after installation

echo "🚀 NoTrace APK Builder Starting..."
echo "================================="

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Python and dependencies
echo "🐍 Installing Python and build tools..."
sudo apt install -y python3 python3-pip python3-venv git zip unzip openjdk-8-jdk

# Install Buildozer
echo "🔧 Installing Buildozer..."
pip3 install --upgrade pip
pip3 install buildozer cython

# Set JAVA_HOME
echo "☕ Setting up Java environment..."
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
echo 'export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64' >> ~/.bashrc

# Install Android SDK components
echo "📱 Setting up Android SDK..."
mkdir -p ~/.buildozer/android/platform/
cd ~/.buildozer/android/platform/

# Download Android SDK command line tools if not exists
if [ ! -d "android-sdk" ]; then
    echo "📥 Downloading Android SDK..."
    wget https://dl.google.com/android/repository/commandlinetools-linux-8512546_latest.zip
    unzip commandlinetools-linux-8512546_latest.zip
    mkdir -p android-sdk/cmdline-tools/latest
    mv cmdline-tools/* android-sdk/cmdline-tools/latest/
    rm -rf cmdline-tools commandlinetools-linux-8512546_latest.zip
fi

# Set Android SDK paths
export ANDROID_HOME=~/.buildozer/android/platform/android-sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

# Accept licenses and install SDK components
echo "📋 Accepting Android SDK licenses..."
yes | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --licenses

echo "📱 Installing Android SDK components..."
$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager "platform-tools" "platforms;android-30" "build-tools;30.0.3"

# Navigate to your NoTrace mobile directory
echo "📂 Navigating to NoTrace mobile directory..."
cd /mnt/e/Code\ -\ Projects/NoTrace/mobile/

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
pip3 install kivy kivymd cryptography

# Build APK
echo "🔨 Building NoTrace APK..."
buildozer android debug

echo ""
echo "🎉 APK BUILD COMPLETE!"
echo "========================"
echo "📱 Your APK file is located at:"
echo "   /mnt/e/Code - Projects/NoTrace/mobile/bin/notrace-0.1-armeabi-v7a-debug.apk"
echo ""
echo "📲 To install on your phone:"
echo "   1. Enable 'Developer Options' and 'USB Debugging' on your Android phone"
echo "   2. Copy the APK file to your phone"
echo "   3. Install using a file manager or:"
echo "      adb install bin/notrace-0.1-armeabi-v7a-debug.apk"
echo ""
echo "🔐 Your NoTrace encryption app is ready for mobile!"
