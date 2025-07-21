#!/bin/bash

# NoTrace Mobile APK Builder
# This script sets up the environment and builds the APK

echo "🚀 NoTrace Mobile APK Builder"
echo "=============================="

# Check if we're on Windows Subsystem for Linux or Linux
if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "msys" ]]; then
    echo "✅ Linux/WSL environment detected"
else
    echo "❌ This script requires Linux or WSL. Please use Windows Subsystem for Linux."
    exit 1
fi

# Install system dependencies
echo "📦 Installing system dependencies..."
sudo apt update
sudo apt install -y python3-pip python3-venv git openjdk-17-jdk unzip

# Install Android SDK
echo "📱 Setting up Android SDK..."
if [ ! -d "$HOME/android-sdk" ]; then
    cd $HOME
    wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
    unzip commandlinetools-linux-9477386_latest.zip
    mkdir -p android-sdk/cmdline-tools
    mv cmdline-tools android-sdk/cmdline-tools/latest
    rm commandlinetools-linux-9477386_latest.zip
fi

# Set environment variables
export ANDROID_HOME=$HOME/android-sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

# Accept Android licenses
echo "📝 Accepting Android licenses..."
yes | sdkmanager --licenses

# Install Android NDK
echo "🔧 Installing Android NDK..."
sdkmanager "ndk;25.1.8937393"
sdkmanager "platforms;android-33"
sdkmanager "build-tools;33.0.0"

export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/25.1.8937393

# Create Python virtual environment
echo "🐍 Setting up Python environment..."
python3 -m venv mobile_env
source mobile_env/bin/activate

# Install Python dependencies
echo "📚 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Initialize buildozer
echo "🏗️ Initializing buildozer..."
buildozer init

# Build APK
echo "📱 Building APK..."
buildozer android debug

echo ""
echo "🎉 Build Complete!"
echo "📱 APK Location: bin/NoTrace-2.0-arm64-v8a_armeabi-v7a-debug.apk"
echo "📋 Install on device: adb install bin/NoTrace-2.0-arm64-v8a_armeabi-v7a-debug.apk"
