# Simple APK Test - For Immediate Testing
# You can use this with online APK builders while Ubuntu installs

# Create a minimal version for testing
import os
import sys

# Add the mobile directory to path
mobile_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, mobile_dir)

# Import the main app
from main import NoTraceApp

# Run the app
if __name__ == '__main__':
    print("🚀 Starting NoTrace Mobile App...")
    print("📱 This will create your APK for phone installation!")
    NoTraceApp().run()
