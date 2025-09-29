#!/bin/bash
# Quick fix for cap2hccapx PATH issue

echo "🔧 Fixing cap2hccapx PATH issue..."

# Find cap2hccapx
CAP2HCCAPX_PATH=$(find /usr -name "cap2hccapx" 2>/dev/null | head -1)

if [ -n "$CAP2HCCAPX_PATH" ]; then
    echo "✅ Found cap2hccapx at: $CAP2HCCAPX_PATH"
    
    # Create symlink in /usr/bin if not already there
    if [ ! -f "/usr/bin/cap2hccapx" ]; then
        echo "🔗 Creating symlink..."
        sudo ln -sf "$CAP2HCCAPX_PATH" /usr/bin/cap2hccapx
    fi
    
    # Add to PATH
    export PATH="/usr/bin:$PATH"
    
    echo "✅ cap2hccapx should now be available"
    which cap2hccapx
else
    echo "❌ cap2hccapx not found anywhere"
    echo "💡 Try: sudo apt install --reinstall hcxtools"
fi
