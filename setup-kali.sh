#!/bin/bash
# setup-kali.sh - Install copilot-tools on Kali WSL
# Installs notify.py as ~/bin/notify (accessible from anywhere)

set -e

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$HOME/bin"

echo "=== Copilot Tools - Kali Setup ==="
echo ""

# Create ~/bin if not exists
mkdir -p "$BIN_DIR"

# Install notify.py
cp "$REPO_DIR/notify.py" "$BIN_DIR/notify"
chmod +x "$BIN_DIR/notify"
echo "Installed: $BIN_DIR/notify"

# Install get-chat-id.py
cp "$REPO_DIR/get-chat-id.py" "$BIN_DIR/get-chat-id"
chmod +x "$BIN_DIR/get-chat-id"
echo "Installed: $BIN_DIR/get-chat-id"

# Ensure ~/bin is in PATH
if ! echo "$PATH" | grep -q "$HOME/bin"; then
    echo ""
    echo "WARNING: $HOME/bin is not in your PATH."
    echo "Add this line to your ~/.zshrc or ~/.bashrc:"
    echo "  export PATH=\"\$HOME/bin:\$PATH\""
    echo "Then run: source ~/.zshrc"
fi

echo ""

# Check if credentials file exists
if [ ! -f "$HOME/.copilot-telegram" ]; then
    echo "Credentials not found. Setup required:"
    echo ""
    echo "  1. Open Telegram → search @BotFather"
    echo "  2. Send /newbot → follow instructions → copy the TOKEN"
    echo "  3. Send any message to your new bot"
    echo "  4. Run:"
    echo "       python3 $BIN_DIR/get-chat-id --token YOUR_TOKEN_HERE"
    echo "     This saves credentials to ~/.copilot-telegram automatically."
    echo ""
else
    echo "Credentials found at ~/.copilot-telegram"
    echo ""
    echo "Test with:"
    echo "  notify 'Hello from Copilot!'"
fi

echo "=== Setup complete ==="
