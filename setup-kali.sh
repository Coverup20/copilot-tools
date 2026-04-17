#!/bin/bash
# setup-kali.sh - Install copilot-tools on Kali WSL
# Installs notify, get-chat-id, telegram-daemon, check-inbox in ~/bin
# Sets up systemd user service for the daemon

set -e

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$HOME/bin"
SYSTEMD_DIR="$HOME/.config/systemd/user"

echo "=== Copilot Tools - Kali Setup ==="
echo ""

# Create dirs
mkdir -p "$BIN_DIR"
mkdir -p "$SYSTEMD_DIR"

# Install binaries
cp "$REPO_DIR/notify.py" "$BIN_DIR/notify"
chmod +x "$BIN_DIR/notify"
echo "Installed: $BIN_DIR/notify"

cp "$REPO_DIR/get-chat-id.py" "$BIN_DIR/get-chat-id"
chmod +x "$BIN_DIR/get-chat-id"
echo "Installed: $BIN_DIR/get-chat-id"

cp "$REPO_DIR/telegram-daemon.py" "$BIN_DIR/telegram-daemon"
chmod +x "$BIN_DIR/telegram-daemon"
echo "Installed: $BIN_DIR/telegram-daemon"

cp "$REPO_DIR/check-inbox.py" "$BIN_DIR/check-inbox"
chmod +x "$BIN_DIR/check-inbox"
echo "Installed: $BIN_DIR/check-inbox"

cp "$REPO_DIR/inbox-worker.py" "$BIN_DIR/inbox-worker"
chmod +x "$BIN_DIR/inbox-worker"
echo "Installed: $BIN_DIR/inbox-worker"

# Install systemd user services
cp "$REPO_DIR/copilot-telegram.service" "$SYSTEMD_DIR/copilot-telegram.service"
echo "Installed: $SYSTEMD_DIR/copilot-telegram.service"

cp "$REPO_DIR/copilot-worker.service" "$SYSTEMD_DIR/copilot-worker.service"
echo "Installed: $SYSTEMD_DIR/copilot-worker.service"

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
    echo "       get-chat-id --token YOUR_TOKEN_HERE"
    echo "     This saves credentials to ~/.copilot-telegram automatically."
    echo ""
else
    echo "Credentials found at ~/.copilot-telegram"
    echo ""

    # Enable and start the daemon
    if command -v systemctl &>/dev/null && systemctl --user status &>/dev/null 2>&1; then
        systemctl --user daemon-reload
        systemctl --user enable copilot-telegram.service copilot-worker.service
        systemctl --user restart copilot-telegram.service copilot-worker.service
        echo "Services enabled and started via systemd."
        echo "Status: systemctl --user status copilot-telegram copilot-worker"
    else
        echo "systemd not available (WSL1?). Start manually:"
        echo "  nohup telegram-daemon &"
        echo "  nohup inbox-worker &"
    fi

    echo ""
    echo "Test with:"
    echo "  notify 'Hello from Copilot!'"
    echo "  check-inbox"
    echo ""
    echo "Sessions (past Telegram interactions) in: ~/.copilot-sessions/"
fi

echo ""
echo "=== Setup complete ==="
