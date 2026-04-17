#!/usr/bin/python3
#
# notify.py - Send a Telegram message from the local machine
# Reads credentials from ~/.copilot-telegram
# Usage: notify.py "Your message here"
#        notify.py -t "Title" "Your message here"
#        echo "message" | notify.py
#

import sys
import os
import argparse
import urllib.request
import urllib.parse
import json

VERSION = "1.0.0"
CREDENTIALS_FILE = os.path.expanduser("~/.copilot-telegram")


## Utils

def load_credentials():
    if not os.path.exists(CREDENTIALS_FILE):
        print(f"ERROR: Credentials file not found: {CREDENTIALS_FILE}", file=sys.stderr)
        print(f"Run: python3 get-chat-id.py to set up credentials", file=sys.stderr)
        sys.exit(1)
    creds = {}
    with open(CREDENTIALS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                creds[k.strip()] = v.strip().strip('"')
    token = creds.get("TELEGRAM_BOT_TOKEN")
    chat_id = creds.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print(f"ERROR: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID missing in {CREDENTIALS_FILE}", file=sys.stderr)
        sys.exit(1)
    return token, chat_id


def send_message(token, chat_id, text):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": "true",
    }).encode()
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            resp = json.loads(r.read())
            return resp.get("ok", False)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"ERROR: HTTP {e.code} - {body}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return False


## Main

def main():
    parser = argparse.ArgumentParser(description=f"Copilot Telegram Notify v{VERSION}")
    parser.add_argument("-t", "--title", help="Optional title/prefix for the message", default=None)
    parser.add_argument("-v", "--version", action="store_true", help="Show version")
    parser.add_argument("message", nargs="?", help="Message to send (or use stdin)")
    args = parser.parse_args()

    if args.version:
        print(f"notify.py v{VERSION}")
        sys.exit(0)

    if args.message:
        text = args.message
    elif not sys.stdin.isatty():
        text = sys.stdin.read().strip()
    else:
        print("ERROR: No message provided. Use: notify.py 'message' or echo 'msg' | notify.py", file=sys.stderr)
        sys.exit(1)

    if args.title:
        text = f"*{args.title}*\n\n{text}"

    token, chat_id = load_credentials()
    ok = send_message(token, chat_id, text)
    if ok:
        print("Sent.")
    else:
        sys.exit(1)


main()
