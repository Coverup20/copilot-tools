#!/usr/bin/python3
#
# telegram-daemon.py - Background daemon: polls Telegram and saves messages to inbox
# Reads credentials from ~/.copilot-telegram
# Inbox file: ~/.copilot-inbox (JSON array of messages)
# Run as: python3 telegram-daemon.py
# Or via systemd: see copilot-telegram.service
#

import sys
import os
import json
import time
import urllib.request
import urllib.parse
import urllib.error
import logging
import signal
import fcntl

VERSION = "1.0.0"
CREDENTIALS_FILE = os.path.expanduser("~/.copilot-telegram")
INBOX_FILE = os.path.expanduser("~/.copilot-inbox")
OFFSET_FILE = os.path.expanduser("~/.copilot-telegram-offset")
LOG_FILE = os.path.expanduser("~/.copilot-telegram-daemon.log")
POLL_TIMEOUT = 30  # long polling seconds
MAX_INBOX = 100    # max messages to keep in inbox


## Utils

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("telegram-daemon")


def load_credentials():
    if not os.path.exists(CREDENTIALS_FILE):
        log.error(f"Credentials file not found: {CREDENTIALS_FILE}")
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
    chat_id = str(creds.get("TELEGRAM_CHAT_ID", ""))
    if not token or not chat_id:
        log.error("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID missing")
        sys.exit(1)
    return token, chat_id


def load_offset():
    if os.path.exists(OFFSET_FILE):
        try:
            with open(OFFSET_FILE) as f:
                return int(f.read().strip())
        except:
            pass
    return 0


def save_offset(offset):
    with open(OFFSET_FILE, "w") as f:
        f.write(str(offset))


def load_inbox():
    if os.path.exists(INBOX_FILE):
        try:
            with open(INBOX_FILE) as f:
                return json.load(f)
        except:
            pass
    return []


def save_inbox(messages):
    # Keep only last MAX_INBOX messages
    messages = messages[-MAX_INBOX:]
    with open(INBOX_FILE, "w") as f:
        json.dump(messages, f, indent=2, ensure_ascii=False)
    os.chmod(INBOX_FILE, 0o600)


def get_updates(token, offset, timeout=30):
    url = f"https://api.telegram.org/bot{token}/getUpdates"
    params = urllib.parse.urlencode({
        "offset": offset,
        "timeout": timeout,
        "allowed_updates": '["message"]',
    })
    full_url = f"{url}?{params}"
    try:
        req = urllib.request.Request(full_url)
        with urllib.request.urlopen(req, timeout=timeout + 5) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        log.warning(f"HTTP {e.code}: {e.read().decode()[:200]}")
        return None
    except Exception as e:
        log.warning(f"getUpdates error: {e}")
        return None


## Daemon

def handle_signal(sig, frame):
    log.info("Signal received, shutting down...")
    sys.exit(0)


def run():
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    token, allowed_chat_id = load_credentials()
    offset = load_offset()

    log.info(f"telegram-daemon v{VERSION} started (chat_id={allowed_chat_id})")
    log.info(f"Inbox: {INBOX_FILE}")
    log.info(f"Log:   {LOG_FILE}")

    while True:
        data = get_updates(token, offset, timeout=POLL_TIMEOUT)

        if data is None:
            time.sleep(5)
            continue

        if not data.get("ok"):
            log.warning(f"API not OK: {data}")
            time.sleep(10)
            continue

        results = data.get("result", [])

        if results:
            inbox = load_inbox()

            for update in results:
                update_id = update.get("update_id", 0)
                offset = max(offset, update_id + 1)

                msg = update.get("message")
                if not msg:
                    continue

                chat_id = str(msg.get("chat", {}).get("id", ""))
                if chat_id != allowed_chat_id:
                    log.warning(f"Ignored message from unknown chat_id: {chat_id}")
                    continue

                text = msg.get("text", "").strip()
                if not text:
                    continue

                from_name = msg.get("from", {}).get("first_name", "Unknown")
                ts = msg.get("date", int(time.time()))

                entry = {
                    "id": update_id,
                    "from": from_name,
                    "text": text,
                    "timestamp": ts,
                    "read": False,
                }
                inbox.append(entry)
                log.info(f"New message from {from_name}: {text[:80]}")

            save_inbox(inbox)
            save_offset(offset)

        else:
            # No new updates, save offset anyway
            save_offset(offset)


run()
