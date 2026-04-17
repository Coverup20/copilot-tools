#!/usr/bin/python3
#
# check-inbox.py - Read and display pending Telegram messages for Copilot
# Usage:
#   check-inbox          - Show unread messages (does NOT mark as read)
#   check-inbox --read   - Show and mark all as read
#   check-inbox --count  - Print unread count only (for scripting)
#   check-inbox --clear  - Delete all messages from inbox
#

import sys
import os
import json
import argparse
import time

VERSION = "1.0.0"
INBOX_FILE = os.path.expanduser("~/.copilot-inbox")


## Utils

def load_inbox():
    if not os.path.exists(INBOX_FILE):
        return []
    try:
        with open(INBOX_FILE) as f:
            return json.load(f)
    except:
        return []


def save_inbox(messages):
    with open(INBOX_FILE, "w") as f:
        json.dump(messages, f, indent=2, ensure_ascii=False)
    os.chmod(INBOX_FILE, 0o600)


def fmt_time(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


## Main

def main():
    parser = argparse.ArgumentParser(description=f"Check Copilot Telegram inbox v{VERSION}")
    parser.add_argument("--read", action="store_true", help="Mark all as read after showing")
    parser.add_argument("--count", action="store_true", help="Print unread count only")
    parser.add_argument("--clear", action="store_true", help="Delete all messages from inbox")
    parser.add_argument("--all", action="store_true", help="Show all messages (including already read)")
    args = parser.parse_args()

    inbox = load_inbox()

    if args.clear:
        save_inbox([])
        print("Inbox cleared.")
        return

    if args.count:
        unread = sum(1 for m in inbox if not m.get("read"))
        print(unread)
        return

    # Filter
    if args.all:
        messages = inbox
    else:
        messages = [m for m in inbox if not m.get("read")]

    if not messages:
        if not args.all:
            print("No unread messages.")
        else:
            print("Inbox is empty.")
        return

    label = "All" if args.all else "Unread"
    print(f"=== Telegram Inbox ({label}: {len(messages)}) ===\n")
    for m in messages:
        ts = fmt_time(m.get("timestamp", 0))
        frm = m.get("from", "?")
        text = m.get("text", "")
        status = "" if m.get("read") else " [NEW]"
        print(f"[{ts}]{status} {frm}: {text}")
    print()

    # Mark as read
    if args.read:
        for m in inbox:
            m["read"] = True
        save_inbox(inbox)
        print(f"Marked {len(messages)} message(s) as read.")


main()
