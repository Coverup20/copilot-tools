#!/usr/bin/python3
#
# inbox-worker.py - Watches ~/.copilot-inbox for new messages,
#                   runs each prompt through Copilot CLI (autopilot),
#                   sends result via notify, saves full session log.
#
# Sessions saved to: ~/.copilot-sessions/YYYY-MM-DD_HH-MM-SS_<snippet>.log
# Runs as systemd user service: copilot-worker.service
#

import sys
import os
import json
import time
import subprocess
import logging
import signal
import re
from datetime import datetime

VERSION = "1.2.0"
INBOX_FILE = os.path.expanduser("~/.copilot-inbox")
SESSIONS_DIR = os.path.expanduser("~/.copilot-sessions")
LOG_FILE = os.path.expanduser("~/.copilot-worker.log")
COPILOT_BIN = "/usr/local/bin/copilot"
NOTIFY_BIN = "/root/bin/notify"
POLL_INTERVAL = 5   # seconds between inbox checks
COPILOT_TIMEOUT = 600  # max seconds to wait for copilot response

# System context injected before every user prompt
SYSTEM_CONTEXT = """
CONTEXT (read before answering):
- You are running as root on checkmk-z1-00 (192.168.10.128), a Linux host.
- Working directory: /opt/checkmk-tools (the checkmk-tools repository).
- SSH access is available WITHOUT passphrase using these aliases (defined in ~/.ssh/config):
    srv-monitoring-sp  -> 45.33.235.86:2333 (root, CheckMK production SP, OMD site: monitoring)
    srv-monitoring-us  -> 195.223.159.27:2333 (root, CheckMK production US, OMD site: monitoring)
    checkmk-vps-01     -> monitor.nethlab.it (root, CheckMK production VPS)
    checkmk-vps-02     -> monitor01.nethlab.it (root, CheckMK staging VPS)
- SERVER GROUPS (use these definitions always):
    "tutti i server checkmk" / "all checkmk servers"      -> srv-monitoring-sp, srv-monitoring-us, checkmk-vps-01, checkmk-vps-02
    "server checkmk dei clienti" / "client checkmk"       -> srv-monitoring-sp, srv-monitoring-us
    "server checkmk vps"                                  -> checkmk-vps-01, checkmk-vps-02
- OMD commands must be run as site user: ssh <host> 'su - monitoring -c "omd status"'
- ALWAYS actually SSH to the servers and collect real data. Do NOT just produce command lists.
- Use 'ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new <alias> <cmd>' for all SSH calls.

USER REQUEST:
""".strip()


## Utils

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("inbox-worker")


def load_inbox():
    if not os.path.exists(INBOX_FILE):
        return []
    try:
        with open(INBOX_FILE) as f:
            return json.load(f)
    except Exception as e:
        log.warning(f"Failed to load inbox: {e}")
        return []


def save_inbox(messages):
    with open(INBOX_FILE, "w") as f:
        json.dump(messages, f, indent=2, ensure_ascii=False)
    os.chmod(INBOX_FILE, 0o600)


def notify(text):
    try:
        r = subprocess.run(
            [NOTIFY_BIN, text],
            timeout=30,
            check=False,
            capture_output=True,
            text=True,
        )
        if r.returncode == 0:
            log.info("Notify sent OK")
        else:
            log.warning(f"notify failed (exit {r.returncode}): {r.stderr.strip()[:300]}")
    except Exception as e:
        log.warning(f"notify failed: {e}")


def clean_output(text):
    # Remove ANSI escape codes
    ansi = re.compile(r'\x1b\[[0-9;]*[mGKHF]|\x1b\].*?\x07|\x1b[@-Z\\-_]')
    text = ansi.sub('', text)
    # Remove XML tool call tags leaked from copilot agent (e.g. <taskcomplete>, <parameter ...>)
    text = re.sub(r'<task_?complete[^>]*>.*?</task_?complete>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<parameter[^>]*>.*?</parameter>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[a-zA-Z_][a-zA-Z0-9_]*\s*/>', '', text)
    # Collapse excessive blank lines
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def truncate_for_telegram(text, max_chars=3500):
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return text[:half] + "\n\n[...truncated...]\n\n" + text[-half:]


def save_session(prompt, output, duration):
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    os.chmod(SESSIONS_DIR, 0o700)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    snippet = re.sub(r'[^a-zA-Z0-9]', '_', prompt[:30]).strip('_')
    filename = f"{ts}_{snippet}.log"
    path = os.path.join(SESSIONS_DIR, filename)
    with open(path, "w") as f:
        f.write(f"=== Copilot Session ===\n")
        f.write(f"Timestamp : {ts}\n")
        f.write(f"Duration  : {duration:.1f}s\n")
        f.write(f"Prompt    : {prompt}\n")
        f.write(f"\n--- OUTPUT ---\n\n")
        f.write(output)
        f.write(f"\n\n--- END ---\n")
    os.chmod(path, 0o600)
    log.info(f"Session saved: {path}")
    return path


def run_copilot(prompt):
    full_prompt = f"{SYSTEM_CONTEXT}\n{prompt}"
    log.info(f"Running copilot for: {prompt[:80]}")
    start = time.time()
    try:
        gh_token = os.environ.get("GH_TOKEN", "")
        result = subprocess.run(
            [COPILOT_BIN, "-p", full_prompt, "--allow-all", "--autopilot", "--no-ask-user"],
            capture_output=True,
            text=True,
            timeout=COPILOT_TIMEOUT,
            env={
                **os.environ,
                "TERM": "dumb",
                "GH_TOKEN": gh_token,
                "GITHUB_TOKEN": gh_token,
                "COPILOT_GITHUB_TOKEN": gh_token,
            },
        )
        duration = time.time() - start
        raw = result.stdout + ("\n" + result.stderr if result.stderr.strip() else "")
        output = clean_output(raw)
        log.info(f"Copilot finished in {duration:.1f}s (exit {result.returncode})")
        return output, duration, result.returncode
    except subprocess.TimeoutExpired:
        duration = time.time() - start
        log.warning(f"Copilot timed out after {duration:.0f}s")
        return f"Timeout after {duration:.0f}s", duration, -1
    except FileNotFoundError:
        return f"ERROR: Copilot CLI not found at {COPILOT_BIN}", 0, -1
    except Exception as e:
        return f"ERROR: {e}", 0, -1


## Worker

def process_message(msg):
    prompt = msg.get("text", "").strip()
    frm = msg.get("from", "?")
    ts = datetime.fromtimestamp(msg.get("timestamp", time.time())).strftime("%H:%M:%S")

    log.info(f"Processing message from {frm} at {ts}: {prompt[:80]}")

    # Notify user that we started processing
    notify(f"Received at {ts}: {prompt[:100]}\n\nProcessing...")

    output, duration, rc = run_copilot(prompt)

    # Save full session log
    session_path = save_session(prompt, output, duration)

    # Send result via Telegram
    telegram_text = f"Response ({duration:.0f}s):\n\n{truncate_for_telegram(output)}"
    notify(telegram_text)

    log.info(f"Done. Session: {session_path}")


def handle_signal(sig, frame):
    log.info("Signal received, shutting down...")
    sys.exit(0)


def run():
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    log.info(f"inbox-worker v{VERSION} started")
    log.info(f"Inbox    : {INBOX_FILE}")
    log.info(f"Sessions : {SESSIONS_DIR}")
    log.info(f"Copilot  : {COPILOT_BIN}")
    log.info(f"Poll     : every {POLL_INTERVAL}s")

    if not os.path.exists(COPILOT_BIN):
        log.error(f"Copilot CLI not found: {COPILOT_BIN}")
        log.error("Install with: npm install -g @githubnext/copilot-cli")
        sys.exit(1)

    while True:
        inbox = load_inbox()
        unread = [m for m in inbox if not m.get("read")]

        for msg in unread:
            # Mark as read immediately to avoid double processing
            for m in inbox:
                if m.get("id") == msg.get("id"):
                    m["read"] = True
            save_inbox(inbox)

            try:
                process_message(msg)
            except Exception as e:
                log.error(f"Error processing message: {e}")
                notify(f"Worker error: {e}")

        time.sleep(POLL_INTERVAL)


run()
