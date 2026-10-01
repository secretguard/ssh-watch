import sys
import re
import json
import os
import subprocess
import requests
from datetime import datetime
from collections import deque, defaultdict

THRESHOLD = 5
WINDOW = 60
BOT_TOKEN = "8850254032:AAGdhHdzMSJBJ6OVfwN8xH4FrgFePoSluKk"
CHAT_ID = "5034528323"
FINDINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "findings.json")

FAIL_RE = re.compile(r"^(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password.*from (\d+\.\d+\.\d+\.\d+)")
SUCCESS_RE = re.compile(r"^(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")

def parse_ts(raw):
    return datetime.strptime(f"{datetime.now().year} {raw}", "%Y %b %d %H:%M:%S")

def save_finding(finding_type, details):
    findings = []
    if os.path.exists(FINDINGS_FILE):
        try:
            with open(FINDINGS_FILE) as f:
                findings = json.load(f)
        except Exception:
            findings = []
    findings.append({
        "type": finding_type,
        "details": details,
        "logged_at": datetime.now().isoformat()
    })
    tmp = FINDINGS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(findings, f, indent=2)
    os.replace(tmp, FINDINGS_FILE)

def send_telegram(message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    try:
        requests.post(url, data={"chat_id": CHAT_ID, "text": message}, timeout=10)
        print("Telegram alert sent.")
    except Exception as e:
        print("Could not send Telegram alert:", e)

def block_ip(ip):
    try:
        subprocess.run(["sudo", "ufw", "deny", "from", ip, "to", "any"], check=True)
        print(f"UFW: blocked {ip}")
    except Exception as e:
        print("Could not block IP:", e)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector.py <auth.log>")
        return

    print("config:", THRESHOLD, "fails /", WINDOW, "s")

    per_ip = defaultdict(deque)
    flagged = {}

    with open(sys.argv[1], errors="ignore") as f:
        for line in f:
            fail_match = FAIL_RE.search(line)
            if fail_match:
                ts = parse_ts(fail_match.group(1))
                ip = fail_match.group(2)
                hits = per_ip[ip]
                hits.append(ts)
                while hits and (ts - hits[0]).total_seconds() > WINDOW:
                    hits.popleft()
                if len(hits) >= THRESHOLD and ip not in flagged:
                    flagged[ip] = ts
                    msg = (f"ALERT: Possible SSH brute force\n"
                           f"Attacker IP: {ip}\n"
                           f"Failed logins: {len(hits)} in {WINDOW} seconds")
                    print(msg)
                    save_finding("brute_force_alert", {
                        "ip": ip,
                        "failed_logins": len(hits),
                        "window_seconds": WINDOW
                    })
                    send_telegram(msg)
                    block_ip(ip)
                continue

            success_match = SUCCESS_RE.search(line)
            if success_match:
                ts = parse_ts(success_match.group(1))
                user = success_match.group(2)
                ip = success_match.group(3)
                if ip in flagged and (ts - flagged[ip]).total_seconds() < 600:
                    msg = (f"CRITICAL: Successful login after brute force!\n"
                           f"IP: {ip}\nLogged in as: {user}")
                    print(msg)
                    save_finding("critical_success_after_attack", {
                        "ip": ip,
                        "user": user
                    })
                    send_telegram(msg)

    if not flagged:
        print("No brute-force pattern found in", sys.argv[1])
        save_finding("no_pattern_found", {"file": sys.argv[1]})

if __name__ == "__main__":
    main()