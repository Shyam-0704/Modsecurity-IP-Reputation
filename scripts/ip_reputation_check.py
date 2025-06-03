#!/usr/bin/env python3

import os
import sys
import json
import time
import requests

# Configuration
OUTPUT_FILE = "/tmp/ip_check_result.txt"
CACHE_DIR = "/var/cache/modsec-threat-monitor"
BANLIST_FILE = os.path.join(CACHE_DIR, "ip_banlist.json")
ALLOWLIST = {"192.168.10.10"}
BAN_DURATION = 86400  # 24 hours in seconds

SLACK_WEBHOOK_URL = "<YOUR-WEBHOOK-URL-HERE>"
API_KEYS = {
    'virustotal': '<VIRUSTOTAL-APIKEY-HERE>',
    'alienvault': '<ALIENVAULT-APIKEY-HERE>',
    'abuseipdb': '<ABUSEIPDB-APIKEY-HERE>'
}

def ensure_cache_dir():
    os.makedirs(CACHE_DIR, exist_ok=True)

def load_banlist():
    try:
        with open(BANLIST_FILE, "r") as f:
            data = json.load(f)
        now = int(time.time())
        # Clean expired entries
        return {ip: exp for ip, exp in data.items() if exp > now}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_banlist(banlist):
    with open(BANLIST_FILE, "w") as f:
        json.dump(banlist, f)

def send_slack_alert(ip, vt, av, ab, flagged_vendors, total_flags, error=None):
    color = "#ff0000" if total_flags >= 3 else "#ffa500"
    if error:
        color = "#808080"
    payload = {
        "username": "ModSecurity Monitor",
        "icon_emoji": ":rotating_light:",
        "attachments": [{
            "color": color,
            "title": "⚠️ IP Reputation Alert" if not error else "❌ API Error Alert",
            "fields": [
                {"title": "IP", "value": ip, "short": True},
                {"title": "VirusTotal", "value": vt, "short": True},
                {"title": "AlienVault", "value": av, "short": True},
                {"title": "AbuseIPDB", "value": ab, "short": True},
                {"title": "Vendors Flagged", "value": flagged_vendors, "short": True},
                {"title": "Total Flags", "value": total_flags, "short": True},
                {"title": "Error", "value": error or "None", "short": False},
            ],
            "footer": "ModSecurity Threat Monitor"
        }]
    }
    try:
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        print(f"[DEBUG] Slack alert failed: {e}", file=sys.stderr)

def check_virustotal(ip):
    try:
        headers = {'x-apikey': API_KEYS['virustotal']}
        r = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}', headers=headers, timeout=5)
        if r.status_code != 200:
            print(f"[DEBUG] VT error {r.status_code}: {r.text}", file=sys.stderr)
            return 0
        return r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
    except Exception as e:
        print(f"[DEBUG] VT exception: {e}", file=sys.stderr)
        return 0

def check_alienvault(ip):
    try:
        headers = {'X-OTX-API-KEY': API_KEYS['alienvault']}
        r = requests.get(f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general', headers=headers, timeout=5)
        if r.status_code != 200:
            print(f"[DEBUG] AV error {r.status_code}: {r.text}", file=sys.stderr)
            return 0
        return r.json().get('pulse_info', {}).get('count', 0)
    except Exception as e:
        print(f"[DEBUG] AV exception: {e}", file=sys.stderr)
        return 0

def check_abuseipdb(ip):
    try:
        headers = {
            'Key': API_KEYS['abuseipdb'],
            'Accept': 'application/json'
        }
        r = requests.get(f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90', headers=headers, timeout=5)
        if r.status_code != 200:
            print(f"[DEBUG] AbuseIPDB error {r.status_code}: {r.text}", file=sys.stderr)
            return 0
        score = r.json().get('data', {}).get('abuseConfidenceScore', 0)
        return 1 if score > 0 else 0
    except Exception as e:
        print(f"[DEBUG] AbuseIPDB exception: {e}", file=sys.stderr)
        return 0

def main():
    ensure_cache_dir()

    xff = os.environ.get("HTTP_X_FORWARDED_FOR")
    remote_ip = os.environ.get("REMOTE_ADDR")
    ip = xff.split(",")[0].strip() if xff else remote_ip

    print(f"[DEBUG] REMOTE_ADDR: {remote_ip}", file=sys.stderr)
    print(f"[DEBUG] X-Forwarded-For: {xff}", file=sys.stderr)
    print(f"[DEBUG] IP selected: {ip}", file=sys.stderr)

    if not ip or ip in ALLOWLIST:
        print("ALLOW")
        print(f"[DEBUG] Skipped (Allowlist or missing IP): {ip}", file=sys.stderr)
        return

    banlist = load_banlist()

    if ip in banlist:
        print("BLOCK")
        print(f"[DEBUG] Banned IP detected: {ip}", file=sys.stderr)
        return

    vt = check_virustotal(ip)
    av = check_alienvault(ip)
    ab = check_abuseipdb(ip)

    flagged_vendors = sum(v > 0 for v in [vt, av, ab])
    total_flags = vt + av + ab

    print(f"[DEBUG] VT={vt}, AV={av}, AB={ab}, Vendors={flagged_vendors}, Total={total_flags}", file=sys.stderr)

    if total_flags >= 2 or flagged_vendors >= 2:
        print("BLOCK")
        print(f"[DEBUG] Decision = BLOCK", file=sys.stderr)
        banlist[ip] = int(time.time()) + BAN_DURATION
        save_banlist(banlist)
        send_slack_alert(ip, vt, av, ab, flagged_vendors, total_flags)
    else:
        print("ALLOW")
        print(f"[DEBUG] Decision = ALLOW", file=sys.stderr)

if __name__ == '__main__':
    main()
