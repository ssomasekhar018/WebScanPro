#!/usr/bin/env python3
import csv
import os
import time
from datetime import datetime
from bs4 import BeautifulSoup
import html
from .core import send_reflected, send_stored_insert, fetch_stored_view
from .config import DATA_DIR, LOGS_DIR, SNAPSHOTS_DIR

# === SETUP ===
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = os.path.join(LOGS_DIR, f"scan_run_{timestamp}.log")
dataset = []

def log(msg):
    print(msg)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def save_snapshot(body, idx):
    path = os.path.join(SNAPSHOTS_DIR, f"snapshot_{timestamp}_{idx}.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    return path

def has_reflected(payload, body):
    if not payload:
        return 0
    variants = [
        payload,
        html.unescape(payload),
        payload.lower(),
        html.unescape(payload).lower()
    ]
    for v in variants:
        if v in body:
            return 1
    return 0

def has_script_tags(body, payload=""):
    if not body:
        return 0

    soup = BeautifulSoup(body, "html.parser")
    scripts = soup.find_all("script")
    injected_keywords = ["alert(", "onerror=", "onload=", "onmouseover=", "javascript:"]

    # 1. Check for injected event handlers (only if payload is present)
    if payload:
        for kw in injected_keywords:
            if kw in body and payload in body:
                return 1

    # 2. Check for <script> tag containing payload
    for script in scripts:
        if script.string and payload and payload in script.string:
            return 1

    return 0

# === MAIN ===
log(f"[*] Scan started: {timestamp}")

# === 1. REFLECTED XSS ===
ref_csv = os.path.join(DATA_DIR, "payloads_reflected.csv")
if not os.path.exists(ref_csv):
    log(f"[!] ERROR: {ref_csv} not found!")
else:
    with open(ref_csv, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, 1):
            payload = row.get("payload", "").strip()
            payload_id = row.get("payload_id", f"R{i}").strip()
            if not payload_id:
                log(f"[!] Skipping row {i}: missing payload_id")
                continue

            try:
                resp = send_reflected(payload)
                snapshot = save_snapshot(resp["body"], f"R{i}")

                row_out = {
                    "payload_id": payload_id,
                    "url": resp["url"],
                    "method": resp["method"],
                    "injection_point": "q",
                    "payload": payload,
                    "response_time": round(resp["rtime"], 3),
                    "status_group": str(resp["status"])[0] + "xx",
                    "html_content_length": len(resp["body"]),
                    "reflected_payload_present": has_reflected(payload, resp["body"]),
                    "script_executed_flag": 0,
                    "error_message_flag": "error" in resp["body"].lower(),
                    "is_malicious": 0,
                    "notes": f"snapshot: {os.path.basename(snapshot)}"
                }

                # CORRECT AUTO-LABEL
                if (row_out["reflected_payload_present"] or 
                    has_script_tags(resp["body"], payload)):
                    row_out["is_malicious"] = 1
                else:
                    row_out["is_malicious"] = 0

                dataset.append(row_out)
                log(f"[R] {payload_id} → {row_out['is_malicious']} (ref={row_out['reflected_payload_present']})")

            except Exception as e:
                log(f"[!] REFLECTED ERROR on {payload_id}: {e}")

# === 2. STORED XSS ===
sto_csv = os.path.join(DATA_DIR, "payloads_stored.csv")
if not os.path.exists(sto_csv):
    log(f"[!] ERROR: {sto_csv} not found!")
else:
    with open(sto_csv, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, 1):
            payload = row.get("payload", "").strip()
            payload_id = row.get("payload_id", f"S{i}").strip()
            if not payload_id:
                log(f"[!] Skipping row {i}: missing payload_id")
                continue

            try:
                # Insert
                resp_insert = send_stored_insert(payload)
                time.sleep(1)  # Wait for DB
                # View
                resp_view = fetch_stored_view()
                snapshot = save_snapshot(resp_view["body"], f"S{i}")

                row_out = {
                    "payload_id": payload_id,
                    "url": resp_view["url"],
                    "method": "GET (after POST)",
                    "injection_point": "comment",
                    "payload": payload,
                    "response_time": round(resp_view["rtime"], 3),
                    "status_group": str(resp_view["status"])[0] + "xx",
                    "html_content_length": len(resp_view["body"]),
                    "reflected_payload_present": has_reflected(payload, resp_view["body"]),
                    "script_executed_flag": 0,
                    "error_message_flag": "error" in resp_view["body"].lower(),
                    "is_malicious": 0,
                    "notes": f"insert_status={resp_insert['status']}; snapshot: {os.path.basename(snapshot)}"
                }

                # CORRECT AUTO-LABEL
                if (row_out["reflected_payload_present"] or 
                    has_script_tags(resp_view["body"], payload)):
                    row_out["is_malicious"] = 1
                else:
                    row_out["is_malicious"] = 0

                dataset.append(row_out)
                log(f"[S] {payload_id} → {row_out['is_malicious']} (insert={resp_insert['status']})")

            except Exception as e:
                log(f"[!] STORED ERROR on {payload_id}: {e}")

# === SAVE DATASET ===
if dataset:
    out_csv = os.path.join(DATA_DIR, "xss_response_dataset.csv")
    keys = dataset[0].keys()
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(dataset)
    log(f"[+] Dataset saved: {out_csv} ({len(dataset)} rows)")
else:
    log("[!] No data collected!")

log(f"[+] Logs & snapshots in {LOGS_DIR}")