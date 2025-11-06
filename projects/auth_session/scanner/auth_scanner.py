#!/usr/bin/env python3
"""
Authentication & Session Security Scanner

Simulates login attempts and session lifecycle events to generate labeled dataset
for ML anomaly detection training.
"""

import csv
import json
import os
import time
import random
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional

# Import configuration and core utilities
from .config import (
    DATA_DIR, LOGS_DIR, PATTERNS_CSV, DATASET_CSV,
    DEFAULT_LOGIN_URL, HASH_SALT,
    WINDOW_5M, WINDOW_10M, WINDOW_15M, WINDOW_60M,
    LABELING_THRESHOLDS, SCAN_OPTIONS,
    VALID_USERS, INVALID_PASSWORDS,
    get_timestamp, get_log_file, get_raw_events_file
)
from .core import (
    anonymize_ip, anonymize_username, anonymize_session_id,
    generate_event_id, make_http_request, parse_auth_result, extract_session_id,
    get_random_user_agent
)

import requests

# === LOGGING ===
timestamp = get_timestamp()
log_file = get_log_file()
raw_events_file = get_raw_events_file()
dataset_file = DATASET_CSV

def log(msg, level="INFO"):
    """Log message to console and log file."""
    ts = datetime.now().isoformat()
    log_msg = f"[{ts}] [{level}] {msg}"
    print(log_msg)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")


# === EVENT TRACKING ===
class EventTracker:
    """Tracks events for rolling window calculations."""
    
    def __init__(self):
        self.events_by_username: Dict[str, deque] = defaultdict(deque)
        self.events_by_ip: Dict[str, deque] = defaultdict(deque)
        self.sessions: Dict[str, Dict] = {}  # session_id -> session_data
        self.usernames: Dict[str, str] = {}  # real -> anonymized mapping
        
    def add_event(self, event: Dict):
        """Add event to tracking queues."""
        username = event.get('username_anon', '')
        ip = event.get('ip_address_anon', '')
        timestamp_str = event.get('timestamp')
        
        # Parse timestamp string to datetime
        try:
            if isinstance(timestamp_str, str):
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                timestamp = timestamp_str if isinstance(timestamp_str, datetime) else datetime.now()
        except:
            timestamp = datetime.now()
        
        if username:
            self.events_by_username[username].append((timestamp, event))
        if ip:
            self.events_by_ip[ip].append((timestamp, event))
            
    def cleanup_old_events(self, window_seconds: int = WINDOW_60M):
        """Remove events older than window from queues."""
        cutoff = datetime.now() - timedelta(seconds=window_seconds)
        for username in list(self.events_by_username.keys()):
            queue = self.events_by_username[username]
            while queue and queue[0][0] < cutoff:
                queue.popleft()
        for ip in list(self.events_by_ip.keys()):
            queue = self.events_by_ip[ip]
            while queue and queue[0][0] < cutoff:
                queue.popleft()
                
    def count_attempts_for_username(self, username: str, window_seconds: int = 600) -> int:
        """Count login attempts for username in rolling window."""
        cutoff = datetime.now() - timedelta(seconds=window_seconds)
        count = 0
        for ts, event in self.events_by_username.get(username, []):
            if ts >= cutoff and event.get('endpoint') in ['/login', '/login.php']:
                count += 1
        return count
        
    def count_attempts_from_ip(self, ip: str, window_seconds: int = 600) -> int:
        """Count login attempts from IP in rolling window."""
        cutoff = datetime.now() - timedelta(seconds=window_seconds)
        count = 0
        for ts, event in self.events_by_ip.get(ip, []):
            if ts >= cutoff and event.get('endpoint') in ['/login', '/login.php']:
                count += 1
        return count
        
    def get_distinct_ips_for_username(self, username: str, window_seconds: int = WINDOW_60M) -> int:
        """Count distinct IPs attempting username in window."""
        cutoff = datetime.now() - timedelta(seconds=window_seconds)
        ips = set()
        for ts, event in self.events_by_username.get(username, []):
            if ts >= cutoff:
                ips.add(event.get('ip_address_anon', ''))
        return len(ips)
        
    def get_last_attempt_time(self, username: str) -> Optional[datetime]:
        """Get timestamp of last login attempt for username."""
        events = self.events_by_username.get(username, [])
        if not events:
            return None
        login_events = [(ts, ev) for ts, ev in events if ev.get('endpoint') in ['/login', '/login.php']]
        if not login_events:
            return None
        return max(ts for ts, _ in login_events)


# EventTracker instance (will be created per scanner instance)


# === AUTH SCANNER ===
class AuthScanner:
    """Main scanner class for simulating authentication events."""
    
    def __init__(self, base_url: str = DEFAULT_LOGIN_URL):
        self.base_url = base_url
        self.tracker = EventTracker()
        self.dataset_rows = []
        
        # Test credentials pool (from config)
        self.valid_users = VALID_USERS
        self.invalid_passwords = INVALID_PASSWORDS
        
    def anonymize_username(self, username: str) -> str:
        """Get or create anonymized username."""
        if username not in self.tracker.usernames:
            self.tracker.usernames[username] = anonymize_username(username)
        return self.tracker.usernames[username]
        
    def simulate_login(self, username: str, password: str, ip_address: str = None, 
                      user_agent: str = None) -> Dict:
        """Simulate a login attempt and capture event data."""
        event_id = generate_event_id()
        timestamp = datetime.now()
        
        # Setup request
        if ip_address:
            # Simulate IP by setting X-Forwarded-For or using proxy (lab only)
            headers = {"X-Forwarded-For": ip_address}
        else:
            headers = {}
            
        if user_agent:
            headers["User-Agent"] = user_agent
        else:
            headers["User-Agent"] = get_random_user_agent()
            
        # Determine if this should succeed
        is_valid = (username, password) in self.valid_users
        
        # Make request
        login_data = {"username": username, "password": password}
        response = make_http_request(
            self.base_url,
            method="POST",
            data=login_data,
            headers=headers
        )
        
        if response:
            status_code = response.status_code
            error = None
        else:
            status_code = 0
            error = "Request failed"
            
        # Determine auth result
        auth_result, failure_reason = parse_auth_result(status_code, username, self.valid_users)
        
        # Extract session ID
        if response and status_code == 200:
            session_id = extract_session_id(response)
            if not session_id:
                # Generate synthetic session ID for testing
                session_id = f"{event_id}_{timestamp}"
        else:
            session_id = None
            
        # Anonymize data
        username_anon = self.anonymize_username(username)
        ip_anon = anonymize_ip(ip_address) if ip_address else anonymize_ip("127.0.0.1")
        session_id_anon = anonymize_session_id(session_id) if session_id else None
        
        # Build event
        log("Creating event dictionary...")
        event = {
            "event_id": generate_event_id(),
            "timestamp": timestamp.isoformat(),
            "username": username_anon,  # Already anonymized
            "username_anon": username_anon,
            "ip_address": ip_anon,  # Already anonymized
            "ip_address_anon": ip_anon,
            "user_agent": headers.get("User-Agent", ""),
            "endpoint": "/login",
            "method": "POST",
            "status_code": status_code,
            "auth_result": auth_result,
            "failure_reason": failure_reason or "",
            "session_id": session_id_anon,
            "password_correct_flag": 1 if is_valid else 0,
        }
        log("Event dictionary created.")
        
        # Compute rolling window counts
        log("Computing rolling window counts...")
        self.tracker.add_event(event)
        self.tracker.cleanup_old_events()
        log("Tracker updated.")
        
        event["attempt_count_for_username"] = self.tracker.count_attempts_for_username(username_anon, WINDOW_10M)
        event["attempt_count_from_ip"] = self.tracker.count_attempts_from_ip(ip_anon, WINDOW_10M)
        log("Rolling window counts computed.")
        
        last_attempt = self.tracker.get_last_attempt_time(username_anon)
        if last_attempt:
            time_since = (timestamp - last_attempt).total_seconds()
        else:
            time_since = None
        event["time_since_last_attempt_for_username"] = time_since if time_since else 0
        log("Time since last attempt computed.")
        
        # Initialize session if successful
        if auth_result == "success" and session_id_anon:
            log("Initializing session...")
            self.tracker.sessions[session_id_anon] = {
                "username": username_anon,
                "ip": ip_anon,
                "created_at": timestamp,
                "user_agent": headers.get("User-Agent", ""),
            }
            log("Session initialized.")

        # Convert datetime to string for JSON serialization
        event_for_ml = event.copy()

        # Call ML model
        log(f"Sending event to ML model: {event_for_ml}")
        ml_response = make_http_request("http://127.0.0.1:5000/predict", json=event_for_ml)
        if ml_response and ml_response.status_code == 200:
            ml_data = ml_response.json()
            event['iforest_score'] = ml_data.get('iforest_score')
            event['autoencoder_error'] = ml_data.get('autoencoder_error')
            event['ml_final_label'] = ml_data.get('final_label')
        else:
            error_message = ml_response.text if ml_response is not None else "No response"
            log(f"ML model prediction failed: {error_message}", "ERROR")
            
        return event
        
    def apply_labeling_heuristics(self, event: Dict) -> Dict:
        """Apply automated labeling heuristics."""
        event = event.copy()
        thresholds = LABELING_THRESHOLDS
        
        # is_bruteforce_candidate
        is_bf = 0
        if (event.get("attempt_count_for_username", 0) >= thresholds["bruteforce_username_attempts"]) or \
           (event.get("attempt_count_from_ip", 0) >= thresholds["bruteforce_ip_attempts"]) or \
           (self.tracker.get_distinct_ips_for_username(event.get("username_anon", ""), WINDOW_60M) >= thresholds["credential_stuffing_distinct_ips"]):
            is_bf = 1
        event["is_bruteforce_candidate"] = is_bf
        
        # is_anomalous
        is_anomalous = 0
        if is_bf:
            is_anomalous = 1
        elif event.get("status_code") == 429:
            is_anomalous = 1
        elif event.get("auth_result") == "success" and event.get("attempt_count_for_username", 0) >= thresholds["account_takeover_failed_before_success"]:
            is_anomalous = 1
            
        event["is_anomalous"] = is_anomalous
        
        # session_reused_flag (check if session used from different IP)
        session_id = event.get("session_id")
        if session_id and session_id in self.tracker.sessions:
            session_data = self.tracker.sessions[session_id]
            if session_data.get("ip") != event.get("ip_address_anon"):
                event["session_reused_flag"] = 1
            else:
                event["session_reused_flag"] = 0
        else:
            event["session_reused_flag"] = 0
            
        # Defaults for missing fields
        event.setdefault("geolocation", "")
        event.setdefault("session_duration", 0)
        event.setdefault("notes", "")
        
        return event
        
    def save_event(self, event: Dict):
        """Save event to raw log and dataset CSV."""
        # Save to raw log
        with open(raw_events_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
            
        # Add to dataset
        self.dataset_rows.append(event)
        
    def save_dataset(self):
        """Save final dataset to CSV."""
        if not self.dataset_rows:
            log("No events to save", "WARNING")
            return
            
        # Define CSV columns
        columns = [
            "event_id", "timestamp", "username", "username_anon", "ip_address", "ip_address_anon",
            "user_agent", "endpoint", "method", "status_code", "auth_result", "failure_reason",
            "attempt_count_for_username", "attempt_count_from_ip",
            "time_since_last_attempt_for_username", "session_id", "session_duration",
            "session_reused_flag", "password_correct_flag", "is_bruteforce_candidate",
            "is_anomalous", "geolocation", "notes"
        ]
        
        # Check if file exists to append or create
        file_exists = os.path.exists(dataset_file)
        
        with open(dataset_file, "a", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            if not file_exists:
                writer.writeheader()
            writer.writerows(self.dataset_rows)
            
        log(f"Saved {len(self.dataset_rows)} events to {dataset_file}")
        self.dataset_rows = []
        
    def run_pattern(self, pattern: Dict, duration_minutes: int = None):
        """Run a single attack pattern."""
        if duration_minutes is None:
            duration_minutes = SCAN_OPTIONS["pattern_duration_minutes"]
            
        pattern_id = pattern.get("pattern_id", "")
        description = pattern.get("description", "")
        attempt_rate = float(pattern.get("attempt_rate", 1.0))
        distributed = int(pattern.get("distributed_flag", 0))
        
        log(f"Running pattern: {pattern_id} - {description}")
        
        # Calculate delay between attempts
        if attempt_rate > 0:
            delay = 60.0 / attempt_rate  # seconds between attempts
        else:
            delay = 0
            
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        attempt_count = 0
        
        # Select test users
        if "NORMAL" in pattern_id or "FAIL" in pattern_id:
            users = [self.valid_users[0]]  # Single user for normal flows
        elif "BF" in pattern_id or "CS" in pattern_id:
            users = self.valid_users + [("attacker_user", "wrong")]  # Mix of valid and invalid
        else:
            users = self.valid_users
            
        # Generate IPs if distributed
        if distributed:
            ips = [f"192.168.1.{i}" for i in range(100, 110)]
        else:
            ips = ["192.168.1.100"]
            
        while True:
            # Select username/password
            if "VALID_MAL" in pattern_id:
                # Valid login then suspicious
                if attempt_count == 0:
                    username, password = self.valid_users[0]
                else:
                    username, password = random.choice(self.valid_users), random.choice(self.invalid_passwords)
            elif random.random() < 0.3 and "BF" not in pattern_id:  # 30% failures for variety
                username, password = random.choice(self.valid_users)[0], random.choice(self.invalid_passwords)
            else:
                username, password = random.choice(users)
                
            # Select IP
            ip = random.choice(ips) if distributed else ips[0]
            
            # Simulate login
            event = self.simulate_login(username, password, ip)
            event = self.apply_labeling_heuristics(event)
            self.save_event(event)
            
            attempt_count += 1
            
            if datetime.now() >= end_time and attempt_count > 0:
                break

            # Sleep
            if delay > 0:
                time.sleep(delay)
                
        log(f"Completed pattern {pattern_id}: {attempt_count} attempts")


def main():
    """Main entry point."""
    log("=== Authentication & Session Security Scanner ===")
    log(f"Log file: {log_file}")
    log(f"Raw events: {raw_events_file}")
    log(f"Dataset: {dataset_file}")
    
    # Load attack patterns
    if not os.path.exists(PATTERNS_CSV):
        log(f"Patterns file not found: {PATTERNS_CSV}", "ERROR")
        return
        
    patterns = []
    with open(PATTERNS_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        patterns = list(reader)
        
    log(f"Loaded {len(patterns)} attack patterns")
    
    # Initialize scanner
    scanner = AuthScanner()
    
    # Run each pattern
    for pattern in patterns:
        try:
            scanner.run_pattern(pattern)  # Uses duration from SCAN_OPTIONS
        except Exception as e:
            log(f"Error running pattern {pattern.get('pattern_id')}: {e}", "ERROR")
            
    # Save final dataset
    scanner.save_dataset()
    
    log("=== Scanner Complete ===")
    log(f"Total events captured: {len(scanner.dataset_rows) if scanner.dataset_rows else 'See dataset file'}")


if __name__ == "__main__":
    main()

