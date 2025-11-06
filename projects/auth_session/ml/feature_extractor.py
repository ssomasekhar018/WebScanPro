#!/usr/bin/env python3
"""
Feature Extractor for Authentication & Session Security Dataset

Extracts ML-ready features from raw login/session events for anomaly detection models.
"""

import csv
import os
import sys
import math
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional
import statistics

# Add parent directory to path for imports
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
DATA_DIR = os.path.join(BASE_DIR, "projects", "auth_session", "data")

# Input/Output files
INPUT_DATASET = os.path.join(DATA_DIR, "login_session_dataset.csv")
OUTPUT_DATASET = os.path.join(DATA_DIR, "feature_dataset.csv")

# Rolling window settings (in seconds)
WINDOW_5M = 300   # 5 minutes
WINDOW_15M = 900  # 15 minutes
WINDOW_60M = 3600 # 60 minutes


class FeatureExtractor:
    """Extracts ML features from raw authentication events."""
    
    def __init__(self, input_file: str = INPUT_DATASET, output_file: str = OUTPUT_DATASET):
        self.input_file = input_file
        self.output_file = output_file
        self.events = []
        self.features = []
        
    def load_events(self):
        """Load events from CSV dataset."""
        if not os.path.exists(self.input_file):
            print(f"ERROR: Input file not found: {self.input_file}")
            sys.exit(1)
            
        print(f"Loading events from {self.input_file}...")
        with open(self.input_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Parse timestamp
                try:
                    row['timestamp_parsed'] = datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
                except:
                    row['timestamp_parsed'] = datetime.now()
                self.events.append(row)
                
        print(f"Loaded {len(self.events)} events")
        
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        from collections import Counter
        counts = Counter(text)
        length = len(text)
        entropy = -sum((count / length) * math.log2(count / length) 
                      for count in counts.values() if count > 0)
        return entropy
        
    def extract_username_features(self, username: str, current_time: datetime, 
                                  events: List[Dict]) -> Dict:
        """Extract features aggregated per username."""
        username_events = [e for e in events if e.get('username_anon') == username]
        
        # Filter by time windows
        events_5m = [e for e in username_events 
                    if (current_time - e['timestamp_parsed']).total_seconds() <= WINDOW_5M]
        events_15m = [e for e in username_events 
                     if (current_time - e['timestamp_parsed']).total_seconds() <= WINDOW_15M]
        events_60m = [e for e in username_events 
                     if (current_time - e['timestamp_parsed']).total_seconds() <= WINDOW_60M]
        
        # Count failures and successes
        failures_5m = sum(1 for e in events_5m if e.get('auth_result') == 'failure')
        failures_15m = sum(1 for e in events_15m if e.get('auth_result') == 'failure')
        failures_60m = sum(1 for e in events_60m if e.get('auth_result') == 'failure')
        
        successes_60m = sum(1 for e in events_60m if e.get('auth_result') == 'success')
        
        # Calculate failure-to-success ratio
        if successes_60m > 0:
            fail_success_ratio = failures_60m / successes_60m
        else:
            fail_success_ratio = failures_60m if failures_60m > 0 else 0.0
            
        # Distinct IPs and user agents
        distinct_ips_60m = len(set(e.get('ip_address_anon', '') for e in events_60m if e.get('ip_address_anon')))
        distinct_user_agents_60m = len(set(e.get('user_agent', '') for e in events_60m if e.get('user_agent')))
        
        # Calculate average time between attempts
        if len(events_60m) > 1:
            timestamps = sorted([e['timestamp_parsed'] for e in events_60m])
            intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                        for i in range(len(timestamps)-1)]
            avg_time_between_attempts = statistics.mean(intervals) if intervals else 0.0
        else:
            avg_time_between_attempts = 0.0
            
        # Username entropy (for detecting automated usernames)
        username_entropy = self.calculate_entropy(username)
        
        return {
            'fail_count_5m': failures_5m,
            'fail_count_15m': failures_15m,
            'fail_count_60m': failures_60m,
            'succ_count_60m': successes_60m,
            'fail_success_ratio': fail_success_ratio,
            'distinct_ips_60m': distinct_ips_60m,
            'distinct_user_agents_60m': distinct_user_agents_60m,
            'avg_time_between_attempts': avg_time_between_attempts,
            'entropy_of_username': username_entropy,
        }
        
    def extract_ip_features(self, ip: str, current_time: datetime, 
                            events: List[Dict]) -> Dict:
        """Extract features aggregated per IP address."""
        ip_events = [e for e in events if e.get('ip_address_anon') == ip]
        
        # Filter by time window (60 minutes)
        events_60m = [e for e in ip_events 
                     if (current_time - e['timestamp_parsed']).total_seconds() <= WINDOW_60M]
        
        # Attempts per minute
        if events_60m:
            total_attempts = len(events_60m)
            time_span = max((current_time - e['timestamp_parsed']).total_seconds() 
                          for e in events_60m)
            if time_span > 0:
                attempts_per_minute = (total_attempts * 60) / time_span
            else:
                attempts_per_minute = total_attempts * 60  # If all same timestamp
        else:
            attempts_per_minute = 0.0
            
        # Distinct usernames attempted
        distinct_usernames = len(set(e.get('username_anon', '') for e in events_60m if e.get('username_anon')))
        
        # Suspicious IP flag (placeholder - could integrate with proxy/TOR databases)
        suspicious_ip_flag = 0  # TODO: Implement IP reputation check
        
        return {
            'attempts_per_minute': attempts_per_minute,
            'distinct_usernames_attempted': distinct_usernames,
            'suspicious_ip_flag': suspicious_ip_flag,
        }
        
    def extract_session_features(self, session_id: str, current_time: datetime,
                                 events: List[Dict]) -> Dict:
        """Extract features for a session."""
        session_events = [e for e in events if e.get('session_id') == session_id]
        
        if not session_events:
            return {
                'session_duration_seconds': 0,
                'actions_after_login_count': 0,
                'session_ip_variation_flag': 0,
            }
            
        # Find session creation (first success event)
        login_events = [e for e in session_events if e.get('auth_result') == 'success']
        if login_events:
            session_start = min(e['timestamp_parsed'] for e in login_events)
            session_duration = (current_time - session_start).total_seconds()
        else:
            session_duration = 0
            
        # Count actions after login (non-login events after first login)
        if login_events:
            first_login_time = min(e['timestamp_parsed'] for e in login_events)
            actions_after_login = sum(1 for e in session_events 
                                     if e.get('endpoint') not in ['/login', '/login.php'] and
                                        e['timestamp_parsed'] > first_login_time)
        else:
            actions_after_login = 0
            
        # Check for IP variation
        ips = set(e.get('ip_address_anon', '') for e in session_events if e.get('ip_address_anon'))
        session_ip_variation_flag = 1 if len(ips) > 1 else 0
        
        return {
            'session_duration_seconds': session_duration,
            'actions_after_login_count': actions_after_login,
            'session_ip_variation_flag': session_ip_variation_flag,
        }
        
    def extract_temporal_features(self, timestamp: datetime) -> Dict:
        """Extract temporal/behavioral features."""
        login_hour_local = timestamp.hour
        weekday = timestamp.weekday()  # 0=Monday, 6=Sunday
        
        return {
            'login_hour_local': login_hour_local,
            'weekday': weekday,
        }
        
    def extract_engineered_features(self, event: Dict, username_features: Dict, 
                                   ip_features: Dict) -> Dict:
        """Extract engineered/composite features."""
        # Velocity score: combination of attempts and IP changes
        attempts_score = min(username_features.get('fail_count_60m', 0) / 10.0, 1.0)
        ip_change_score = min(username_features.get('distinct_ips_60m', 0) / 5.0, 1.0)
        velocity_score = (attempts_score + ip_change_score) / 2.0
        
        # Geolocation change flag (placeholder - requires geolocation data)
        geolocation_change_flag = 0  # TODO: Implement if geolocation data available
        
        return {
            'velocity_score': velocity_score,
            'geolocation_change_flag': geolocation_change_flag,
        }
        
    def extract_features_for_event(self, event: Dict, all_events: List[Dict]) -> Dict:
        """Extract all features for a single event."""
        timestamp = event['timestamp_parsed']
        username = event.get('username_anon', '')
        ip = event.get('ip_address_anon', '')
        session_id = event.get('session_id', '')
        
        # Extract feature groups
        username_features = self.extract_username_features(username, timestamp, all_events)
        ip_features = self.extract_ip_features(ip, timestamp, all_events)
        session_features = self.extract_session_features(session_id, timestamp, all_events) if session_id else {
            'session_duration_seconds': 0,
            'actions_after_login_count': 0,
            'session_ip_variation_flag': 0,
        }
        temporal_features = self.extract_temporal_features(timestamp)
        engineered_features = self.extract_engineered_features(event, username_features, ip_features)
        
        # Combine all features
        feature_row = {
            # Event identifiers
            'event_id': event.get('event_id', ''),
            'timestamp': event.get('timestamp', ''),
            'username_anon': username,
            'ip_address_anon': ip,
            
            # Username features
            **username_features,
            
            # IP features
            **ip_features,
            
            # Session features
            **session_features,
            
            # Temporal features
            **temporal_features,
            
            # Engineered features
            **engineered_features,
            
            # Labels (from original event)
            'auth_result': event.get('auth_result', ''),
            'is_bruteforce_candidate': event.get('is_bruteforce_candidate', 0),
            'is_anomalous': event.get('is_anomalous', 0),
        }
        
        return feature_row
        
    def extract_all_features(self):
        """Extract features for all events."""
        print("Extracting features...")
        
        for i, event in enumerate(self.events):
            if (i + 1) % 100 == 0:
                print(f"Processing event {i+1}/{len(self.events)}...")
                
            feature_row = self.extract_features_for_event(event, self.events)
            self.features.append(feature_row)
            
        print(f"Extracted features for {len(self.features)} events")
        
    def save_features(self):
        """Save extracted features to CSV."""
        if not self.features:
            print("No features to save")
            return
            
        print(f"Saving features to {self.output_file}...")
        
        # Get all unique column names
        columns = set()
        for row in self.features:
            columns.update(row.keys())
        columns = sorted(list(columns))
        
        # Write CSV
        with open(self.output_file, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            writer.writerows(self.features)
            
        print(f"Saved {len(self.features)} feature rows to {self.output_file}")
        
    def run(self):
        """Run full feature extraction pipeline."""
        print("=== Feature Extractor ===")
        self.load_events()
        self.extract_all_features()
        self.save_features()
        print("=== Complete ===")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Extract ML features from authentication dataset")
    parser.add_argument("--input", default=INPUT_DATASET, help="Input dataset CSV file")
    parser.add_argument("--output", default=OUTPUT_DATASET, help="Output feature dataset CSV file")
    
    args = parser.parse_args()
    
    extractor = FeatureExtractor(input_file=args.input, output_file=args.output)
    extractor.run()


if __name__ == "__main__":
    main()

