import csv
import hashlib
import json
import logging
import os
import random
import time
import uuid
from datetime import datetime, timezone

# --- Configuration ---
# File paths
LOGS_DIR = 'c:/Users/somas/OneDrive/Documents/Infosys Springboard/project-root/projects/auth_session/logs'
DATA_DIR = 'c:/Users/somas/OneDrive/Documents/Infosys Springboard/project-root/projects/auth_session/data'
ATTACK_PATTERNS_FILE = os.path.join(DATA_DIR, 'attack_patterns.csv')
RAW_LOG_FILE = os.path.join(LOGS_DIR, f'raw_login_events_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
DATASET_FILE = os.path.join(DATA_DIR, 'login_session_dataset.csv')

# Create directories if they don't exist
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# Mock authentication endpoint
AUTH_ENDPOINT_URL = 'http://localhost:5000/login'  # A mock server should be running this

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, f'scan_run_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')),
        logging.StreamHandler()
    ]
)

# --- Helper Functions ---
def get_hashed_value(value: str, salt: str = 'default_salt') -> str:
    """Hashes a string value using SHA-256 for anonymization."""
    return hashlib.sha256((value + salt).encode()).hexdigest()

def get_iso_timestamp() -> str:
    """Returns the current time in UTC ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()

# --- Mock Authentication Server Interaction ---
def mock_login_attempt(username: str, ip_address: str, user_agent: str) -> dict:
    """Simulates a login attempt and returns a mock response."""
    # In a real scenario, this would make an HTTP request.
    # Here, we simulate outcomes based on the username.
    password_correct = random.choice([True, False, False, False]) # 25% chance of success
    
    if 'admin' in username or 'ceo' in username:
        # Simulate higher failure rate for sensitive accounts
        password_correct = random.choice([True, False, False, False, False, False])

    if password_correct:
        return {
            'status_code': 200,
            'auth_result': 'success',
            'session_id': get_hashed_value(str(uuid.uuid4())),
            'failure_reason': None
        }
    else:
        return {
            'status_code': 401,
            'auth_result': 'failure',
            'session_id': None,
            'failure_reason': 'wrong password'
        }

# --- Main Scanner Logic ---
class AuthScanner:
    def __init__(self):
        self.event_history = []
        self.initialize_dataset_file()

    def initialize_dataset_file(self):
        """Creates the CSV file with headers if it doesn't exist."""
        if not os.path.exists(DATASET_FILE):
            with open(DATASET_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'event_id', 'timestamp', 'username', 'user_id', 'ip_address',
                    'user_agent', 'endpoint', 'method', 'status_code', 'auth_result',
                    'failure_reason', 'attempt_count_for_username', 'attempt_count_from_ip',
                    'time_since_last_attempt_for_username', 'session_id', 'is_bruteforce_candidate',
                    'is_anomalous', 'notes'
                ])

    def log_raw_event(self, event_data: dict):
        """Logs the raw, unprocessed event to a log file."""
        with open(RAW_LOG_FILE, 'a') as f:
            f.write(json.dumps(event_data) + '\n')

    def append_to_dataset(self, processed_event: dict):
        """Appends a processed and sanitized event to the main CSV dataset."""
        with open(DATASET_FILE, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=processed_event.keys())
            writer.writerow(processed_event)

    def process_and_label_event(self, raw_event: dict) -> dict:
        """Sanitizes, enriches, and labels an event before storing it."""
        # --- Sanitization ---
        processed = {
            'event_id': str(uuid.uuid4()),
            'timestamp': raw_event['timestamp'],
            'username': get_hashed_value(raw_event['username']),
            'user_id': get_hashed_value(raw_event.get('user_id', raw_event['username'])),
            'ip_address': get_hashed_value(raw_event['ip_address']),
            'user_agent': raw_event['user_agent'],
            'endpoint': '/login',
            'method': 'POST',
            'status_code': raw_event['response']['status_code'],
            'auth_result': raw_event['response']['auth_result'],
            'failure_reason': raw_event['response']['failure_reason'],
            'session_id': raw_event['response'].get('session_id')
        }

        # --- Enrichment (calculating rolling window stats) ---
        # These are simplified for this script. A real system would use a database or cache.
        username_events = [e for e in self.event_history if e['username'] == processed['username']]
        ip_events = [e for e in self.event_history if e['ip_address'] == processed['ip_address']]
        
        processed['attempt_count_for_username'] = len(username_events) + 1
        processed['attempt_count_from_ip'] = len(ip_events) + 1
        
        if username_events:
            last_event_time = datetime.fromisoformat(username_events[-1]['timestamp'])
            processed['time_since_last_attempt_for_username'] = (datetime.fromisoformat(processed['timestamp']) - last_event_time).total_seconds()
        else:
            processed['time_since_last_attempt_for_username'] = 0

        # --- Labeling Heuristics ---
        processed['is_bruteforce_candidate'] = 0
        processed['is_anomalous'] = 0
        processed['notes'] = ''

        if processed['attempt_count_for_username'] >= 10:
            processed['is_bruteforce_candidate'] = 1
            processed['notes'] += 'High attempt count for username. '

        if processed['attempt_count_from_ip'] >= 50:
            processed['is_bruteforce_candidate'] = 1
            processed['notes'] += 'High attempt count from IP. '

        if raw_event.get('scenario_id') in ['7', '10'] and processed['auth_result'] == 'success':
             processed['is_anomalous'] = 1
             processed['notes'] += 'Anomalous success pattern. '

        return processed

    def run_scenario(self, scenario: dict):
        """Executes a single attack scenario."""
        logging.info(f"Running scenario: {scenario['scenario_id']} - {scenario['description']}")
        num_attempts = int(scenario['num_attempts'])
        
        for i in range(num_attempts):
            # Simulate different IPs if required by the scenario
            if scenario['ip_source'] == 'multiple_ips':
                ip_address = f"10.0.{random.randint(0, 255)}.{random.randint(0, 255)}"
            else:
                ip_address = "192.168.1.100"

            # Simulate different user agents
            user_agent = random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'python-requests/2.25.1',
                'curl/7.68.0'
            ])

            username = scenario['target_username'] if scenario['target_username'] != 'N/A' else f'user_{uuid.uuid4().hex[:6]}'

            # Simulate the login
            response = mock_login_attempt(username, ip_address, user_agent)

            # Create the raw event log
            raw_event = {
                'scenario_id': scenario['scenario_id'],
                'timestamp': get_iso_timestamp(),
                'username': username,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'response': response
            }
            
            self.log_raw_event(raw_event)
            
            # Process, label, and store the event
            processed_event = self.process_and_label_event(raw_event)
            self.append_to_dataset(processed_event)
            self.event_history.append(processed_event) # Keep history for enrichment

            # Simulate time passing between attempts
            time.sleep(random.uniform(0.1, 1.0) if num_attempts > 20 else random.uniform(1, 3))

    def run(self):
        """Main execution loop to run all scenarios."""
        logging.info("Starting authentication scanner...")
        try:
            with open(ATTACK_PATTERNS_FILE, 'r') as f:
                reader = csv.DictReader(f)
                scenarios = list(reader)
        except FileNotFoundError:
            logging.error(f"Attack patterns file not found at: {ATTACK_PATTERNS_FILE}")
            return

        for scenario in scenarios:
            self.run_scenario(scenario)
        
        logging.info(f"Scanner finished. Dataset saved to: {DATASET_FILE}")

if __name__ == "__main__":
    scanner = AuthScanner()
    scanner.run()

