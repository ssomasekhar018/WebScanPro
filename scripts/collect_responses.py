import pandas as pd
import requests
import time
import os
import re
from datetime import datetime

# Configuration
BASE_URL = "http://localhost/dvwa"  # Adjust to your DVWA URL
OUTPUT_DIR = "../outputs/response_logs"
CSV_PATH = "../data/endpoints.csv"
OUTPUT_CSV = "../data/raw_server_responses.csv"
ERROR_KEYWORDS = ["sql syntax", "warning", "exception", "error", "fatal", "mysql_fetch"]  # Add more as needed

# Ensure output dir exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Load existing dataset
df = pd.read_csv(CSV_PATH)

# Define payloads (customize per input_type if needed)
def get_payloads(input_type, default_value):
    safe_payload = default_value if pd.notna(default_value) else "test"
    if "sql" in input_type.lower() or "id" in input_type.lower():
        injection_payload = "' OR 1=1--"
    else:  # Default for text, e.g., XSS
        injection_payload = "<script>alert('xss')</script>"
    return safe_payload, injection_payload

# Function to send request and capture attributes
def send_request(row, payload, label):
    url = row['url']
    method = row['method'].upper()
    param_name = row['param_name']
    form_action = row['form_action']
    
    # Prepare params/data
    if method == 'GET':
        params = {param_name: payload}
        data = None
    else:  # POST
        params = None
        data = {param_name: payload}
    
    start_time = time.time()
    try:
        if form_action and form_action != url:
            url = form_action  # Use form_action if different
        response = requests.request(method, url, params=params, data=data, timeout=10)
        response_time = (time.time() - start_time) * 1000  # ms
        status = response.status_code
        content_length = len(response.text)
        
        # Check for error flag
        error_flag = 1 if any(re.search(keyword, response.text.lower()) for keyword in ERROR_KEYWORDS) else 0
        
        # Optional: Save full response
        safe_filename = payload.replace('/', '_').replace(' ', '_')[:50]  # Sanitize
        response_path = os.path.join(OUTPUT_DIR, f"{url.split('/')[-1]}_{param_name}_{label}_{safe_filename}.txt")
        with open(response_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        return {
            'input_value': payload,
            'label': label,
            'response_status': status,
            'response_time': round(response_time, 2),
            'html_content_length': content_length,
            'error_message_flag': error_flag,
            'response_body_path': response_path
        }
    except Exception as e:
        print(f"Request failed for {url} {payload}: {e}")
        return {
            'input_value': payload,
            'label': label,
            'response_status': 0,
            'response_time': 0,
            'html_content_length': 0,
            'error_message_flag': 0,
            'response_body_path': ''
        }

# Process each row
enhanced_rows = []
for idx, row in df.iterrows():
    safe_payload, injection_payload = get_payloads(row['input_type'], row['default_value'])
    
    # Safe request
    safe_attrs = send_request(row, safe_payload, 'safe')
    enhanced_row_safe = {**row.to_dict(), **safe_attrs}
    enhanced_rows.append(enhanced_row_safe)
    
    # Injection request
    injection_attrs = send_request(row, injection_payload, 'injection')
    enhanced_row_injection = {**row.to_dict(), **injection_attrs}
    enhanced_rows.append(enhanced_row_injection)

# Create enhanced DataFrame and save
enhanced_df = pd.DataFrame(enhanced_rows)
enhanced_df.to_csv(OUTPUT_CSV, index=False)
print(f"Enhanced dataset saved to {OUTPUT_CSV}")
print(enhanced_df.head())  # Preview