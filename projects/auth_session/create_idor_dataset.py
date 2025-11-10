
import pandas as pd
import requests
import os

# Create necessary directories
os.makedirs("data/raw_requests", exist_ok=True)
os.makedirs("docs", exist_ok=True)

# Define users and their resources
users = {
    "user_a": {"owned_resources": ["101", "102"]},
    "user_b": {"owned_resources": ["201", "202"]}
}

# Base URL for the mock server
base_url = "http://127.0.0.1:5000"

def collect_and_label_data():
    """
    Collects data from the mock server, labels it for IDOR, and saves it to a CSV file.
    """
    records = []
    request_id = 0

    for user, data in users.items():
        owned_resources = data["owned_resources"]
        other_resources = [res for res_owner in users.values() for res in res_owner["owned_resources"] if res not in owned_resources]

        # Test access to owned resources (authorized)
        for resource_id in owned_resources:
            request_id += 1
            headers = {"X-User-ID": user}
            response = requests.get(f"{base_url}/user/profile?id={resource_id}", headers=headers)
            records.append({
                "request_id": request_id,
                "endpoint": "/user/profile",
                "method": "GET",
                "parameter": f"id={resource_id}",
                "user_id": user,
                "target_id": resource_id,
                "status_code": response.status_code,
                "response_length": len(response.text),
                "sensitive_data_found": "profile data" in response.text,
                "is_unauthorized": 0
            })

        # Test access to other users' resources (unauthorized)
        for resource_id in other_resources:
            request_id += 1
            headers = {"X-User-ID": user}
            response = requests.get(f"{base_url}/user/profile?id={resource_id}", headers=headers)
            records.append({
                "request_id": request_id,
                "endpoint": "/user/profile",
                "method": "GET",
                "parameter": f"id={resource_id}",
                "user_id": user,
                "target_id": resource_id,
                "status_code": response.status_code,
                "response_length": len(response.text),
                "sensitive_data_found": "profile data" in response.text,
                "is_unauthorized": 1
            })

    df = pd.DataFrame(records)
    df.to_csv("data/idor_dataset.csv", index=False)
    print("IDOR dataset created successfully.")

if __name__ == "__main__":
    # This script assumes the mock_server.py is running
    try:
        collect_and_label_data()
    except requests.exceptions.ConnectionError as e:
        print(f"Error connecting to the mock server: {e}")
        print("Please make sure the mock_server.py is running in a separate terminal.")
