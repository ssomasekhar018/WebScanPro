
import pandas as pd
from scanner_ml_integration import score_session
import os

# Create output directory
os.makedirs("projects/auth_session/output", exist_ok=True)

# Load sample data
try:
    df = pd.read_csv("projects/auth_session/data/feature_dataset.csv")
except FileNotFoundError:
    print("Error: feature_dataset.csv not found. Please ensure the dataset exists.")
    exit()

# Take a sample of the data to test
sample_df = df.sample(n=4, random_state=42)

# Score each session and collect the results
results = []
for _, row in sample_df.iterrows():
    session_data = row.to_dict()
    result = score_session(session_data)
    results.append(result)

# Save the results to a CSV file
results_df = pd.DataFrame(results)
results_df.to_csv("projects/auth_session/output/test_integration_results.csv", index=False)

print("Integration test finished. Results saved to projects/auth_session/output/test_integration_results.csv")
