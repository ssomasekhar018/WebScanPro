import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# --- Configuration ---
DATASET_FILE = 'c:/Users/somas/OneDrive/Documents/Infosys Springboard/project-root/projects/auth_session/data/login_session_dataset.csv'
FEATURE_DATASET_FILE = 'c:/Users/somas/OneDrive/Documents/Infosys Springboard/project-root/projects/auth_session/data/feature_dataset.csv'

class FeatureExtractor:
    def __init__(self, dataset_path):
        self.df = pd.read_csv(dataset_path)
        self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
        # Fill NaNs for object columns that will be used in rolling operations
        for col in ['ip_address', 'user_agent', 'username', 'event_id']:
            if col in self.df.columns and self.df[col].dtype == 'object':
                self.df[col].fillna('', inplace=True)

    def extract_features(self):
        # Convert to categorical and create numeric codes
        for col in ['ip_address', 'user_agent', 'username']:
            if col in self.df.columns:
                self.df[col] = self.df[col].astype('category')
                self.df[f'{col}_code'] = self.df[col].cat.codes

        # --- Per-Username Features ---
        self.df = self.df.sort_values('timestamp').set_index('timestamp')
        
        self.df['is_failure'] = (self.df['auth_result'] == 'failure').astype(int)
        self.df['is_success'] = (self.df['auth_result'] == 'success').astype(int)

        # Time-window features
        self.df['fail_count_5m'] = self.df.groupby('username')['is_failure'].rolling('5min').sum().reset_index(0,drop=True)
        self.df['fail_count_15m'] = self.df.groupby('username')['is_failure'].rolling('15min').sum().reset_index(0,drop=True)
        self.df['fail_count_60m'] = self.df.groupby('username')['is_failure'].rolling('60min').sum().reset_index(0,drop=True)
        self.df['succ_count_60m'] = self.df.groupby('username')['is_success'].rolling('60min').sum().reset_index(0,drop=True)
        
        # Ratio features
        self.df['fail_success_ratio'] = self.df['fail_count_60m'] / (self.df['succ_count_60m'] + 1)
        
        # Distinct counts
        self.df['distinct_ips_60m'] = self.df.groupby('username_code')['ip_address_code'].rolling('60min').apply(lambda x: x.nunique()).reset_index(0,drop=True)
        self.df['distinct_user_agents_60m'] = self.df.groupby('username_code')['user_agent_code'].rolling('60min').apply(lambda x: x.nunique()).reset_index(0,drop=True)
        
        # --- Per-IP Features ---
        self.df['attempts_per_minute'] = self.df.groupby('ip_address_code')['username_code'].rolling('1min').count().reset_index(0,drop=True)
        self.df['distinct_usernames_attempted'] = self.df.groupby('ip_address_code')['username_code'].rolling('60min').apply(lambda x: x.nunique()).reset_index(0,drop=True)

        # Fill NaN values that result from rolling operations
        feature_cols = [
            'fail_count_5m', 'fail_count_15m', 'fail_count_60m', 'succ_count_60m',
            'fail_success_ratio', 'distinct_ips_60m', 'distinct_user_agents_60m',
            'attempts_per_minute', 'distinct_usernames_attempted'
        ]
        for col in feature_cols:
            self.df[col].fillna(0, inplace=True)

        # --- Temporal Features ---
        self.df['login_hour_local'] = self.df.index.hour
        self.df['weekday'] = self.df.index.weekday

        # --- Engineered Features ---
        self.df['entropy_of_username'] = self.df['username'].apply(lambda x: -np.sum([p * np.log2(p) for p in [x.count(c) / len(x) for c in set(x)]]))
        
        # Reset index to save to csv
        self.df = self.df.reset_index()

    def save_features(self, output_path):
        self.df.to_csv(output_path, index=False)
        print(f"Feature dataset saved to: {output_path}")

if __name__ == "__main__":
    extractor = FeatureExtractor(DATASET_FILE)
    extractor.extract_features()
    extractor.save_features(FEATURE_DATASET_FILE)