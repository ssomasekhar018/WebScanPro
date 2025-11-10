
import pandas as pd
import numpy as np
import re

def get_url_features(df):
    """Extracts URL-based features."""
    df['endpoint_path'] = df['endpoint']
    df['param_key_count'] = df['parameter'].apply(lambda x: len(x.split('&')))

    def get_param_type(param_str):
        try:
            val = param_str.split('=')[1]
            if val.isdigit():
                return 'numeric'
            elif re.match(r'^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$', val):
                return 'uuid'
            else:
                return 'alphanumeric'
        except IndexError:
            return 'none'

    df['param_type_pattern'] = df['parameter'].apply(get_param_type)
    return df

def get_parameter_features(df):
    """Extracts parameter-based features."""
    df['self_access'] = (df['user_id'].astype(str) == df['target_id'].astype(str)).astype(int)

    # Calculate parameter change rate per user
    param_change = df.groupby('user_id')['target_id'].nunique().reset_index(name='unique_targets')
    total_reqs = df.groupby('user_id').size().reset_index(name='total_requests')
    user_stats = pd.merge(param_change, total_reqs, on='user_id')
    user_stats['param_change_rate'] = user_stats['unique_targets'] / user_stats['total_requests']

    df = pd.merge(df, user_stats[['user_id', 'param_change_rate']], on='user_id')
    return df

def get_response_features(df):
    """Extracts response-based features."""
    df['status_code_cat'] = df['status_code'].astype('category').cat.codes
    return df

def generate_summary_report(df, output_path):
    """Generates a markdown summary of the feature dataset."""
    unique_endpoints = df['endpoint_path'].nunique()
    unauthorized_percentage = (df['is_unauthorized'].sum() / len(df)) * 100

    param_type_dist = df['param_type_pattern'].value_counts(normalize=True) * 100
    status_code_dist = df['status_code'].value_counts(normalize=True) * 100

    with open(output_path, 'w') as f:
        f.write("# IDOR Feature Engineering Summary Report\n\n")
        f.write("This report summarizes the feature-engineered dataset for IDOR detection.\n\n")
        f.write("## Key Statistics\n\n")
        f.write(f"- **Unique Endpoints Analyzed:** {unique_endpoints}\n")
        f.write(f"- **Unauthorized Access Percentage:** {unauthorized_percentage:.2f}%\n\n")
        f.write("## Feature Distributions\n\n")
        f.write("### Parameter Type Distribution\n")
        f.write(param_type_dist.to_markdown())
        f.write("\n\n### Status Code Distribution\n")
        f.write(status_code_dist.to_markdown())

def main():
    """Main function to run the feature engineering pipeline."""
    df = pd.read_csv('data/idor_dataset.csv')

    df = get_url_features(df)
    df = get_parameter_features(df)
    df = get_response_features(df)

    # Define feature columns
    feature_cols = [
        'param_key_count', 'self_access', 'param_change_rate',
        'status_code_cat', 'response_length', 'sensitive_data_found',
        'is_unauthorized'
    ]
    
    # Ensure all feature columns exist, creating them with 0 if they don't
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0

    final_df = df[feature_cols]

    # Save the feature-rich dataset
    final_df.to_csv('data/idor_features.csv', index=False)
    print("Feature dataset 'idor_features.csv' created successfully.")

    # Generate the summary report
    generate_summary_report(df, 'docs/idor_feature_summary.md')
    print("Summary report 'idor_feature_summary.md' created successfully.")

if __name__ == '__main__':
    main()
