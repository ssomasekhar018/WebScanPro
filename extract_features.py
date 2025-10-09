import pandas as pd
import re

def extract_features(input_file='metadata.csv', output_file='features_extracted.csv'):
    # Load the dataset (use pd.read_json if preferring JSON)
    df = pd.read_csv(input_file)
    
    # Map to expected names for clarity (optional, but helps)
    df = df.rename(columns={
        'param_name': 'parameter',
        'default_value': 'input_value',
        'input_type': 'param_type'
    })
    
    # Define special characters (expand if needed, e.g., add ; / etc. for security)
    special_chars = r'[<>\'"%&]'
    
    # SQL keywords (common injection terms)
    sql_keywords = ['select', 'union', 'insert', 'delete', 'drop', 'update', '--', 'or', 'and']
    
    # HTML tags pattern (basic regex for common tags)
    html_tag_pattern = r'<(script|img|iframe|svg|object|embed|link|style|a|form|input|button)[^>]*>'
    
    # Extract features
    df['input_length'] = df['input_value'].apply(lambda x: len(str(x)))
    
    df['num_special_chars'] = df['input_value'].apply(
        lambda x: len(re.findall(special_chars, str(x)))
    )
    
    df['num_digits'] = df['input_value'].apply(
        lambda x: sum(c.isdigit() for c in str(x))
    )
    
    df['contains_sql_keyword'] = df['input_value'].apply(
        lambda x: 1 if any(kw in str(x).lower() for kw in sql_keywords) else 0
    )
    
    df['contains_html_tag'] = df['input_value'].apply(
        lambda x: 1 if re.search(html_tag_pattern, str(x), re.IGNORECASE) else 0
    )
    
    # Select required columns
    columns = ['url', 'parameter', 'input_value', 'input_length', 'num_special_chars', 
               'num_digits', 'param_type', 'contains_sql_keyword', 'contains_html_tag']
    features_df = df[columns]
    
    # Save to CSV
    features_df.to_csv(output_file, index=False)
    print(f"Features extracted and saved to {output_file}")

# Run the function
if __name__ == "__main__":
    extract_features()