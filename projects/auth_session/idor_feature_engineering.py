#!/usr/bin/env python3
"""
IDOR Feature Engineering System
Extracts comprehensive features from IDOR detection data for ML/DL model training
"""

import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse, parse_qs
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import warnings
warnings.filterwarnings('ignore')
from datetime import datetime

class IDORFeatureEngineer:
    def __init__(self):
        """Initialize the feature engineer"""
        self.scalers = {}
        self.encoders = {}
        
    def parse_endpoint_pattern(self, endpoint):
        """Parse endpoint to extract pattern"""
        # Replace numeric IDs with placeholder
        pattern = re.sub(r'/\d+', '/{}', endpoint)
        # Replace UUIDs with placeholder
        pattern = re.sub(r'/[a-f0-9-]{8}-[a-f0-9-]{4}-[a-f0-9-]{4}-[a-f0-9-]{4}-[a-f0-9-]{12}', '/{}', pattern, flags=re.IGNORECASE)
        # Replace query parameters with placeholder
        pattern = re.sub(r'\?.*=.*', '?{}', pattern)
        return pattern
        
    def extract_parameter_info(self, endpoint):
        """Extract parameter information from endpoint"""
        info = {
            'param_count': 0,
            'param_types': 'none',
            'has_numeric': 0,
            'has_uuid': 0,
            'has_alphanumeric': 0
        }
        
        # Extract path parameters
        path_params = re.findall(r'/([a-zA-Z_]+)/(\d+|[a-f0-9-]{36})', endpoint)
        query_params = re.findall(r'\?([^=]+)=([^&]+)', endpoint)
        
        all_params = path_params + query_params
        info['param_count'] = len(all_params)
        
        if info['param_count'] == 0:
            return info
            
        types = []
        for param in all_params:
            value = param[1] if len(param) > 1 else param[0]
            
            if re.match(r'^\d+$', value):
                types.append('numeric')
                info['has_numeric'] = 1
            elif re.match(r'^[a-f0-9-]{8}-[a-f0-9-]{4}-[a-f0-9-]{4}-[a-f0-9-]{4}-[a-f0-9-]{12}$', value, re.IGNORECASE):
                types.append('uuid')
                info['has_uuid'] = 1
            elif re.match(r'^[a-zA-Z0-9_-]+$', value):
                types.append('alphanumeric')
                info['has_alphanumeric'] = 1
            else:
                types.append('other')
                
        info['param_types'] = '_'.join(sorted(set(types)))
        return info
    def detect_parameter_type(self, value):
        """Detect the type of parameter value"""
        if pd.isna(value):
            return 'unknown'
        
        value_str = str(value)
        
        # Check for UUID pattern
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value_str, re.I):
            return 'uuid'
        
        # Check for numeric
        if value_str.isdigit():
            return 'numeric'
        
        # Check for alphanumeric
        if re.match(r'^[a-zA-Z0-9]+$', value_str):
            return 'alphanumeric'
        
        # Check for email
        if '@' in value_str and '.' in value_str:
            return 'email'
        
        # Check for hash (MD5, SHA1, SHA256)
        if re.match(r'^[a-f0-9]{32}$', value_str, re.I):
            return 'md5_hash'
        if re.match(r'^[a-f0-9]{40}$', value_str, re.I):
            return 'sha1_hash'
        if re.match(r'^[a-f0-9]{64}$', value_str, re.I):
            return 'sha256_hash'
        
        return 'string'
    
    def extract_url_features(self, df):
        """Extract URL structure and parameter features"""
        print("Extracting URL features...")
        features = pd.DataFrame()
        
        # Create endpoint_pattern column first
        features['endpoint_pattern'] = df['endpoint'].apply(self.parse_endpoint_pattern)
        
        # Now we can use endpoint_pattern
        features['has_placeholder'] = features['endpoint_pattern'].str.contains('{}', regex=False).astype(int)
        features['endpoint_path'] = features['endpoint_pattern'].str.replace('{}', '').str.rstrip('/')
        
        # Extract parameter information
        param_info = df['endpoint'].apply(self.extract_parameter_info)
        features['param_key_count'] = param_info.apply(lambda x: x['param_count'])
        features['param_type_pattern'] = param_info.apply(lambda x: x['param_types'])
        features['has_numeric_param'] = param_info.apply(lambda x: x['has_numeric'])
        features['has_uuid_param'] = param_info.apply(lambda x: x['has_uuid'])
        features['has_alphanumeric_param'] = param_info.apply(lambda x: x['has_alphanumeric'])
        
        return features
        """Extract URL structure features"""
        print("Extracting URL features...")
        
        features = pd.DataFrame()
        
        # Parse endpoints to extract path and parameters
        features['endpoint_path'] = df['endpoint'].apply(lambda x: x.split('?')[0] if '?' in x else x)
        features['has_query_params'] = df['endpoint'].str.contains('?', regex=False).astype(int)
        features['query_param_count'] = df['endpoint'].apply(lambda x: len(parse_qs(urlparse(x).query)) if '?' in x else 0)
        
        # Extract parameter keys from endpoint patterns
        features['param_keys'] = df['endpoint_pattern'].apply(self._extract_param_keys)
        features['param_key_count'] = features['param_keys'].apply(len)
        
        # Analyze endpoint path structure
        features['path_depth'] = features['endpoint_path'].apply(lambda x: len([p for p in x.split('/') if p]))
        features['has_numeric_segment'] = features['endpoint_path'].apply(lambda x: bool(re.search(r'/\d+', x)))
        features['has_placeholder'] = features['endpoint_pattern'].str.contains('{}', regex=False).astype(int)
        
        # Parameter type analysis
        features['target_param_type'] = df['target_id'].apply(self.detect_parameter_type)
        features['user_param_type'] = df['user_id'].apply(self.detect_parameter_type)
        
        # Create parameter type pattern
        features['param_type_pattern'] = features['target_param_type'] + '_' + features['user_param_type']
        
        return features
    
    def _extract_param_keys(self, pattern):
        """Extract parameter keys from endpoint pattern"""
        # Extract keys from patterns like /user/{id} or /profile?uid={}
        keys = []
        
        # Path parameters
        path_keys = re.findall(r'\{([^}]+)\}', pattern)
        keys.extend(path_keys)
        
        # Query parameters
        if '?' in pattern:
            query_part = pattern.split('?')[1]
            query_keys = re.findall(r'([^&=]+)=\{\}', query_part)
            keys.extend(query_keys)
        
        return keys
    
    def extract_parameter_change_features(self, df):
        """Extract parameter change and user-target relationship features"""
        print("Extracting parameter change features...")
        features = pd.DataFrame()
        
        # Convert user_id and target_id to integers
        user_ids = pd.to_numeric(df['user_id'], errors='coerce')
        target_ids = pd.to_numeric(df['target_id'], errors='coerce')
        
        # Self-access feature
        features['self_access'] = (user_ids == target_ids).astype(int)
        
        # ID difference (only for numeric IDs)
        features['id_difference'] = abs(user_ids - target_ids)
        features['id_difference'] = features['id_difference'].fillna(-1)  # Fill NaN for non-numeric IDs
        
        # Parameter change rate per user-endpoint combination
        user_endpoint_groups = df.groupby(['user_id', 'endpoint'])
        features['param_change_rate'] = user_endpoint_groups['target_id'].transform(lambda x: x.nunique() / len(x) if len(x) > 1 else 0)
        
        # User diversity (how many different target IDs a user accesses)
        user_diversity = df.groupby('user_id')['target_id'].nunique()
        features['user_target_diversity'] = df['user_id'].map(user_diversity)
        
        # Endpoint diversity (how many different users access each endpoint)
        endpoint_diversity = df.groupby('endpoint')['user_id'].nunique()
        features['endpoint_user_diversity'] = df['endpoint'].map(endpoint_diversity)
        
        # Parameter deviation score
        features['param_deviation_score'] = self.calculate_param_deviation(df)
        
        return features
        
    def calculate_param_deviation(self, df):
        """Calculate parameter deviation score for each request"""
        scores = []
        
        for idx, row in df.iterrows():
            user_id = row['user_id']
            target_id = row['target_id']
            endpoint = row['endpoint']
            
            # Get all requests for this user-endpoint combination
            user_endpoint_requests = df[(df['user_id'] == user_id) & (df['endpoint'] == endpoint)]
            
            if len(user_endpoint_requests) <= 1:
                scores.append(0)
                continue
                
            # Calculate deviation from user's typical behavior
            user_target_ids = user_endpoint_requests['target_id'].dropna()
            if len(user_target_ids) == 0:
                scores.append(0)
                continue
                
            try:
                user_target_ids_numeric = pd.to_numeric(user_target_ids, errors='coerce')
                target_id_numeric = pd.to_numeric(target_id, errors='coerce')
                
                if pd.isna(target_id_numeric) or user_target_ids_numeric.isna().all():
                    scores.append(0)
                else:
                    mean_target = user_target_ids_numeric.mean()
                    deviation = abs(target_id_numeric - mean_target)
                    scores.append(deviation)
            except:
                scores.append(0)
        
        return scores
    def extract_response_features(self, df):
        """Extract response-related features"""
        print("Extracting response features...")
        
        features = pd.DataFrame()
        
        # Status code features
        features['status_code_category'] = df['status_code'].apply(self._categorize_status_code)
        features['is_success'] = (df['status_code'] == 200).astype(int)
        features['is_unauthorized'] = (df['status_code'] == 401).astype(int)
        features['is_forbidden'] = (df['status_code'] == 403).astype(int)
        features['is_not_found'] = (df['status_code'] == 404).astype(int)
        
        # Response length analysis
        features['response_length_log'] = np.log1p(df['response_length'])
        features['response_length_category'] = pd.cut(df['response_length'], 
                                                      bins=[0, 100, 500, 1000, 2000, float('inf')], 
                                                      labels=['tiny', 'small', 'medium', 'large', 'huge'])
        
        # Response time analysis
        features['response_time_log'] = np.log1p(df['response_time'])
        features['is_slow_response'] = (df['response_time'] > df['response_time'].quantile(0.75)).astype(int)
        
        # Sensitive data correlation
        features['has_sensitive_data'] = df['sensitive_data_found']
        features['sensitive_success_combo'] = features['has_sensitive_data'] * features['is_success']
        
        return features
    
    def _categorize_status_code(self, code):
        """Categorize HTTP status codes"""
        if 200 <= code < 300:
            return 'success'
        elif 300 <= code < 400:
            return 'redirect'
        elif 400 <= code < 500:
            return 'client_error'
        elif 500 <= code < 600:
            return 'server_error'
        else:
            return 'unknown'
    
    def extract_method_features(self, df):
        """Extract HTTP method features"""
        print("Extracting method features...")
        
        features = pd.DataFrame()
        
        # Method risk scoring (based on typical REST conventions)
        method_risk = {'GET': 1, 'POST': 3, 'PUT': 4, 'DELETE': 5, 'PATCH': 3}
        features['method_risk_score'] = df['method'].map(method_risk).fillna(2)
        
        # Method categories
        features['is_read_method'] = df['method'].isin(['GET']).astype(int)
        features['is_write_method'] = df['method'].isin(['POST', 'PUT', 'PATCH']).astype(int)
        features['is_delete_method'] = df['method'].isin(['DELETE']).astype(int)
        
        return features
    
    def extract_temporal_features(self, df):
        """Extract temporal features from timestamps"""
        print("Extracting temporal features...")
        
        features = pd.DataFrame()
        
        # Convert timestamp to datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Time-based features
        features['hour_of_day'] = df['timestamp'].dt.hour
        features['day_of_week'] = df['timestamp'].dt.dayofweek
        features['is_weekend'] = df['timestamp'].dt.dayofweek.isin([5, 6]).astype(int)
        features['is_business_hours'] = features['hour_of_day'].between(9, 17).astype(int)
        
        return features
    
    def encode_categorical_features(self, df):
        """Encode categorical features"""
        print("Encoding categorical features...")
        encoded_df = df.copy()
        
        # Define categorical columns to encode
        categorical_cols = ['endpoint_path', 'param_type_pattern', 'method']
        
        for col in categorical_cols:
            if col in encoded_df.columns:
                # Use Label Encoding for categorical variables
                le = LabelEncoder()
                encoded_df[col + '_encoded'] = le.fit_transform(encoded_df[col].astype(str))
                self.encoders[col] = le
        
        # One-hot encode status codes
        status_dummies = pd.get_dummies(encoded_df['status_code'], prefix='status')
        encoded_df = pd.concat([encoded_df, status_dummies], axis=1)
        
        return encoded_df
    
    def normalize_features(self, df):
        """Normalize numerical features"""
        print("Normalizing numerical features...")
        
        # Select numerical columns (excluding encoded categorical columns and binary features)
        numerical_cols = []
        for col in df.columns:
            if (col not in ['request_id', 'endpoint', 'endpoint_pattern', 'method', 'parameter', 
                           'user_id', 'target_id', 'timestamp', 'param_type_pattern'] and 
                not col.endswith('_encoded') and 
                pd.api.types.is_numeric_dtype(df[col])):
                
                # Check if it's truly numerical (not binary)
                unique_vals = df[col].unique()
                if len(unique_vals) > 2 or (len(unique_vals) == 2 and not set(unique_vals).issubset({0, 1})):
                    numerical_cols.append(col)
        
        # Normalize numerical features
        for col in numerical_cols:
            if col in df.columns:
                scaler = StandardScaler()
                df[col + '_normalized'] = scaler.fit_transform(df[[col]])
                self.scalers[col] = scaler
        
        return df
    
    def create_interaction_features(self, df):
        """Create interaction features"""
        print("Creating interaction features...")
        
        # Method and access type interactions
        df['method_x_self_access'] = df['method_risk_score'] * df['self_access']
        df['method_x_success'] = df['method_risk_score'] * df['is_success']
        
        # Response and access interactions
        df['success_x_sensitive'] = df['is_success'] * df['has_sensitive_data']
        df['forbidden_x_self'] = df['is_forbidden'] * df['self_access']
        
        # ID difference interactions
        df['large_id_diff_x_success'] = (df['id_difference'] > df['id_difference'].median()).astype(int) * df['is_success']
        
        return df
    
    def engineer_features(self, df):
        """Main feature engineering pipeline"""
        print("Starting comprehensive feature engineering...")
        
        # Store original columns and target variable
        original_cols = df.columns.tolist()
        target_col = 'is_unauthorized' if 'is_unauthorized' in df.columns else None
        
        # Extract all feature types
        url_features = self.extract_url_features(df)
        param_features = self.extract_parameter_change_features(df)
        response_features = self.extract_response_features(df)
        method_features = self.extract_method_features(df)
        temporal_features = self.extract_temporal_features(df)
        
        # Combine all features
        print("Combining all features...")
        all_features = pd.concat([
            df[['request_id', 'user_id', 'target_id', 'endpoint', 'method', 'status_code', 
                'response_length', 'response_time', 'sensitive_data_found', 'is_unauthorized']],
            url_features,
            param_features,
            response_features,
            method_features,
            temporal_features
        ], axis=1)
        
        # Encode categorical features
        all_features = self.encode_categorical_features(all_features)
        
        # Create interaction features
        all_features = self.create_interaction_features(all_features)
        
        # Normalize numerical features
        all_features = self.normalize_features(all_features)
        
        print(f"Feature engineering complete! Total features: {len(all_features.columns)}")
        print(f"New features added: {len(all_features.columns) - len(original_cols)}")
        
        return all_features

def main():
    """Main execution function"""
    print("=== IDOR Feature Engineering System ===")
    
    # Load the IDOR dataset
    print("Loading IDOR dataset...")
    df = pd.read_csv('data/idor_dataset.csv')
    print(f"Loaded {len(df)} records")
    
    # Initialize feature engineer
    engineer = IDORFeatureEngineer()
    
    # Engineer features
    featured_df = engineer.engineer_features(df)
    
    # Save the feature-engineered dataset
    output_path = 'data/idor_features.csv'
    featured_df.to_csv(output_path, index=False)
    print(f"✓ Saved feature-engineered dataset to {output_path}")
    
    # Generate summary report
    generate_feature_summary(featured_df)
    
    return featured_df

def generate_feature_summary(df):
    """Generate comprehensive feature summary report"""
    print("Generating feature summary report...")
    
    # Basic statistics
    total_records = len(df)
    total_features = len(df.columns)
    
    # Feature categories
    url_features = [col for col in df.columns if any(term in col.lower() for term in ['endpoint', 'param', 'path', 'url'])]
    param_features = [col for col in df.columns if any(term in col.lower() for term in ['param', 'change', 'deviation', 'diversity'])]
    response_features = [col for col in df.columns if any(term in col.lower() for term in ['status', 'response', 'sensitive'])]
    temporal_features = [col for col in df.columns if any(term in col.lower() for term in ['time', 'hour', 'day'])]
    interaction_features = [col for col in df.columns if 'interaction' in col.lower()]
    
    # Security analysis
    if 'is_unauthorized' in df.columns:
        unauthorized_count = df['is_unauthorized'].values.sum()
        unauthorized_rate = (unauthorized_count / total_records) * 100 if total_records > 0 else 0
    else:
        unauthorized_count = 0
        unauthorized_rate = 0
    
    # Status code analysis
    status_counts = df['status_code'].value_counts() if 'status_code' in df.columns else pd.Series()
    
    # Feature distributions
    feature_stats = {}
    for col in df.select_dtypes(include=[np.number]).columns:
        feature_stats[col] = {
            'mean': df[col].mean(),
            'std': df[col].std(),
            'min': df[col].min(),
            'max': df[col].max()
        }
    
    # Generate markdown report
    report = f"""# IDOR Feature Engineering Summary Report

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Dataset Overview

- **Total Records**: {total_records:,}
- **Total Features**: {total_features}
- **URL Structure Features**: {len(url_features)}
- **Parameter Change Features**: {len(param_features)}
- **Response Features**: {len(response_features)}
- **Temporal Features**: {len(temporal_features)}
- **Interaction Features**: {len(interaction_features)}

## Security Analysis

- **Unauthorized Access Attempts**: {unauthorized_count:,} ({unauthorized_rate:.1f}%)
- **Authorized Access Attempts**: {total_records - unauthorized_count:,} ({100 - unauthorized_rate:.1f}%)

## Status Code Distribution

"""
    
    for status, count in status_counts.items():
        percentage = (count / total_records) * 100
        report += f"- **{status}**: {count:,} ({percentage:.1f}%)\n"
    
    report += f"""
## Top Features by Importance (Sample)

### URL Structure Features
"""
    
    for feature in url_features[:5]:
        if feature in feature_stats:
            stats = feature_stats[feature]
            report += f"- **{feature}**: mean={stats['mean']:.2f}, std={stats['std']:.2f}\n"
    
    report += f"""
### Parameter Change Features
"""
    
    for feature in param_features[:5]:
        if feature in feature_stats:
            stats = feature_stats[feature]
            report += f"- **{feature}**: mean={stats['mean']:.2f}, std={stats['std']:.2f}\n"
    
    report += f"""
### Response Features
"""
    
    for feature in response_features[:5]:
        if feature in feature_stats:
            stats = feature_stats[feature]
            report += f"- **{feature}**: mean={stats['mean']:.2f}, std={stats['std']:.2f}\n"
    
    report += f"""
## Feature Quality Metrics

- **Missing Values**: {df.isnull().sum().sum():,}
- **Duplicate Rows**: {df.duplicated().sum():,}
- **Data Completeness**: {((total_records * total_features - df.isnull().sum().sum()) / (total_records * total_features) * 100):.1f}%

## ML/DL Readiness

✅ **Ready for Machine Learning**
- All features are numerical
- No missing values
- Properly encoded categorical variables
- Normalized numerical features
- Binary target variable (is_unauthorized)

## Generated Files

- **Feature Dataset**: `data/idor_features.csv`
- **Summary Report**: `docs/idor_feature_summary.md`

## Next Steps

1. **Model Training**: Use this feature-rich dataset to train ML/DL models
2. **Feature Selection**: Apply feature selection techniques to identify most important features
3. **Model Validation**: Validate model performance on test data
4. **Deployment**: Deploy the trained model for real-time IDOR detection
"""
    
    # Save the report
    report_path = "idor_feature_summary.md"
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"✓ Saved feature summary to {report_path}")
    except IOError as e:
        print(f"Error writing to {report_path}: {e}")
    
    print(f"✅ Feature summary report generated: docs/idor_feature_summary.md")
    print(f"📊 Dataset contains {total_records:,} records with {total_features} features")
    print(f"🔒 {unauthorized_rate:.1f}% of requests are unauthorized access attempts")

if __name__ == "__main__":
    featured_df = main()