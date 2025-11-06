import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import os

# Load the feature dataset
data_path = 'C:\\Users\\somas\\OneDrive\\Documents\\Infosys Springboard\\WebScanPro_ML\\data\\features_extracted.csv'
df = pd.read_csv(data_path)

# Handle missing values
numerical_cols = ['input_length', 'num_special_chars', 'num_digits']
for col in numerical_cols:
    df[col] = df[col].fillna(df[col].median())

categorical_cols = ['url', 'parameter', 'param_type', 'input_value']
for col in categorical_cols:
    df[col] = df[col].fillna(df[col].mode()[0])

boolean_cols = ['contains_sql_keyword', 'contains_html_tag']
for col in boolean_cols:
    df[col] = df[col].fillna(False)

# Encode categorical columns
label_encoders = {}
for col in categorical_cols[:3]:  # Exclude input_value
    le = LabelEncoder()
    df[col + '_encoded'] = le.fit_transform(df[col])
    label_encoders[col] = le

# Drop original categorical columns and input_value
df = df.drop(categorical_cols, axis=1)

# Normalize numerical columns
scaler = MinMaxScaler()
df[numerical_cols] = scaler.fit_transform(df[numerical_cols])

# Save the cleaned dataset
output_path = 'C:\\Users\\somas\\OneDrive\\Documents\\Infosys Springboard\\WebScanPro_ML\\data\\cleaned_dataset.csv'
df.to_csv(output_path, index=False)
print(f"Cleaned dataset saved to: {output_path}")

# Verify output
print("\nFinal Dataset Shape:", df.shape)
print("\nFinal Dataset Info:")
print(df.info())
print("\nFirst 5 Rows of Final Dataset:")
print(df.head())