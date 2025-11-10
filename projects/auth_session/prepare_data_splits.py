
import pandas as pd
from sklearn.model_selection import train_test_split
import os

# Create the output directory if it doesn't exist
os.makedirs('data/splits', exist_ok=True)

# Load the feature-engineered dataset
df = pd.read_csv('data/idor_features.csv')

# Separate features (X) and target (y)
X = df.drop('is_unauthorized', axis=1)
y = df['is_unauthorized']

# Split the data into training (60%), validation (20%), and testing (20%)
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.4, random_state=42, stratify=y
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
)

# Save the splits to CSV files
X_train.to_csv('data/splits/X_train.csv', index=False)
y_train.to_csv('data/splits/y_train.csv', index=False)
X_val.to_csv('data/splits/X_val.csv', index=False)
y_val.to_csv('data/splits/y_val.csv', index=False)
X_test.to_csv('data/splits/X_test.csv', index=False)
y_test.to_csv('data/splits/y_test.csv', index=False)

print("Data successfully split and saved to data/splits/")
