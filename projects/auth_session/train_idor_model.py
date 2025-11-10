
import pandas as pd
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

# Load the data splits
X_train = pd.read_csv('data/splits/X_train.csv')
y_train = pd.read_csv('data/splits/y_train.csv').values.ravel()
X_val = pd.read_csv('data/splits/X_val.csv')
y_val = pd.read_csv('data/splits/y_val.csv').values.ravel()
X_test = pd.read_csv('data/splits/X_test.csv')
y_test = pd.read_csv('data/splits/y_test.csv').values.ravel()

# Create a preprocessing and modeling pipeline
pipeline = Pipeline([
    ('preprocessor', StandardScaler()),
    ('classifier', LogisticRegression(random_state=42))
])

# Train the model
pipeline.fit(X_train, y_train)

# Evaluate the model on the validation set
y_pred = pipeline.predict(X_val)
print("Validation Set Performance:")
print(classification_report(y_val, y_pred))

# Save the trained model
joblib.dump(pipeline, 'projects/auth_session/ml/idor_model.joblib')

print("Model saved to projects/auth_session/ml/")
