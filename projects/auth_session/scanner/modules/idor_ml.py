
import joblib
import pandas as pd

# Load the trained model
pipeline = joblib.load('ml/idor_model.joblib')

def predict(request_record):
    """Predicts if a request is an IDOR attempt."""
    # Convert the request record to a DataFrame
    df = pd.DataFrame([request_record])

    # Make a prediction
    prediction = pipeline.predict(df)

    return prediction[0]
