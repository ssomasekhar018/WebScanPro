
import joblib
import pandas as pd

try:
    # Load the preprocessor
    preprocessor_path = 'c:\\Users\\somas\\OneDrive\\Documents\\Infosys Springboard\\project-root\\projects\\sql_injection\\models\\preprocessor.pkl'
    preprocessor = joblib.load(preprocessor_path)

    # Check for feature names
    if hasattr(preprocessor, 'get_feature_names_out'):
        print("Feature names from preprocessor:")
        print(preprocessor.get_feature_names_out())
    elif hasattr(preprocessor, 'feature_names_in_'):
        print("Feature names from preprocessor:")
        print(preprocessor.feature_names_in_)
    else:
        print("Could not retrieve feature names from the preprocessor.")
        print("Preprocessor details:", preprocessor)

except Exception as e:
    print(f"An error occurred: {e}")
