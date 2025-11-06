import os
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from tensorflow.keras.models import load_model
import numpy as np
import scipy

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello, World!"

if __name__ == '__main__':
    app.run(port=5001, debug=True)
