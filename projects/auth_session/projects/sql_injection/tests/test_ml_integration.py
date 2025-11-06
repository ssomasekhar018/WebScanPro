import pytest
import joblib
import pandas as pd
from scanner.ml_integration import MLIntegrator
from unittest.mock import patch

@pytest.fixture
def ml_integrator(tmp_path):
    dummy_model_path = tmp_path / 'dummy_model.pkl'
    dummy_model = type('DummyModel', (), {
        'predict': lambda self, x: [1],
        'predict_proba': lambda self, x: [[0.1, 0.9]]
    })()
    joblib.dump(dummy_model, dummy_model_path)
    integrator = MLIntegrator()
    integrator.load_model(str(dummy_model_path), None)
    return integrator

def test_load_model(tmp_path):
    dummy_path = tmp_path / 'model.pkl'
    joblib.dump({'predict': lambda x: [0]}, dummy_path)
    integrator = MLIntegrator()
    integrator.load_model(str(dummy_path), None)
    assert integrator.model is not None

def test_prepare_features(ml_integrator):
    req = {'url': '/test', 'payload': 'test'}
    resp = {'status_code': 200, 'response_time': 0.1}
    features = ml_integrator.prepare_features(req, resp)
    assert isinstance(features, pd.DataFrame)
    assert features.shape == (1, 5)  # Adjust based on your features count

@patch.object(MLIntegrator, 'model')
def test_predict(mock_model, ml_integrator):
    mock_model.predict.return_value = [1]
    mock_model.predict_proba.return_value = [[0.1, 0.9]]
    features = pd.DataFrame([[1,2,3,4,5]])
    label, conf = ml_integrator.predict(features)
    assert label == 1
    assert conf == 0.9

def test_predict_failure(ml_integrator):
    ml_integrator.model = None
    label, conf = ml_integrator.predict(pd.DataFrame())
    assert label == "unknown"
    assert conf == 0.0