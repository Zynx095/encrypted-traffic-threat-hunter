import pytest
import pandas as pd
import numpy as np
from pipeline.preprocessing import get_preprocessor, get_full_pipeline, configure_resampler
from sklearn.linear_model import LogisticRegression

@pytest.fixture
def dummy_data():
    X = pd.DataFrame({
        'flow_duration': [10, 20, np.nan, 40, 50, 60, 70, 80],
        'packet_count': [1, 2, 3, 4, 5, 6, 7, 8],
        'ja3_hash': ['a', 'b', np.nan, 'a', 'c', 'd', 'e', 'a']
    })
    y = pd.Series([0, 1, 0, 1, 0, 1, 0, 1])
    return X, y

def test_preprocessing_imputation(dummy_data):
    X, y = dummy_data
    preprocessor = get_preprocessor(
        numeric_features=['flow_duration', 'packet_count'],
        categorical_features=['ja3_hash'],
        scale_numeric=True
    )

    # Fit and transform
    X_trans = preprocessor.fit_transform(X, y)

    # The nan in flow_duration (row 2, value index 2) should be imputed with the median of [10,20,40,50,60,70,80] -> 50
    # Wait, Standard scaler applies after imputer.
    # We just need to check no nans remain in the numeric columns.
    assert not np.isnan(X_trans[:, :2].astype(float)).any()

    # Categorical NaN should be encoded and the entire array should be numeric
    assert np.issubdtype(X_trans.dtype, np.number)

def test_preprocessing_pipeline_structure():
    model = LogisticRegression()
    resampler = configure_resampler('smote')
    pipeline = get_full_pipeline(['flow_duration'], ['ja3_hash'], model, resampler)

    steps = dict(pipeline.steps)
    assert 'preprocessor' in steps
    assert 'resampler' in steps
    assert 'classifier' in steps
    assert type(steps['resampler']).__name__ == 'SMOTE'
