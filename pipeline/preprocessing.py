import pandas as pd
import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from imblearn.pipeline import Pipeline as ImbPipeline
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler

def get_preprocessor(numeric_features, categorical_features, scale_numeric=True):
    """
    Creates a column transformer for preprocessing flow features.
    Only numeric scaling and basic imputation are applied here.
    Fingerprints/Categoricals are left as strings with missing values marked as 'Missing'.
    """

    numeric_transformer_steps = [
        ('imputer', SimpleImputer(strategy='median'))
    ]
    if scale_numeric:
        numeric_transformer_steps.append(('scaler', StandardScaler()))

    numeric_transformer = ImbPipeline(steps=numeric_transformer_steps)

    categorical_transformer = ImbPipeline(steps=[
        ('imputer', SimpleImputer(strategy='constant', fill_value='Missing')),
        ('encoder', OneHotEncoder(handle_unknown='ignore'))
    ])

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, numeric_features),
            ('cat', categorical_transformer, categorical_features)
        ],
        remainder='passthrough'
    )

    return preprocessor

def get_full_pipeline(numeric_features, categorical_features, model, resampler=None, scale_numeric=True):
    """
    Creates a full imblearn Pipeline incorporating leakage-safe preprocessing,
    resampling (e.g. SMOTE) ONLY on the training fold, and the final model estimator.
    """
    steps = [
        ('preprocessor', get_preprocessor(numeric_features, categorical_features, scale_numeric=scale_numeric))
    ]

    if resampler is not None:
        steps.append(('resampler', resampler))

    steps.append(('classifier', model))

    return ImbPipeline(steps=steps)

def configure_resampler(strategy="smote", random_state=42):
    """
    Configure the resampling strategy.
    Choices: 'smote', 'undersample', or None.
    """
    if strategy == "smote":
        # Note: SMOTE struggles with categorical variables natively.
        # For this pilot, if we use SMOTE, we must handle categoricals (like JA3/JA4).
        # We will drop JA3/JA4 for flow-only experiments (A).
        # For mixed experiments, we'll need to drop or encode them before SMOTE.
        return SMOTE(random_state=random_state)
    elif strategy == "undersample":
        return RandomUnderSampler(random_state=random_state)
    else:
        return None
