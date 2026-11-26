"""Opt-in machine-learning check. Needs numpy and lightgbm: pip install 'zscan[ml]'.

Importing this package is cheap; numpy and lightgbm are only imported when a model is used.
"""
from .model import (DEFAULT_THRESHOLD, MODEL_FILES, MlScorer, MlUnavailable, installed_models,  # noqa: F401
                    models_dir, update_models)
