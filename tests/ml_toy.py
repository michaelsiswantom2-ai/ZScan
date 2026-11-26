"""A tiny LightGBM model for testing the ML plumbing. It is trained on generated data and
knows nothing about real malware: "benign" is a small ELF with plain text, "malicious" is one
stuffed with random bytes. It only shows that features, model files and reports connect up."""
import random

import lightgbm as lgb
import numpy as np

from samples import build_elf
from zscan.ml import features

PARAMS = {"objective": "binary", "num_leaves": 4, "min_data_in_leaf": 1, "min_data_in_bin": 1,
          "learning_rate": 0.5, "verbose": -1, "seed": 3, "deterministic": True,
          "force_row_wise": True, "num_threads": 1}


def plain_elf(rng: random.Random) -> bytes:
    text = b"usage: tool [options] file\n" * rng.randint(2, 6) + b"\x90" * rng.randint(50, 200) + b"\xc3"
    return build_elf(text=text)


def noisy_elf(rng: random.Random) -> bytes:
    return build_elf(text=bytes(rng.getrandbits(8) for _ in range(rng.randint(3000, 6000))))


def train(path, n_features: int = features.FULL_DIM, rounds: int = 5) -> None:
    rng = random.Random(3)
    X, y = [], []
    for _ in range(24):
        for make, label in ((plain_elf, 0), (noisy_elf, 1)):
            X.append(features.pad_for_model(features.feature_vector(make(rng)), n_features)
                     if n_features >= features.NON_PE_DIM else
                     features.feature_vector(make(rng))[:n_features])
            y.append(label)
    booster = lgb.train(PARAMS, lgb.Dataset(np.array(X, dtype=np.float32), np.array(y)), num_boost_round=rounds)
    booster.save_model(str(path))
