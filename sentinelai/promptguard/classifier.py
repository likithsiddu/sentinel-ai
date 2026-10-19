"""ML layer: TF-IDF (word + character n-grams) -> logistic regression.

Character n-grams give some robustness to typos / spacing tricks; the word model captures
attack vocabulary. Trained in well under a second on first use, so no binary model is
committed to the repo (reproducible, auditable, nothing to poison).
"""
from __future__ import annotations

from functools import lru_cache

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from . import dataset
from .patterns import normalize


def build_pipeline() -> Pipeline:
    feats = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=1)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2)),
    ])
    return Pipeline([("tfidf", feats),
                     ("clf", LogisticRegression(C=6.0, class_weight="balanced", max_iter=2000))])


def training_data() -> tuple[list[str], list[int]]:
    X = [normalize(t)[0] for t in dataset.MALICIOUS_TRAIN + dataset.BENIGN_TRAIN]
    y = [1] * len(dataset.MALICIOUS_TRAIN) + [0] * len(dataset.BENIGN_TRAIN)
    return X, y


@lru_cache(maxsize=1)
def get_model() -> Pipeline:
    X, y = training_data()
    return build_pipeline().fit(X, y)


def ml_probability(text_normalised: str) -> float:
    return float(get_model().predict_proba([text_normalised])[0][1])
