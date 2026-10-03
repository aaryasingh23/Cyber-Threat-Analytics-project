"""Feature selection + preprocessing shared by the anomaly (Phase 6) and supervised (Phase 7) models.

Leakage rules
-------------
* Never used as features: flow_id, orig_id (row ids are ordered by class in the source files),
  label / is_attack / attack_cat (targets), split, and the cleaning flags.
* stcpb / dtcpb (random TCP initial sequence numbers) are excluded as pure noise.
* srcip, dstip, stime do not exist in this release (would also be excluded).
* All transformers are FIT ON TRAINING DATA ONLY and applied to the test split.
"""
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, RobustScaler

from config import CATEGORICAL_COLS

EXCLUDE = {"flow_id", "orig_id", "label", "is_attack", "attack_cat", "split", "stcpb", "dtcpb",
           "flag_label_mismatch", "flag_negative", "flag_invalid_ftp_login", "flag_zero_duration",
           "is_duplicate", "in_both_splits"}


def numeric_features(df):
    return [c for c in df.select_dtypes(include="number").columns if c not in EXCLUDE]


def skewed_features(df, cols, threshold=1.0):
    """Non-negative columns with |skew| > threshold get a log1p transform."""
    sk = df[cols].astype("float64").skew()
    return [c for c in cols if sk[c] > threshold and df[c].min() >= 0]


def build_preprocessor(train_df, with_categoricals=True):
    num = numeric_features(train_df)
    skewed = skewed_features(train_df, num)
    plain = [c for c in num if c not in skewed]
    transformers = [
        ("log_num", Pipeline([("log1p", FunctionTransformer(np.log1p, feature_names_out="one-to-one")),
                              ("scale", RobustScaler())]), skewed),
        ("num", RobustScaler(), plain),
    ]
    if with_categoricals:
        transformers.append(("cat", OneHotEncoder(handle_unknown="infrequent_if_exist", min_frequency=100,
                                                  sparse_output=False, dtype=np.float32), CATEGORICAL_COLS))
    pre = ColumnTransformer(transformers, verbose_feature_names_out=False)
    pre.set_output(transform="pandas")
    return pre, {"numeric": num, "log_transformed": skewed, "categorical": CATEGORICAL_COLS if with_categoricals else []}


def to_model_frame(df):
    """Categoricals as plain strings (OneHotEncoder + unseen categories friendly)."""
    out = df.copy()
    for c in CATEGORICAL_COLS:
        out[c] = out[c].astype(str)
    return out


def split_train_test(df):
    """Official UNSW-NB15 split - no random shuffling, so no shuffle leakage."""
    train = df[df["split"] == "train"].reset_index(drop=True)
    test = df[df["split"] == "test"].reset_index(drop=True)
    return to_model_frame(train), to_model_frame(test)


def transform(pre, df):
    return pre.transform(df).astype(np.float32)


if __name__ == "__main__":
    from config import CLEAN_PARQUET
    d = pd.read_parquet(CLEAN_PARQUET)
    tr, te = split_train_test(d)
    p, info = build_preprocessor(tr)
    Xtr = p.fit_transform(tr)
    print(Xtr.shape, len(info["numeric"]), "numeric,", len(info["log_transformed"]), "log1p")
