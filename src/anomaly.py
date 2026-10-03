"""Phase 6: unsupervised anomaly detection.

Protocol
--------
* Fit ONLY on NORMAL flows from the official training split (56,000 flows).
  20% of those normals are held out to set each model's alert threshold at the
  95th percentile of normal scores (i.e. a target ~5% false-positive rate).
* Evaluate on the full, mixed official TEST split (82,332 flows) - never seen in fitting.
* Sampling (stated explicitly): LOF is fit on 20,000 normals, One-Class SVM on 10,000
  normals and the autoencoder on 20,000 normals because they scale poorly.
  Isolation Forest uses all 44,800 fitting normals.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.svm import OneClassSVM

from config import ANOMALY_PARQUET, CLEAN_PARQUET, REPORTS_DIR, SEED
from features import build_preprocessor, split_train_test, transform
from models import binary_metrics, metrics_table, plot_confusion, plot_curves
from utils import banner, save_json, timer

SAMPLES = {"lof": 20_000, "ocsvm": 10_000, "autoencoder": 20_000}


def _sample(X, n, seed=SEED):
    if len(X) <= n:
        return X
    return X.sample(n, random_state=seed)


def fit_models(X_fit):
    """Return {name: score_fn}. Every score_fn returns 'higher = more anomalous'."""
    out = {}
    with timer("IsolationForest"):
        iso = IsolationForest(n_estimators=300, max_samples=4096, contamination="auto",
                              random_state=SEED, n_jobs=-1).fit(X_fit)
        out["IsolationForest"] = lambda X: -iso.score_samples(X)
    with timer(f"LOF (novelty, sample {SAMPLES['lof']:,})"):
        lof = LocalOutlierFactor(n_neighbors=35, novelty=True, n_jobs=-1).fit(_sample(X_fit, SAMPLES["lof"]).to_numpy())
        out["LocalOutlierFactor"] = lambda X: -lof.score_samples(X.to_numpy())
    with timer(f"OneClassSVM (sample {SAMPLES['ocsvm']:,})"):
        oc = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05).fit(_sample(X_fit, SAMPLES["ocsvm"]))
        out["OneClassSVM"] = lambda X: -oc.score_samples(X)
    with timer(f"Autoencoder (MLP, sample {SAMPLES['autoencoder']:,})"):
        Xa = _sample(X_fit, SAMPLES["autoencoder"]).to_numpy()
        ae = MLPRegressor(hidden_layer_sizes=(48, 12, 48), activation="relu", max_iter=60,
                          early_stopping=True, random_state=SEED).fit(Xa, Xa)
        out["Autoencoder"] = lambda X: np.mean((ae.predict(X.to_numpy()) - X.to_numpy()) ** 2, axis=1)
    return out


def run():
    banner("PHASE 6 - ANOMALY DETECTION (unsupervised)")
    df = pd.read_parquet(CLEAN_PARQUET)
    train, test = split_train_test(df)
    normal = train[train["label"] == 0]
    fit_df, val_df = train_test_split(normal, test_size=0.2, random_state=SEED)
    print(f"Fit on {len(fit_df):,} normal train flows; threshold set on {len(val_df):,} held-out normals; "
          f"evaluate on {len(test):,} test flows ({test['label'].mean():.1%} attacks)")

    pre, info = build_preprocessor(fit_df)
    X_fit = pre.fit_transform(fit_df).astype(np.float32)
    X_val, X_test = transform(pre, val_df), transform(pre, test)
    print(f"Features: {X_fit.shape[1]} ({len(info['log_transformed'])} log1p-transformed numeric, "
          "RobustScaler, one-hot proto/service/state)")

    scorers = fit_models(X_fit)
    y = test["label"].to_numpy()
    rows, scores, thresholds = [], {}, {}
    for name, fn in scorers.items():
        with timer(f"score {name}"):
            s_val, s_test = fn(X_val), fn(X_test)
        thr = float(np.quantile(s_val, 0.95))
        pred = (s_test > thr).astype(int)
        m = binary_metrics(y, s_test, pred, name)
        m["threshold"] = thr
        rows.append(m)
        scores[name] = s_test
        thresholds[name] = (thr, s_val)

    table = metrics_table(rows).sort_values("pr_auc", ascending=False)
    print(table[["model", "precision", "recall_attack", "f1", "roc_auc", "pr_auc", "fpr"]].to_string(index=False))
    table.to_csv(REPORTS_DIR / "metrics" / "anomaly_model_comparison.csv", index=False)
    best = table.iloc[0]["model"]
    print(f"Best anomaly model by PR-AUC: {best}")

    plot_curves(y, scores, "anomaly detectors (test set)", "06_anomaly_roc_pr")
    thr, s_val = thresholds[best]
    best_pred = (scores[best] > thr).astype(int)
    plot_confusion(y, best_pred, [0, 1], f"{best} @ 95th pct of normal scores", "06_anomaly_confusion")

    # Normalised score = empirical CDF vs held-out normal scores ("more anomalous than X% of normal")
    s_val_sorted = np.sort(s_val)
    norm = np.searchsorted(s_val_sorted, scores[best], side="right") / len(s_val_sorted)
    out = pd.DataFrame({"flow_id": df.loc[df["split"] == "test", "flow_id"].to_numpy(),
                        "label": y, "attack_cat": test["attack_cat"].to_numpy()})
    for name, s in scores.items():
        out[f"score_{name}"] = s.astype(np.float32)
    out["anomaly_score_best"] = scores[best].astype(np.float32)
    out["anomaly_score_norm"] = norm.astype(np.float32)
    out["anomaly_flag"] = best_pred.astype(np.int8)
    out.to_parquet(ANOMALY_PARQUET, index=False)

    per_cat = out.groupby("attack_cat")["anomaly_flag"].agg(["size", "mean"]).rename(
        columns={"size": "flows", "mean": "flag_rate"}).sort_values("flag_rate", ascending=False)
    per_cat.to_csv(REPORTS_DIR / "metrics" / "anomaly_detection_by_category.csv")
    print("Flag rate per class (best model):\n", per_cat.round(3).to_string())

    result = {"best_model": best, "comparison": table.to_dict(orient="records"),
              "samples": SAMPLES, "fit_normals": len(fit_df), "val_normals": len(val_df),
              "test_flows": len(test), "n_features": X_fit.shape[1],
              "detection_by_category": per_cat.reset_index().to_dict(orient="records")}
    save_json(result, "anomaly_results")
    return result


if __name__ == "__main__":
    run()
