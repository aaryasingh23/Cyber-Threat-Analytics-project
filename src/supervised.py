"""Phase 7: supervised ML - binary (normal vs attack) and multiclass (attack_cat).

Split strategy: the dataset has no timestamps, so a time-based split is impossible. We use the
OFFICIAL UNSW-NB15 train/test files (175,341 / 82,332 flows), which the authors generated
separately - no random shuffling between them, so no shuffle leakage. Preprocessing is fit on
train only. Excluded from features: ids, labels, attack_cat, split, cleaning flags, TCP sequence
numbers (see features.py). srcip/dstip/stime do not exist in this release.
Imbalance: class_weight='balanced' (no SMOTE).
"""
import warnings

import lightgbm as lgb
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score

from config import CLEAN_PARQUET, PREDICTIONS_PARQUET, REPORTS_DIR, SEED
from features import build_preprocessor, split_train_test, transform
from models import binary_metrics, metrics_table, plot_confusion, plot_curves
from utils import banner, save_fig, save_json, timer

CLASSES = ["Normal", "Generic", "Exploits", "Fuzzers", "DoS", "Reconnaissance",
           "Analysis", "Backdoor", "Shellcode", "Worms"]


def make_models(task):
    lgb_obj = {"objective": "binary"} if task == "binary" else {"objective": "multiclass"}
    # Multiclass LR with lbfgs took ~10 min at 2000 iterations; 300 is plenty for a baseline.
    lr_iter = 2000 if task == "binary" else 300
    return {
        "LogisticRegression": LogisticRegression(max_iter=lr_iter, class_weight="balanced", C=1.0),
        "RandomForest": RandomForestClassifier(n_estimators=300, min_samples_leaf=2, max_features="sqrt",
                                               class_weight="balanced_subsample", n_jobs=-1,
                                               random_state=SEED),
        "LightGBM": lgb.LGBMClassifier(n_estimators=400, learning_rate=0.05, num_leaves=63,
                                       subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
                                       class_weight="balanced", random_state=SEED, n_jobs=-1,
                                       verbose=-1, **lgb_obj),
    }


def importance_plot(model, names, title, fname, top=20):
    imp = pd.Series(model.feature_importances_, index=names)
    imp = (imp / imp.sum()).sort_values(ascending=False).head(top)
    fig, ax = plt.subplots(figsize=(8, 6))
    imp[::-1].plot.barh(ax=ax, color="#1565c0")
    ax.set_title(title)
    ax.set_xlabel("relative importance")
    save_fig(fig, fname)
    return imp


def run():
    banner("PHASE 7 - SUPERVISED ML")
    df = pd.read_parquet(CLEAN_PARQUET)
    train, test = split_train_test(df)
    pre, info = build_preprocessor(train)
    X_tr = pre.fit_transform(train).astype(np.float32)
    X_te = transform(pre, test)
    names = list(X_tr.columns)
    print(f"Train {X_tr.shape}, test {X_te.shape} - official split, preprocessing fit on train only")

    # ------------------------------------------------------------ binary
    y_tr, y_te = train["label"].to_numpy(), test["label"].to_numpy()
    rows, probs, fitted = [], {}, {}
    for name, model in make_models("binary").items():
        with timer(f"binary {name}"):
            model.fit(X_tr, y_tr)
        p = model.predict_proba(X_te)[:, 1]
        rows.append(binary_metrics(y_te, p, (p >= 0.5).astype(int), name))
        probs[name], fitted[name] = p, model
    bin_table = metrics_table(rows).sort_values("pr_auc", ascending=False)
    print(bin_table[["model", "precision", "recall_attack", "f1", "roc_auc", "pr_auc", "fpr", "accuracy"]]
          .to_string(index=False))
    bin_table.to_csv(REPORTS_DIR / "metrics" / "binary_model_comparison.csv", index=False)
    best_bin = bin_table.iloc[0]["model"]
    plot_curves(y_te, probs, "binary classifiers (test set)", "07_binary_roc_pr")
    plot_confusion(y_te, (probs[best_bin] >= 0.5).astype(int), [0, 1],
                   f"{best_bin} binary (threshold 0.5)", "07_binary_confusion")

    # Per-category recall of the best binary model (which attacks slip through?)
    det = pd.DataFrame({"attack_cat": test["attack_cat"], "pred": (probs[best_bin] >= 0.5).astype(int)})
    det_by_cat = det.groupby("attack_cat")["pred"].agg(["size", "mean"]).rename(
        columns={"size": "flows", "mean": "flagged_as_attack"}).sort_values("flagged_as_attack")
    det_by_cat.to_csv(REPORTS_DIR / "metrics" / "binary_detection_by_category.csv")
    print("Best binary model - share flagged as attack per class:\n", det_by_cat.round(3).to_string())

    # ------------------------------------------------------------ multiclass
    yc_tr, yc_te = train["attack_cat"].to_numpy(), test["attack_cat"].to_numpy()
    mrows, mfitted, mpreds = [], {}, {}
    for name, model in make_models("multiclass").items():
        with timer(f"multiclass {name}"):
            model.fit(X_tr, yc_tr)
        pred = model.predict(X_te)
        mrows.append({"model": name,
                      "macro_f1": f1_score(yc_te, pred, average="macro"),
                      "weighted_f1": f1_score(yc_te, pred, average="weighted"),
                      "macro_recall": classification_report(yc_te, pred, output_dict=True,
                                                            zero_division=0)["macro avg"]["recall"],
                      "accuracy": float((pred == yc_te).mean())})
        mfitted[name], mpreds[name] = model, pred
    multi_table = metrics_table(mrows).sort_values("macro_f1", ascending=False)
    print(multi_table.to_string(index=False))
    multi_table.to_csv(REPORTS_DIR / "metrics" / "multiclass_model_comparison.csv", index=False)
    best_multi = multi_table.iloc[0]["model"]
    report = classification_report(yc_te, mpreds[best_multi], labels=CLASSES, output_dict=True, zero_division=0)
    per_class = pd.DataFrame(report).T.loc[CLASSES].round(4)
    per_class.to_csv(REPORTS_DIR / "metrics" / "multiclass_per_class_report.csv")
    print(f"Per-class report ({best_multi}):\n", per_class.to_string())
    plot_confusion(yc_te, mpreds[best_multi], CLASSES, f"{best_multi} multiclass (row-normalised)",
                   "07_multiclass_confusion", normalize="true")

    # ------------------------------------------------------------ explainability
    imp_rf = importance_plot(fitted["RandomForest"], names, "Random Forest (binary) - impurity importance",
                             "07_importance_rf")
    lgbm = fitted["LightGBM"]
    lgbm_gain = pd.Series(lgbm.booster_.feature_importance("gain"), index=names)
    lgbm_gain = (lgbm_gain / lgbm_gain.sum()).sort_values(ascending=False)
    fig, ax = plt.subplots(figsize=(8, 6))
    lgbm_gain.head(20)[::-1].plot.barh(ax=ax, color="#1565c0")
    ax.set_title("LightGBM (binary) - gain importance")
    save_fig(fig, "07_importance_lgbm")

    shap_n = 2000
    X_shap = X_te.sample(shap_n, random_state=SEED)
    with timer(f"SHAP TreeExplainer on {shap_n:,} test flows"), warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        sv = shap.TreeExplainer(lgbm).shap_values(X_shap)
        sv = sv[1] if isinstance(sv, list) else sv
    plt.figure()
    shap.summary_plot(sv, X_shap, show=False, max_display=20)
    save_fig(plt.gcf(), "07_shap_summary")
    plt.figure()
    shap.summary_plot(sv, X_shap, plot_type="bar", show=False, max_display=20)
    save_fig(plt.gcf(), "07_shap_bar")
    shap_imp = pd.Series(np.abs(sv).mean(axis=0), index=names).sort_values(ascending=False)
    pd.DataFrame({"feature": names, "rf_importance": imp_rf.reindex(names).fillna(0).values}).to_csv(
        REPORTS_DIR / "metrics" / "feature_importance_rf.csv", index=False)
    pd.DataFrame({"feature": shap_imp.index, "mean_abs_shap": shap_imp.values,
                  "lgbm_gain": lgbm_gain.reindex(shap_imp.index).values}).to_csv(
        REPORTS_DIR / "metrics" / "feature_importance_shap.csv", index=False)
    print("Top SHAP features:", shap_imp.head(10).round(3).to_dict())

    # ------------------------------------------------------------ save predictions for risk scoring
    best_m = mfitted[best_multi]
    proba = pd.DataFrame(best_m.predict_proba(X_te), columns=[f"p_{c}" for c in best_m.classes_])
    preds = pd.DataFrame({
        "flow_id": df.loc[df["split"] == "test", "flow_id"].to_numpy(),
        "label": y_te, "attack_cat": yc_te,
        "p_attack": probs[best_bin].astype(np.float32),
        "pred_attack": (probs[best_bin] >= 0.5).astype(np.int8),
        "pred_attack_cat": mpreds[best_multi],
    })
    preds = pd.concat([preds, proba.astype(np.float32)], axis=1)
    preds.to_parquet(PREDICTIONS_PARQUET, index=False)

    result = {"split": "official train/test (no timestamps -> no time split)",
              "n_features": len(names), "best_binary": best_bin, "best_multiclass": best_multi,
              "binary": bin_table.to_dict(orient="records"),
              "multiclass": multi_table.to_dict(orient="records"),
              "per_class": per_class.reset_index().rename(columns={"index": "class"}).to_dict(orient="records"),
              "binary_detection_by_category": det_by_cat.reset_index().to_dict(orient="records"),
              "top_shap": shap_imp.head(15).to_dict(), "shap_sample": shap_n}
    save_json(result, "supervised_results")
    return result


if __name__ == "__main__":
    run()
