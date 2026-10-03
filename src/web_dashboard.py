"""Phase 12: build a self-contained interactive web dashboard (dashboard/index.html).

All numbers are aggregated from the pipeline outputs and embedded as JSON, so the page works
offline in any browser (Chart.js is the only external script, loaded from cdnjs).
"""
import json

import numpy as np
import pandas as pd

from config import CLEAN_PARQUET, EXPORT_DIR, RISK_PARQUET, ROOT
from utils import banner, load_json

TEMPLATE = ROOT / "src" / "web_dashboard_template.html"
OUT_DIR = ROOT / "dashboard"
CAT_ORDER = ["Normal", "Generic", "Exploits", "Fuzzers", "DoS", "Reconnaissance",
             "Analysis", "Backdoor", "Shellcode", "Worms"]


def _records(df):
    return json.loads(df.to_json(orient="records"))


def build_data():
    flows = pd.read_parquet(CLEAN_PARQUET, columns=["service", "state", "dur", "label", "attack_cat"])
    risk = pd.read_parquet(RISK_PARQUET)
    for c in risk.select_dtypes(include="category").columns:
        risk[c] = risk[c].astype(str)
    sup, an, rr = load_json("supervised_results"), load_json("anomaly_results"), load_json("risk_results")
    eda, cl, tp = load_json("eda_profile"), load_json("cleaning_summary"), load_json("threat_patterns")

    # Filterable cube of the 82,332 risk-scored test flows
    cube = (risk.groupby(["service", "attack_cat", "risk_bucket", "label", "pred_attack", "pred_attack_cat"])
            .size().rename("n").reset_index())

    abt = pd.read_csv(EXPORT_DIR / "attack_by_type.csv")
    abt["order"] = abt["attack_cat"].map({c: i for i, c in enumerate(CAT_ORDER)})
    abt = abt.sort_values("order")

    svc = flows.assign(service=flows["service"].astype(str), attack_cat=flows["attack_cat"].astype(str))
    mat = pd.crosstab(svc["service"], svc["attack_cat"]).reindex(columns=CAT_ORDER, fill_value=0)
    mat = mat.loc[mat.sum(axis=1).sort_values(ascending=False).index]

    st = flows.groupby(flows["state"].astype(str)).agg(flows=("label", "size"), attacks=("label", "sum"))
    st = st[st["flows"] >= 50].sort_values("flows", ascending=False).reset_index()

    bins = [-1, 0, 0.001, 0.01, 0.1, 1, 10, np.inf]
    labels = ["0 s", "<1 ms", "1–10 ms", "10–100 ms", "0.1–1 s", "1–10 s", "≥10 s"]
    db = flows.assign(b=pd.cut(flows["dur"], bins=bins, labels=labels)).groupby("b", observed=False).agg(
        flows=("label", "size"), attacks=("label", "sum")).reset_index().rename(columns={"b": "bin"})
    db["bin"] = db["bin"].astype(str)

    top_flows = risk.sort_values("risk_score", ascending=False).groupby("service").head(60)
    top_flows = top_flows.sort_values("risk_score", ascending=False)[
        ["flow_id", "proto", "service", "state", "sbytes", "dbytes", "rate", "attack_cat", "pred_attack_cat",
         "p_attack", "anomaly_score_norm", "risk_score", "risk_bucket"]].round(3)

    seg = pd.read_csv(EXPORT_DIR / "top_risky_segments.csv").head(15)
    mm = pd.read_csv(EXPORT_DIR / "model_metrics.csv")
    pc = pd.read_csv(EXPORT_DIR / "per_class_report.csv")
    fi = pd.read_csv(EXPORT_DIR / "feature_importance.csv").head(12)
    recs = pd.read_csv(EXPORT_DIR / "recommendations.csv")
    kpis = pd.read_csv(EXPORT_DIR / "kpis.csv")

    return {
        "meta": {"train": eda["rows_by_split"]["train"], "test": eda["rows_by_split"]["test"],
                 "duplicates": cl["duplicates_flagged"], "overlap": cl["test_rows_seen_in_train"],
                 "best_binary": sup["best_binary"], "best_multi": sup["best_multiclass"],
                 "best_anomaly": an["best_model"], "risk_auc": rr["risk_auc_vs_label"]["roc_auc"],
                 "weights": rr["weights"], "chi_v": tp["chi_square"]["attack_cat_vs_proto"]["cramers_v"]},
        "kpis": _records(kpis),
        "cube": cube.values.tolist(),
        "attack_types": _records(abt[["attack_cat", "flows", "severity_weight", "severity_level", "description",
                                      "avg_sbytes", "avg_dur"]].round(4)),
        "matrix": {"rows": mat.index.tolist(), "cols": CAT_ORDER, "values": mat.values.tolist()},
        "states": _records(st), "dur_bins": _records(db),
        "segments": _records(seg[["segment", "flows", "critical_flows", "mean_risk", "max_risk",
                                  "true_attack_flows", "segment_risk_bucket"]]),
        "models": _records(mm[["family", "model", "precision", "recall_attack", "f1", "roc_auc", "pr_auc", "fpr"]]),
        "multiclass": sup["multiclass"],
        "per_class": _records(pc[["class", "precision", "recall", "f1-score", "support"]]),
        "features": _records(fi[["feature", "mean_abs_shap"]].round(4)),
        "recs": _records(recs),
        "top_flows": _records(top_flows),
        "mann_whitney": tp["mann_whitney"],
    }


def run():
    banner("PHASE 12 - WEB DASHBOARD")
    data = build_data()
    html = TEMPLATE.read_text(encoding="utf-8").replace(
        "/*__DATA__*/null", json.dumps(data, separators=(",", ":")))
    OUT_DIR.mkdir(exist_ok=True)
    # artifact.html = page body only (for publishing); index.html = full document to open locally
    (OUT_DIR / "artifact.html").write_text(html, encoding="utf-8")
    out = OUT_DIR / "index.html"
    head = "\n".join(['<!doctype html>', '<html lang="en">', '<head>', '<meta charset="utf-8">',
                      '<meta name="viewport" content="width=device-width, initial-scale=1">',
                      '</head>', '<body>', ''])
    out.write_text(head + html + "\n".join(["", "</body>", "</html>", ""]), encoding="utf-8")
    print(f"Wrote dashboard/index.html ({len(html) / 1024:.0f} KB, {len(data['cube'])} cube rows)")
    return out


if __name__ == "__main__":
    run()
