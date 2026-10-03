"""Phase 8: flow-level and segment-level risk scoring + security KPIs.

Risk score (0-100), computed for every flow of the held-out TEST split (82,332 flows) so that
every component is out-of-sample:

    risk = 100 * ( 0.40 * anomaly_norm      # Isolation-Forest score as ECDF vs held-out normal traffic
                 + 0.30 * p_attack          # best binary classifier's attack probability
                 + 0.20 * exp_severity      # sum_c P(class c) * severity_weight(c) from the multiclass model
                 + 0.10 * rule_score )      # mean of 3 transparent rule flags

Why these weights
-----------------
* 0.40 anomaly  - label-free; the only component that can surface novel / zero-day behaviour,
                  so it carries the most weight even though it is noisier than the classifier.
* 0.30 model    - strongest single detector on known attack families, but it can only recognise
                  what it was trained on (and over-fits lab artefacts such as TTL).
* 0.20 severity - turns "is it bad" into "how bad": a predicted Worm/Backdoor matters more than
                  a Fuzzer. Uses PREDICTED class probabilities, never the true label (no leakage).
* 0.10 rules    - simple, explainable analyst rules; low weight because they are coarse.

Rule flags (thresholds learned on NORMAL TRAINING traffic only):
  * flag_high_pkt_rate : rate > 99th percentile of normal train flows
  * flag_rare_proto    : protocol seen in < 0.1% of normal train flows (substitute for "rare port",
                         ports are not in this release)
  * flag_burst_context : ct_srv_src or ct_dst_src_ltm > 99th percentile of normal train flows
                         (repetitive host/service hammering - substitute for "port scan", since
                         distinct-port counts need IPs/ports)
"""
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from config import (ANOMALY_PARQUET, CLEAN_PARQUET, PREDICTIONS_PARQUET, REPORTS_DIR, RISK_BUCKETS,
                    RISK_PARQUET, RISK_WEIGHTS, SEVERITY)
from db import get_engine, run_script, view_stage, write_table
from utils import banner, load_json, save_json


def bucket(score):
    for lo, hi, name in RISK_BUCKETS:
        if lo <= score < hi:
            return name
    return "Critical"


def rule_thresholds(train_normal):
    proto_share = train_normal["proto"].astype(str).value_counts(normalize=True)
    return {
        "rate_p99": float(train_normal["rate"].quantile(0.99)),
        "ct_srv_src_p99": float(train_normal["ct_srv_src"].quantile(0.99)),
        "ct_dst_src_ltm_p99": float(train_normal["ct_dst_src_ltm"].quantile(0.99)),
        "common_protos": sorted(proto_share[proto_share >= 0.001].index.tolist()),
    }


def run():
    banner("PHASE 8 - RISK SCORING")
    flows = pd.read_parquet(CLEAN_PARQUET)
    anom = pd.read_parquet(ANOMALY_PARQUET)[["flow_id", "anomaly_score_norm", "anomaly_flag"]]
    preds = pd.read_parquet(PREDICTIONS_PARQUET)
    train_normal = flows[(flows["split"] == "train") & (flows["label"] == 0)]
    thr = rule_thresholds(train_normal)
    print(f"Rule thresholds (normal train): rate>{thr['rate_p99']:,.0f}, ct_srv_src>{thr['ct_srv_src_p99']:.0f}, "
          f"ct_dst_src_ltm>{thr['ct_dst_src_ltm_p99']:.0f}, common protos={thr['common_protos']}")

    test = flows[flows["split"] == "test"][["flow_id", "proto", "service", "state", "rate", "ct_srv_src",
                                             "ct_dst_src_ltm", "sbytes", "dbytes", "dur", "spkts"]]
    r = test.merge(anom, on="flow_id").merge(preds, on="flow_id")
    assert len(r) == len(test), "join lost rows"

    r["flag_high_pkt_rate"] = (r["rate"] > thr["rate_p99"]).astype(np.int8)
    r["flag_rare_proto"] = (~r["proto"].astype(str).isin(thr["common_protos"])).astype(np.int8)
    r["flag_burst_context"] = ((r["ct_srv_src"] > thr["ct_srv_src_p99"]) |
                               (r["ct_dst_src_ltm"] > thr["ct_dst_src_ltm_p99"])).astype(np.int8)
    r["rule_score"] = r[["flag_high_pkt_rate", "flag_rare_proto", "flag_burst_context"]].mean(axis=1)

    pcols = [c for c in r.columns if c.startswith("p_") and c != "p_attack"]
    sev = np.array([SEVERITY[c[2:]] for c in pcols])
    r["exp_severity"] = r[pcols].to_numpy() @ sev
    r["pred_severity"] = r["pred_attack_cat"].map(SEVERITY)

    w = RISK_WEIGHTS
    r["risk_score"] = (100 * (w["anomaly"] * r["anomaly_score_norm"] + w["model_prob"] * r["p_attack"] +
                              w["severity"] * r["exp_severity"] + w["rules"] * r["rule_score"])).round(2)
    r["risk_bucket"] = r["risk_score"].apply(bucket)
    r["risk_bucket"] = pd.Categorical(r["risk_bucket"], ["Low", "Medium", "High", "Critical"], ordered=True)

    keep = ["flow_id", "proto", "service", "state", "sbytes", "dbytes", "dur", "spkts", "rate",
            "label", "attack_cat", "pred_attack", "pred_attack_cat", "p_attack", "anomaly_score_norm",
            "anomaly_flag", "exp_severity", "pred_severity", "flag_high_pkt_rate", "flag_rare_proto",
            "flag_burst_context", "rule_score", "risk_score", "risk_bucket"]
    risk = r[keep].copy()
    risk.to_parquet(RISK_PARQUET, index=False)

    # ---------------- bucket validation (does risk rank true attacks well?)
    bd = risk.groupby("risk_bucket", observed=False).agg(
        flows=("flow_id", "size"), true_attacks=("label", "sum"), avg_risk=("risk_score", "mean"))
    bd["attack_precision"] = (bd["true_attacks"] / bd["flows"]).round(4)
    bd["pct_flows"] = (100 * bd["flows"] / bd["flows"].sum()).round(2)
    print(bd.to_string())
    flag_rates = risk[["flag_high_pkt_rate", "flag_rare_proto", "flag_burst_context"]].groupby(risk["label"]).mean()
    print("Rule flag rates by label:\n", flag_rates.round(3).to_string())

    # ---------------- segment-level risk (substitute for IP-level risk)
    seg = risk.groupby(["proto", "service", "state"], observed=True).agg(
        flows=("flow_id", "size"), max_risk=("risk_score", "max"), mean_risk=("risk_score", "mean"),
        p95_risk=("risk_score", lambda s: s.quantile(0.95)),
        critical_flows=("risk_bucket", lambda s: int((s == "Critical").sum())),
        predicted_attack_flows=("pred_attack", "sum"), true_attack_flows=("label", "sum"),
        distinct_pred_attack_types=("pred_attack_cat", lambda s: s[s != "Normal"].nunique()),
    ).reset_index()
    seg = seg[seg["flows"] >= 20].copy()
    seg["segment"] = seg["proto"].astype(str) + "/" + seg["service"].astype(str) + "/" + seg["state"].astype(str)
    seg["segment_risk_bucket"] = seg["mean_risk"].apply(bucket)
    # rank by impact: number of Critical flows, then mean risk
    seg = seg.sort_values(["critical_flows", "mean_risk"], ascending=False).round(2)
    seg.to_csv(REPORTS_DIR / "metrics" / "segment_risk.csv", index=False)
    print("Top risky segments:\n", seg.head(10)[["segment", "flows", "mean_risk", "max_risk",
                                                 "critical_flows", "segment_risk_bucket"]].to_string(index=False))

    # ---------------- KPIs
    sup, an = load_json("supervised_results"), load_json("anomaly_results")
    best_bin = next(m for m in sup["binary"] if m["model"] == sup["best_binary"])
    attacks = flows[flows["label"] == 1]
    svc = attacks.loc[attacks["service"] != "none", "service"].value_counts()
    kpis = [
        ("Total flows (train+test)", len(flows), "count"),
        ("Attack flows", int(flows["label"].sum()), "count"),
        ("Attack rate %", round(100 * flows["label"].mean(), 2), "percent"),
        ("Flows risk-scored (test split)", len(risk), "count"),
        ("Critical-risk flows", int((risk["risk_bucket"] == "Critical").sum()), "count"),
        ("High-risk flows", int((risk["risk_bucket"] == "High").sum()), "count"),
        ("Critical + High share %", round(100 * risk["risk_bucket"].isin(["Critical", "High"]).mean(), 2), "percent"),
        ("High/Critical-risk segments", int(seg["segment_risk_bucket"].isin(["High", "Critical"]).sum()), "count"),
        ("Top attack type", attacks["attack_cat"].astype(str).value_counts().index[0], "text"),
        ("Top attack type flows", int(attacks["attack_cat"].astype(str).value_counts().iloc[0]), "count"),
        ("Top targeted service", svc.index[0], "text"),
        ("Top targeted service attack flows", int(svc.iloc[0]), "count"),
        ("Detection rate (recall) - " + sup["best_binary"], round(100 * best_bin["recall_attack"], 2), "percent"),
        ("False positive rate - " + sup["best_binary"], round(100 * best_bin["fpr"], 2), "percent"),
        ("PR-AUC - " + sup["best_binary"], round(best_bin["pr_auc"], 4), "ratio"),
        ("Anomaly detector recall - " + an["best_model"],
         round(100 * an["comparison"][0]["recall_attack"], 2), "percent"),
        ("Peak attack hour", "N/A - no timestamps in train/test release", "text"),
        ("Top targeted port", "N/A - no ports in train/test release", "text"),
        ("Unique attacking IPs / targeted hosts", "N/A - no IPs in train/test release", "text"),
    ]
    kpi_df = pd.DataFrame(kpis, columns=["kpi", "value", "unit"])
    kpi_df.to_csv(REPORTS_DIR / "metrics" / "kpis.csv", index=False)
    print(kpi_df.to_string(index=False))

    # ---------------- DB: load risk tables + risk views
    engine = get_engine()
    write_table(risk, "flow_risk", engine)
    write_table(seg, "segment_risk", engine)
    run_script(engine, view_stage("risk"))
    print(" - flow_risk / segment_risk loaded into the database, risk views created")

    result = {"weights": RISK_WEIGHTS, "rule_thresholds": thr,
              "bucket_distribution": bd.reset_index().astype({"risk_bucket": str}).to_dict(orient="records"),
              "rule_flag_rates_by_label": flag_rates.reset_index().to_dict(orient="records"),
              "top_segments": seg.head(15).to_dict(orient="records"),
              "kpis": kpi_df.to_dict(orient="records")}
    result["risk_auc_vs_label"] = {"roc_auc": roc_auc_score(risk["label"], risk["risk_score"]),
                                   "pr_auc": average_precision_score(risk["label"], risk["risk_score"])}
    print("Risk score vs true label:", {k: round(v, 4) for k, v in result["risk_auc_vs_label"].items()})
    save_json(result, "risk_results")
    return result


if __name__ == "__main__":
    run()
