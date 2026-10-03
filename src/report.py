"""Phase 11: SOC-style insights report. Every number is read from saved pipeline outputs."""
import pandas as pd

from config import EXPORT_DIR, REPORTS_DIR, RISK_WEIGHTS
from utils import banner, load_json

M = REPORTS_DIR / "metrics"
SQL = EXPORT_DIR / "sql"


def pct(x, d=1):
    return f"{100 * x:.{d}f}%"


def gather():
    g = {
        "eda": load_json("eda_profile"), "clean": load_json("cleaning_summary"),
        "tp": load_json("threat_patterns"), "an": load_json("anomaly_results"),
        "sup": load_json("supervised_results"), "risk": load_json("risk_results"),
        "kpis": pd.read_csv(M / "kpis.csv"),
        "seg_sql": pd.read_csv(SQL / "q07_suspicious_segments.csv"),
        "svc": pd.read_csv(SQL / "q06_top_targeted_services.csv"),
        "proto": pd.read_csv(SQL / "q02_attack_rate_by_protocol.csv"),
        "an_cat": pd.read_csv(M / "anomaly_detection_by_category.csv"),
        "per_class": pd.read_csv(M / "multiclass_per_class_report.csv", index_col=0),
        "shap": pd.read_csv(M / "feature_importance_shap.csv"),
        "seg_risk": pd.read_csv(M / "segment_risk.csv"),
        "flows": pd.read_parquet(REPORTS_DIR.parent / "data" / "processed" / "flows_clean.parquet",
                                 columns=["proto", "label", "split"]),
    }
    g["best_bin"] = next(m for m in g["sup"]["binary"] if m["model"] == g["sup"]["best_binary"])
    g["best_an"] = g["an"]["comparison"][0]
    g["buckets"] = {b["risk_bucket"]: b for b in g["risk"]["bucket_distribution"]}
    return g


def build_recommendations(g=None):
    """Finding -> Evidence -> Recommended action -> Priority (also exported for Power BI)."""
    g = g or gather()
    seg = g["seg_sql"].set_index(["proto", "service", "state"])
    dns_int = seg.loc[("udp", "dns", "INT")]
    svc = g["svc"].set_index("service")
    flows = g["flows"]
    common = set(g["risk"]["rule_thresholds"]["common_protos"])
    rare = flows[~flows["proto"].astype(str).isin(common)]
    flag = {r["label"]: r for r in g["risk"]["rule_flag_rates_by_label"]}
    an_cat = g["an_cat"].set_index("attack_cat")["flag_rate"]
    pc = g["per_class"]
    b, crit = g["best_bin"], g["buckets"]["Critical"]
    shap = g["shap"].set_index("feature")["mean_abs_shap"]
    exploit_svcs = svc[svc["dominant_attack"] == "Exploits"].head(4)

    recs = [
        ("Unanswered UDP/DNS bursts (Generic attacks) are the largest threat by volume",
         f"udp/dns/INT segment: {int(dns_int.flows):,} flows, {dns_int.attack_rate_pct:.1f}% malicious; "
         f"{svc.loc['dns','dominant_pct']:.1f}% of DNS attack flows are Generic; sub-ms flows are "
         f"{pct(next(x['attack_rate'] for x in g['tp']['duration_bins'] if x['dur_bin']=='<1ms'))} attacks",
         "Enable DNS response-rate limiting, block unsolicited inbound DNS from untrusted sources, alert on "
         "bursts of INT-state (no-reply) UDP flows to the same host/service", "Critical"),
        ("Exploit traffic concentrates on classic application services",
         "Exploits dominate attack flows on " + ", ".join(
             f"{s} ({r.dominant_pct:.0f}% of {int(r.attack_flows):,})" for s, r in exploit_svcs.iterrows()),
         "Prioritise patching of web, mail and FTP servers; put HTTP behind a WAF/IPS with exploit signatures; "
         "disable plaintext POP3/FTP where possible", "Critical"),
        ("Uncommon IP protocols are almost always malicious",
         f"{len(rare):,} flows use protocols outside {sorted(common)}; {pct(rare['label'].mean())} are attacks. "
         f"Rare-protocol rule fires on {pct(flag[1]['flag_rare_proto'])} of attacks vs "
         f"{pct(flag[0]['flag_rare_proto'], 2)} of normal flows",
         "Default-deny non-essential IP protocols at the perimeter and on internal segments; alert on any "
         "allowed exception", "High"),
        ("Supervised detector catches almost every attack but raises many false alarms on new traffic",
         f"{b['model']}: recall {pct(b['recall_attack'])}, PR-AUC {b['pr_auc']:.3f}, but FPR {pct(b['fpr'])} "
         f"({b['fp']:,} false alarms on {b['fp'] + b['tn']:,} normal test flows) - train/test distribution shift",
         f"Triage by risk bucket rather than raw model alerts: Critical-bucket precision is "
         f"{pct(crit['attack_precision'])} on {crit['flows']:,} flows. Re-tune the threshold on recent local "
         "traffic and retrain regularly", "High"),
        ("The model leans heavily on TTL, a lab-specific artefact",
         f"sttl mean abs SHAP {shap.iloc[0]:.2f} vs {shap.index[1]} {shap.iloc[1]:.2f}; sttl/dttl 254/0 is "
         f"{pct(next(t['attack_rate'] for t in g['tp']['ttl'] if t['sttl']==254 and t['dttl']==0))} attacks",
         "Before production use, validate on your own network captures and test a model without TTL "
         "features; treat UNSW-NB15 accuracy as an upper bound", "High"),
        ("Unsupervised anomaly detection misses stealthy and payload-based attacks",
         f"Isolation Forest flags {pct(an_cat['Generic'])} of Generic and {pct(an_cat['DoS'])} of DoS flows, but only "
         f"{pct(an_cat['Reconnaissance'])} of Reconnaissance, {pct(an_cat['Shellcode'])} of Shellcode and "
         f"{pct(an_cat['Worms'])} of Worms",
         "Keep anomaly scoring as one layer (novelty detection) alongside signatures/IDS rules and the "
         "supervised model - never as the only control", "Medium"),
        ("Attack-type labels for DoS / Analysis / Backdoor are unreliable",
         f"Multiclass F1: DoS {pc.loc['DoS','f1-score']:.2f}, Analysis {pc.loc['Analysis','f1-score']:.2f}, "
         f"Backdoor {pc.loc['Backdoor','f1-score']:.2f} (vs Generic {pc.loc['Generic','f1-score']:.2f}) - their "
         "flow features overlap heavily",
         "Use the binary attack score for alerting and treat predicted category as a hint; enrich these "
         "alerts with payload/host context before escalation", "Medium"),
        ("Visibility gap: no IPs, ports or timestamps in this dataset version",
         "IP-level risk, true port-scan counts (distinct dsport per srcip) and peak attack hours could not "
         "be computed; segment-level substitutes were used",
         "Ingest the full UNSW-NB15 release or production NetFlow/Zeek logs with IPs and timestamps to "
         "enable per-host risk, scan detection and time-based alerting", "Medium"),
    ]
    return pd.DataFrame(recs, columns=["finding", "evidence", "recommended_action", "priority"])


def run():
    banner("PHASE 11 - INSIGHTS REPORT")
    g = gather()
    recs = build_recommendations(g)
    recs.to_csv(EXPORT_DIR / "recommendations.csv", index=False)
    e, c, b, a = g["eda"], g["clean"], g["best_bin"], g["best_an"]
    k = g["kpis"].set_index("kpi")["value"]
    bk = g["buckets"]
    sup = g["sup"]
    multi_best = next(m for m in sup["multiclass"] if m["model"] == sup["best_multiclass"])
    chi = g["tp"]["chi_square"]["attack_cat_vs_proto"]
    mw = {m["feature"]: m for m in g["tp"]["mann_whitney"]}
    st = {s["state"]: s for s in g["tp"]["state"]}
    top_svc = g["svc"].iloc[0]

    bin_tbl = pd.DataFrame(sup["binary"])[["model", "precision", "recall_attack", "f1", "roc_auc", "pr_auc", "fpr"]]
    an_tbl = pd.DataFrame(g["an"]["comparison"])[["model", "precision", "recall_attack", "f1", "roc_auc", "pr_auc", "fpr"]]
    mc_tbl = pd.DataFrame(sup["multiclass"])
    kpi_tbl = g["kpis"][["kpi", "value"]]
    bucket_tbl = pd.DataFrame(g["risk"]["bucket_distribution"])[["risk_bucket", "flows", "pct_flows",
                                                                 "true_attacks", "attack_precision", "avg_risk"]]
    seg_tbl = g["seg_risk"].head(10)[["segment", "flows", "critical_flows", "mean_risk", "max_risk",
                                      "segment_risk_bucket"]]
    rec_md = "\n".join(f"| {i} | {r.finding} | {r.evidence} | {r.recommended_action} | **{r.priority}** |"
                       for i, r in enumerate(recs.itertuples(), 1))

    md = f"""# SOC Threat Analytics Report – UNSW-NB15

*Generated by `src/report.py` from pipeline outputs in `reports/metrics/`. All numbers come from actual runs.*

## 1. Executive summary

- **{int(k['Total flows (train+test)']):,} network flows** analysed; **{float(k['Attack rate %']):.2f}% are attacks**
  ({int(k['Attack flows']):,} flows across 9 attack families). Most frequent attack type: **{k['Top attack type']}**
  ({int(k['Top attack type flows']):,} flows). Most targeted identified service: **{top_svc.service}**
  ({int(top_svc.attack_flows):,} attack flows).
- Best detector, **{b['model']}**, catches **{pct(b['recall_attack'])}** of attacks on the held-out test split
  (PR-AUC {b['pr_auc']:.3f}), but **{pct(b['fpr'])} of normal flows are falsely flagged**. That is a real
  operational cost, driven by a distribution shift between the official train and test files.
- The combined **risk score** ranks traffic well (ROC-AUC {g['risk']['risk_auc_vs_label']['roc_auc']:.3f} vs. true labels).
  {bk['Critical']['flows']:,} test flows ({bk['Critical']['pct_flows']:.1f}%) are **Critical**, and
  {pct(bk['Critical']['attack_precision'])} of those are real attacks. The **Low** bucket holds only
  {pct(bk['Low']['attack_precision'])} attacks.
- Top risks: DNS/UDP Generic floods, exploits against HTTP/SMTP/FTP, rare IP protocols, and a model that
  depends on lab-specific TTL values.

## 2. Problem

A SOC needs to (1) separate malicious from benign flows, (2) understand which attack families hit which
services, (3) surface novel or anomalous behaviour, and (4) prioritise alerts so analysts work the riskiest
traffic first.

## 3. Data

- **UNSW-NB15, official train/test release** (UNSW Canberra Cyber Range Lab, 2015): {e['rows_by_split']['train']:,}
  training + {e['rows_by_split']['test']:,} testing flows, 45 columns, 10 classes. Attack share is
  {pct(e['attack_share_by_split']['train'])} in train vs {pct(e['attack_share_by_split']['test'])} in test.
- **Not available in this release:** srcip, dstip, sport, dsport, stime, ltime. IP-level, port-level and
  time-of-day analyses were **skipped or replaced** (segment = proto/service/state; connection-context
  counters `ct_*` for scan/DoS behaviour; duration bins instead of time). No data was invented.
- Cleaning ({c['rows_before']:,} → {c['rows_after']:,} rows, no rows dropped): {c['duplicates_flagged']:,}
  feature-identical duplicates flagged; {c['test_rows_seen_in_train']:,} test rows identical to a training row;
  {c['invalid_ftp_login']} invalid `is_ftp_login` values capped; {c['zero_duration']:,} zero-duration flows flagged.
  See `reports/cleaning_log.md`.
- Phase 9 (simulated auth/user/asset data) was **not generated**. Everything here is real UNSW-NB15 data.

## 4. Methods

| Step | What was done |
|---|---|
| Storage | SQLite DB (`network_flows`, `dim_attack_type`, `segment_summary`, `flow_risk`, `segment_risk`), loaded in 50k-row chunks, row counts verified; 19 SQL queries (CTEs, RANK, LAG, NTILE, rolling windows) + dashboard views |
| Statistics | Chi-square + Cramér's V (attack type × protocol/service), Mann-Whitney U with rank-biserial effect sizes, Spearman correlations |
| Anomaly detection | Isolation Forest, LOF (novelty, 20k-sample), One-Class SVM (10k-sample), MLP autoencoder (20k-sample); fit on **normal training flows only**, threshold = 95th percentile of held-out normal scores, evaluated on the full test split |
| Supervised ML | Logistic Regression, Random Forest, LightGBM; binary and 10-class; official split (no timestamps for a time split, no shuffling across files); preprocessing fit on train only; ids/labels/flags/TCP sequence numbers excluded; `class_weight='balanced'`; SHAP on 2,000 test flows |
| Risk score | `100 × ({RISK_WEIGHTS['anomaly']} · anomaly ECDF + {RISK_WEIGHTS['model_prob']} · P(attack) + {RISK_WEIGHTS['severity']} · expected severity + {RISK_WEIGHTS['rules']} · rule flags)`; buckets Low <25 ≤ Medium <50 ≤ High <75 ≤ Critical |

**Why these risk weights:** the anomaly score carries the most weight (0.40) because it is the only
label-free component and can surface novel behaviour. The classifier (0.30) is the strongest detector, but
it only knows attack families it was trained on and over-fits lab artefacts. Expected severity (0.20) turns
"is it bad" into "how bad" using *predicted* class probabilities, never the true label. Rule flags (0.10) are
transparent but coarse.

## 5. Key findings

1. **Connection state is a top signal.** INT (no-reply) flows are {pct(st['INT']['attack_rate'])} attacks
   ({st['INT']['flows']:,} flows); established CON flows are only {pct(st['CON']['attack_rate'])}.
2. **Attacks are small and fast.** Median attack sbytes {mw['sbytes']['median_attack']:.0f} vs
   {mw['sbytes']['median_normal']:.0f} for normal (rank-biserial {mw['sbytes']['rank_biserial']:+.2f}); attack flows
   usually get no response (dbytes r={mw['dbytes']['rank_biserial']:+.2f}, large effect).
3. **Attack type depends on protocol** (χ²={chi['chi2']:,.0f}, dof={chi['dof']}, Cramér's V={chi['cramers_v']:.2f}).
   DNS is dominated by Generic attacks; HTTP, SMTP, FTP and POP3 by Exploits; uncommon protocols are almost
   always malicious.
4. **Supervised beats unsupervised.** {b['model']} PR-AUC {b['pr_auc']:.3f} vs best anomaly detector
   ({a['model']}) PR-AUC {a['pr_auc']:.3f}. The anomaly detector misses Reconnaissance and Shellcode.
5. **Multiclass is much harder than binary.** Best macro-F1 {multi_best['macro_f1']:.3f} ({sup['best_multiclass']}).
   DoS, Analysis and Backdoor are frequently confused with each other.
6. **Model explanations reveal dataset bias.** `sttl` has by far the largest SHAP importance, which
   reflects how the lab generated attack traffic rather than a universal attack property.

### Model results (held-out test split, {e['rows_by_split']['test']:,} flows)

**Binary (normal vs attack), threshold 0.5**

{bin_tbl.to_markdown(index=False, floatfmt=".4f")}

**Anomaly detectors (unsupervised)**

{an_tbl.to_markdown(index=False, floatfmt=".4f")}

**Multiclass (attack_cat)**

{mc_tbl.to_markdown(index=False, floatfmt=".4f")}

### Risk buckets (test split)

{bucket_tbl.to_markdown(index=False, floatfmt=".4g")}

### Highest-impact segments (proto/service/state, by Critical flows)

{seg_tbl.to_markdown(index=False)}

### KPIs

{kpi_tbl.to_markdown(index=False)}

## 6. Recommendations (Finding → Evidence → Recommended action → Priority)

| # | Finding | Evidence | Recommended action | Priority |
|---|---|---|---|---|
{rec_md}

## 7. Limitations

- **Lab-generated, 2015 data.** UNSW-NB15 was produced with the IXIA PerfectStorm tool in a cyber-range lab.
  Traffic mixes, protocols and attack tooling differ from a modern enterprise network.
- **Dataset artefacts.** TTL values (`sttl`, `dttl`, `ct_state_ttl`) almost encode the label. Models will
  overfit to this dataset and should be re-validated on local traffic before use.
- **Train/test distribution shift.** The official files differ in class mix, which drives the
  {pct(b['fpr'])} false-positive rate. Thresholds were *not* tuned on the test set, to avoid leakage.
- **Missing fields.** No IPs, ports or timestamps, so there is no IP-level risk, true port-scan detection,
  or time trends. Segment-level and behavioural substitutes are approximations.
- **Duplicates.** {c['duplicates_flagged']:,} duplicate flows were kept to preserve the benchmark split, and
  {c['test_rows_seen_in_train']:,} test rows also appear in train, which slightly inflates test scores.
- **Label-based evaluation.** Metrics assume the dataset labels are correct. Some UNSW-NB15 classes
  (DoS / Analysis / Backdoor) have near-identical feature vectors, which caps achievable multiclass accuracy.
- **Sampling.** LOF, One-Class SVM and the autoencoder were fit on samples (20k / 10k / 20k normal flows),
  and SHAP was computed on 2,000 flows.
- **Synthetic data.** None was used. Phase 9 was skipped by choice.
"""
    (REPORTS_DIR / "insights_report.md").write_text(md, encoding="utf-8")
    print(f"Wrote reports/insights_report.md ({len(md):,} chars) and powerbi/exports/recommendations.csv")
    print(recs[["finding", "priority"]].to_string(index=False))
    return recs


if __name__ == "__main__":
    run()
