"""Phase 10: Power BI preparation - pre-aggregated exports + PNG previews of each dashboard page.

No raw 257k-row dump is exported. The flow-level table is the 82,332-flow risk-scored TEST split
(< 100k rows, every score out-of-sample).
"""
import textwrap

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.gridspec import GridSpec

from config import CLEAN_PARQUET, EXPORT_DIR, PREVIEW_DIR, REPORTS_DIR, RISK_COLORS, RISK_PARQUET
from db import dim_attack_type
from report import build_recommendations
from utils import banner, load_json

M = REPORTS_DIR / "metrics"
RISK_ORDER = ["Low", "Medium", "High", "Critical"]
BG, CARD, INK = "#0f1b2d", "#17263c", "#e8eef6"


def save(df, name, parquet=False):
    df.to_csv(EXPORT_DIR / f"{name}.csv", index=False)
    if parquet:
        df.to_parquet(EXPORT_DIR / f"{name}.parquet", index=False)
    print(f"   {name}: {len(df):,} rows")
    return df


def build_exports():
    flows = pd.read_parquet(CLEAN_PARQUET)
    risk = pd.read_parquet(RISK_PARQUET)
    sup, an = load_json("supervised_results"), load_json("anomaly_results")
    dim = dim_attack_type()

    kpis = pd.read_csv(M / "kpis.csv")
    save(kpis, "kpis")
    save(dim, "dim_attack_type")

    abt = flows.groupby("attack_cat", observed=True).agg(
        flows=("flow_id", "size"), avg_sbytes=("sbytes", "mean"), avg_dbytes=("dbytes", "mean"),
        avg_dur=("dur", "mean"), avg_spkts=("spkts", "mean"), avg_rate=("rate", "mean"),
        train_flows=("split", lambda s: int((s == "train").sum())),
        test_flows=("split", lambda s: int((s == "test").sum()))).reset_index()
    abt["attack_cat"] = abt["attack_cat"].astype(str)
    abt = abt.merge(dim, on="attack_cat")
    abt["pct_of_all_flows"] = (100 * abt["flows"] / abt["flows"].sum()).round(3)
    save(abt.round(4), "attack_by_type")

    bins = [-1, 0, 0.001, 0.01, 0.1, 1, 10, np.inf]
    labels = ["0s", "<1ms", "1-10ms", "10-100ms", "0.1-1s", "1-10s", ">=10s"]
    f2 = flows.assign(dur_bin=pd.cut(flows["dur"], bins=bins, labels=labels))
    dbin = f2.groupby(["dur_bin", "attack_cat"], observed=True).size().rename("flows").reset_index()
    dbin["dur_bin_order"] = dbin["dur_bin"].cat.codes
    save(dbin.astype({"dur_bin": str, "attack_cat": str}), "attack_by_duration_bin")

    psm = flows.groupby(["proto", "service", "attack_cat"], observed=True).agg(
        flows=("flow_id", "size"), attack_flows=("label", "sum")).reset_index()
    save(psm.astype({"proto": str, "service": str, "attack_cat": str}), "protocol_service_matrix")

    st = flows.groupby(["state", "attack_cat"], observed=True).size().rename("flows").reset_index()
    save(st.astype({"state": str, "attack_cat": str}), "attack_by_state")

    seg = pd.read_csv(M / "segment_risk.csv")
    save(seg.head(50), "top_risky_segments")

    bd = pd.DataFrame(load_json("risk_results")["bucket_distribution"])
    bd["sort_order"] = bd["risk_bucket"].map({b: i for i, b in enumerate(RISK_ORDER)})
    bd["color"] = bd["risk_bucket"].map(RISK_COLORS)
    save(bd, "risk_bucket_distribution")

    mm = []
    for r in sup["binary"]:
        mm.append({"family": "Supervised (binary)", **r})
    for r in an["comparison"]:
        mm.append({"family": "Anomaly (unsupervised)", **{k: v for k, v in r.items() if k != "threshold"}})
    save(pd.DataFrame(mm), "model_metrics")
    save(pd.DataFrame(sup["multiclass"]), "model_metrics_multiclass")
    save(pd.read_csv(M / "multiclass_per_class_report.csv").rename(columns={"Unnamed: 0": "class"}),
         "per_class_report")
    save(pd.read_csv(M / "feature_importance_shap.csv").head(30), "feature_importance")
    save(build_recommendations(), "recommendations")

    best = next(r for r in sup["binary"] if r["model"] == sup["best_binary"])
    cm = pd.DataFrame([("Normal", "Normal", best["tn"]), ("Normal", "Attack", best["fp"]),
                       ("Attack", "Normal", best["fn"]), ("Attack", "Attack", best["tp"])],
                      columns=["actual", "predicted", "flows"])
    save(cm, "confusion_matrix_binary")

    fs = risk.copy()
    for c in fs.select_dtypes(include="category").columns:
        fs[c] = fs[c].astype(str)
    fs["traffic"] = np.where(fs["label"] == 1, "Attack", "Normal")
    save(fs, "flow_sample", parquet=True)
    return dict(abt=abt, dbin=dbin, seg=seg, bd=bd, mm=pd.DataFrame(mm), kpis=kpis, risk=fs,
                flows=flows, sup=sup, an=an, st=st)


# ------------------------------------------------------------------ previews
def _card(fig, gs, title, value, color="#4fc3f7"):
    ax = fig.add_subplot(gs)
    ax.set_facecolor(CARD)
    ax.set_xticks([]), ax.set_yticks([])
    for s in ax.spines.values():
        s.set_visible(False)
    ax.text(0.5, 0.62, value, ha="center", va="center", fontsize=19, color=color, weight="bold")
    ax.text(0.5, 0.22, title, ha="center", va="center", fontsize=9, color=INK)


def _style(ax, title):
    ax.set_facecolor(CARD)
    ax.set_title(title, color=INK, fontsize=10, loc="left")
    ax.tick_params(colors=INK, labelsize=8)
    for s in ax.spines.values():
        s.set_color("#33475f")
    ax.grid(color="#2a3b52", lw=0.5)
    ax.xaxis.label.set_color(INK)
    ax.yaxis.label.set_color(INK)


def _page(title):
    fig = plt.figure(figsize=(16, 9), facecolor=BG)
    fig.suptitle(title, color=INK, fontsize=16, x=0.02, ha="left", weight="bold")
    fig.text(0.98, 0.955, "UNSW-NB15 Threat Analytics | preview of intended Power BI layout",
             color="#8aa0b8", ha="right", fontsize=9)
    return fig


def _kv(kpis, key_start):
    row = kpis[kpis["kpi"].str.startswith(key_start)].iloc[0]
    return row["value"]


def build_previews(d):
    k, risk, abt = d["kpis"], d["risk"], d["abt"]
    sev_color = abt.set_index("attack_cat")["severity_weight"]

    # Page 1 - Security Overview
    fig = _page("1 · Security Overview")
    gs = GridSpec(3, 6, figure=fig, hspace=0.45, wspace=0.35, top=0.9)
    _card(fig, gs[0, 0], "Total flows", f"{int(float(_kv(k, 'Total flows'))):,}")
    _card(fig, gs[0, 1], "Attack rate", f"{float(_kv(k, 'Attack rate')):.1f}%", "#ef5350")
    _card(fig, gs[0, 2], "Critical flows (test)", f"{int(float(_kv(k, 'Critical-risk'))):,}", RISK_COLORS["Critical"])
    _card(fig, gs[0, 3], "Detection rate", f"{float(_kv(k, 'Detection rate')):.1f}%", "#66bb6a")
    _card(fig, gs[0, 4], "False positive rate", f"{float(_kv(k, 'False positive rate')):.1f}%", "#ffa726")
    _card(fig, gs[0, 5], "Top attack type", str(_kv(k, "Top attack type")), "#ef5350")
    ax = fig.add_subplot(gs[1:, 0:2])
    tr = risk["traffic"].value_counts()
    ax.pie(tr, labels=tr.index, colors=["#c62828" if i == "Attack" else "#2e7d32" for i in tr.index],
           autopct="%1.1f%%", textprops={"color": INK}, wedgeprops={"width": 0.45})
    ax.set_title("Normal vs attack (test split)", color=INK, fontsize=10, loc="left")
    ax = fig.add_subplot(gs[1:, 2:4])
    a = abt[abt["attack_cat"] != "Normal"].sort_values("flows")
    ax.barh(a["attack_cat"], a["flows"], color=plt.cm.Reds(0.35 + 0.65 * a["severity_weight"]))
    _style(ax, "Attack flows by type (colour = severity)")
    ax = fig.add_subplot(gs[1:, 4:6])
    bd = d["bd"].set_index("risk_bucket").loc[RISK_ORDER]
    ax.bar(bd.index, bd["flows"], color=[RISK_COLORS[b] for b in bd.index])
    _style(ax, "Flows by risk bucket")
    fig.savefig(PREVIEW_DIR / "page1_security_overview.png", dpi=110, facecolor=BG)
    plt.close(fig)

    # Page 2 - Threat Analysis
    fig = _page("2 · Threat Analysis")
    gs = GridSpec(2, 3, figure=fig, hspace=0.35, wspace=0.3, top=0.9)
    ax = fig.add_subplot(gs[0, 0:2])
    psm = pd.read_csv(EXPORT_DIR / "protocol_service_matrix.csv")
    mat = psm.pivot_table(index="service", columns="attack_cat", values="flows", aggfunc="sum").fillna(0)
    mat = mat.div(mat.sum(axis=1), axis=0)
    ax.imshow(mat.to_numpy(), cmap="Reds", aspect="auto")
    ax.set_xticks(range(mat.shape[1]), mat.columns, rotation=30, ha="right")
    ax.set_yticks(range(mat.shape[0]), mat.index)
    _style(ax, "Service x attack category (row %)")
    ax.grid(False)
    ax = fig.add_subplot(gs[0, 2])
    st = d["st"].groupby("state")["flows"].sum().sort_values().tail(6)
    ax.barh(st.index, st.values, color="#ef6c00")
    _style(ax, "Flows by connection state")
    ax = fig.add_subplot(gs[1, 0:2])
    db = d["dbin"].assign(is_attack=lambda x: x["attack_cat"] != "Normal")
    piv = db.pivot_table(index="dur_bin_order", columns="is_attack", values="flows", aggfunc="sum").fillna(0)
    lab = db.drop_duplicates("dur_bin_order").set_index("dur_bin_order")["dur_bin"].sort_index()
    ax.bar(lab.astype(str), piv[False], color="#2e7d32", label="Normal")
    ax.bar(lab.astype(str), piv[True], bottom=piv[False], color="#c62828", label="Attack")
    ax.legend(facecolor=CARD, labelcolor=INK, fontsize=8)
    _style(ax, "Flows by duration bin (time-trend substitute)")
    ax = fig.add_subplot(gs[1, 2])
    ax.scatter(np.log10(abt["avg_sbytes"] + 1), np.log10(abt["avg_rate"] + 1),
               s=np.sqrt(abt["flows"]) * 2, c=[plt.cm.Reds(0.3 + 0.7 * sev_color[c]) for c in abt["attack_cat"]])
    for _, r in abt.iterrows():
        ax.annotate(r["attack_cat"], (np.log10(r["avg_sbytes"] + 1), np.log10(r["avg_rate"] + 1)),
                    color=INK, fontsize=7)
    ax.set_xlabel("log10 avg sbytes"), ax.set_ylabel("log10 avg rate")
    _style(ax, "Traffic profile per class")
    fig.savefig(PREVIEW_DIR / "page2_threat_analysis.png", dpi=110, facecolor=BG)
    plt.close(fig)

    # Page 3 - Suspicious segments & network patterns
    fig = _page("3 · Suspicious Segments & Network Patterns (IP-level substitute)")
    gs = GridSpec(2, 2, figure=fig, hspace=0.35, wspace=0.25, top=0.9)
    ax = fig.add_subplot(gs[:, 0])
    seg = d["seg"].head(15)[::-1]  # already ranked by critical flows
    ax.barh(seg["segment"], seg["critical_flows"], color=[RISK_COLORS[b] for b in seg["segment_risk_bucket"]])
    ax.set_xscale("log")
    _style(ax, "Top 15 segments by Critical flows (colour = segment risk bucket)")
    ax = fig.add_subplot(gs[0, 1])
    fl = risk.groupby("traffic")[["flag_high_pkt_rate", "flag_rare_proto", "flag_burst_context"]].mean() * 100
    fl.T.plot.bar(ax=ax, color={"Attack": "#c62828", "Normal": "#2e7d32"}, rot=0)
    ax.legend(facecolor=CARD, labelcolor=INK, fontsize=8)
    _style(ax, "Rule flag hit rate % by true traffic type")
    ax = fig.add_subplot(gs[1, 1])
    ax.hist([risk.loc[risk.traffic == "Normal", "risk_score"], risk.loc[risk.traffic == "Attack", "risk_score"]],
            bins=40, stacked=True, color=["#2e7d32", "#c62828"], label=["Normal", "Attack"])
    ax.legend(facecolor=CARD, labelcolor=INK, fontsize=8)
    _style(ax, "Risk score distribution")
    fig.savefig(PREVIEW_DIR / "page3_suspicious_segments.png", dpi=110, facecolor=BG)
    plt.close(fig)

    # Page 4 - Anomaly & model performance
    fig = _page("4 · Anomaly & Model Performance")
    gs = GridSpec(2, 2, figure=fig, hspace=0.4, wspace=0.25, top=0.9)
    mm = d["mm"]
    for i, (metric, ttl) in enumerate([("recall_attack", "Recall (attack)"), ("fpr", "False positive rate"),
                                       ("pr_auc", "PR-AUC")][:2]):
        ax = fig.add_subplot(gs[0, i])
        ax.bar(mm["model"], mm[metric], color=["#1565c0" if f.startswith("Super") else "#8e24aa" for f in mm["family"]])
        plt.setp(ax.get_xticklabels(), rotation=25, ha="right")
        _style(ax, f"{ttl} - blue supervised, purple anomaly")
    ax = fig.add_subplot(gs[1, 0])
    ax.bar(mm["model"], mm["pr_auc"], color=["#1565c0" if f.startswith("Super") else "#8e24aa" for f in mm["family"]])
    plt.setp(ax.get_xticklabels(), rotation=25, ha="right")
    _style(ax, "PR-AUC")
    ax = fig.add_subplot(gs[1, 1])
    fi = pd.read_csv(EXPORT_DIR / "feature_importance.csv").head(12)[::-1]
    ax.barh(fi["feature"], fi["mean_abs_shap"], color="#4fc3f7")
    _style(ax, "Top features (mean |SHAP|, LightGBM)")
    fig.savefig(PREVIEW_DIR / "page4_model_performance.png", dpi=110, facecolor=BG)
    plt.close(fig)

    # Page 5 - Risk & recommendations
    fig = _page("5 · Risk & Recommendations")
    gs = GridSpec(2, 3, figure=fig, hspace=0.4, wspace=0.3, top=0.9)
    ax = fig.add_subplot(gs[0, 0])
    bd = d["bd"].set_index("risk_bucket").loc[RISK_ORDER]
    ax.pie(bd["flows"], labels=bd.index, colors=[RISK_COLORS[b] for b in bd.index], autopct="%1.0f%%",
           textprops={"color": INK}, wedgeprops={"width": 0.45})
    ax.set_title("Risk bucket share", color=INK, fontsize=10, loc="left")
    ax = fig.add_subplot(gs[0, 1:])
    crit = risk[risk["risk_bucket"] == "Critical"]["pred_attack_cat"].value_counts().head(8)[::-1]
    ax.barh(crit.index, crit.values, color=RISK_COLORS["Critical"])
    _style(ax, "Critical flows by predicted attack type")
    ax = fig.add_subplot(gs[1, :])
    ax.axis("off")
    ax.set_facecolor(CARD)
    ax.text(0.01, 0.95, "Recommendations table (from reports/insights_report.md): Finding -> Evidence -> Action -> Priority",
            color=INK, fontsize=11, va="top", weight="bold")
    recs = build_recommendations()
    rows = [(r.priority, r.finding, r.recommended_action) for r in recs.itertuples()][:6]
    for i, (p, f, a) in enumerate(rows):
        y = 0.80 - i * 0.14
        ax.text(0.01, y, p, color=RISK_COLORS.get(p, INK), fontsize=9, weight="bold", va="top")
        ax.text(0.09, y, textwrap.fill(f, 60), color=INK, fontsize=8.5, va="top")
        ax.text(0.50, y, textwrap.fill(a, 95), color="#8aa0b8", fontsize=8, va="top")
    fig.savefig(PREVIEW_DIR / "page5_risk_recommendations.png", dpi=110, facecolor=BG)
    plt.close(fig)
    print(f"   previews saved to {PREVIEW_DIR}")


def run():
    banner("PHASE 10 - POWER BI PREPARATION")
    d = build_exports()
    build_previews(d)
    return d


if __name__ == "__main__":
    run()
