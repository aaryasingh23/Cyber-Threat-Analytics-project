"""Phase 5: threat pattern analysis + statistical tests, with plain-English findings."""
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from scipy import stats

from config import CLEAN_PARQUET, REPORTS_DIR, SEED
from utils import PALETTE, banner, save_fig, save_json

CAT_ORDER = ["Normal", "Generic", "Exploits", "Fuzzers", "DoS", "Reconnaissance",
             "Analysis", "Backdoor", "Shellcode", "Worms"]


def cramers_v(table):
    chi2, p, dof, _ = stats.chi2_contingency(table)
    n = table.to_numpy().sum()
    r, k = table.shape
    return chi2, p, dof, float(np.sqrt(chi2 / (n * (min(r, k) - 1))))


def mann_whitney(df, col):
    a = df.loc[df["label"] == 1, col].astype(float)
    n = df.loc[df["label"] == 0, col].astype(float)
    u, p = stats.mannwhitneyu(a, n, alternative="two-sided")
    # Rank-biserial correlation: P(attack > normal) - P(attack < normal)
    rbc = 2 * u / (len(a) * len(n)) - 1
    return {"feature": col, "median_attack": float(a.median()), "median_normal": float(n.median()),
            "U": float(u), "p_value": float(p), "rank_biserial": round(float(rbc), 4),
            "effect": ("large" if abs(rbc) >= 0.5 else "medium" if abs(rbc) >= 0.3
                       else "small" if abs(rbc) >= 0.1 else "negligible")}


def run():
    banner("PHASE 5 - THREAT PATTERN ANALYSIS")
    df = pd.read_parquet(CLEAN_PARQUET)
    df["attack_cat"] = pd.Categorical(df["attack_cat"].astype(str), categories=CAT_ORDER)
    findings = []

    # ---- 1. Traffic profile per attack type (boxplots, log scale)
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    for ax, col in zip(axes, ["dur", "sbytes", "spkts"]):
        tmp = df[["attack_cat", col]].copy()
        tmp[col] = np.log10(tmp[col].astype(float) + 1)
        sns.boxplot(data=tmp, x=col, y="attack_cat", ax=ax, showfliers=False, color="#90a4ae")
        ax.set_xlabel(f"log10({col}+1)")
        ax.set_ylabel("")
        ax.set_title(f"{col} by attack category")
    save_fig(fig, "05_profile_boxplots")
    prof = df.groupby("attack_cat", observed=True)[["dur", "sbytes", "dbytes", "spkts", "rate"]].median()
    prof.to_csv(REPORTS_DIR / "metrics" / "attack_profile_medians.csv")
    gen = prof.loc["Generic"]
    findings.append(("05_profile_boxplots",
        f"Generic attacks are tiny and fast: median sbytes {gen.sbytes:.0f} B and median duration "
        f"{gen.dur:.6f}s vs {prof.loc['Normal','sbytes']:.0f} B / {prof.loc['Normal','dur']:.3f}s for normal flows. "
        f"Exploits carry the heaviest payloads among attacks (median sbytes {prof.loc['Exploits','sbytes']:.0f} B). "
        "Volume alone does not separate attacks: several attack classes overlap heavily with normal traffic."))

    # ---- 2. Protocol / service x attack_cat heatmaps (row-normalised)
    top_proto = df["proto"].value_counts().head(8).index
    df["proto_grp"] = np.where(df["proto"].isin(top_proto), df["proto"].astype(str), "other")
    fig, axes = plt.subplots(1, 2, figsize=(20, 6))
    for ax, col in zip(axes, ["proto_grp", "service"]):
        ct = pd.crosstab(df[col], df["attack_cat"], normalize="index") * 100
        sns.heatmap(ct, annot=True, fmt=".0f", cmap="Reds", ax=ax, cbar_kws={"label": "% of row"})
        ax.set_title(f"{col.replace('_grp', '')} x attack category (% of flows in row)")
        ax.set_xlabel("")
    save_fig(fig, "05_proto_service_heatmap")
    unas = df.loc[df["proto"] == "unas", "attack_cat"].value_counts(normalize=True).head(3)
    findings.append(("05_proto_service_heatmap",
        f"DNS is dominated by Generic attacks ({(df.loc[df.service=='dns','attack_cat']=='Generic').mean():.1%} of DNS flows). "
        f"The 'unas' protocol is 100% malicious ({(df.proto=='unas').sum():,} flows, mostly "
        f"{', '.join(f'{k} {v:.0%}' for k, v in unas.items())}). 'other' (rare) protocols are almost "
        f"entirely attacks ({df.loc[df.proto_grp=='other','label'].mean():.1%}), while ARP is entirely normal."))

    # ---- 3. State anomalies
    st = df.groupby("state", observed=True).agg(flows=("label", "size"), attack_rate=("label", "mean"))
    st = st[st.flows >= 50].sort_values("flows", ascending=False)
    fig, ax = plt.subplots(figsize=(8, 4))
    sns.barplot(x=st.index, y=st.attack_rate * 100, ax=ax, color="#c62828")
    for i, (f, r) in enumerate(zip(st.flows, st.attack_rate)):
        ax.text(i, r * 100 + 1, f"{r:.0%}\n(n={f:,})", ha="center", fontsize=9)
    ax.set_ylabel("attack rate %")
    ax.set_ylim(0, 115)
    ax.set_title("Attack rate by connection state (states with >= 50 flows)")
    save_fig(fig, "05_state_attack_rate")
    findings.append(("05_state_attack_rate",
        f"INT (interrupted/no-reply) connections have a {st.loc['INT','attack_rate']:.1%} attack rate "
        f"across {st.loc['INT','flows']:,} flows, versus {st.loc['CON','attack_rate']:.1%} for CON (established, "
        "two-way) flows. Half-open / unanswered connections are the strongest single state signal."))

    # ---- 4. Time spikes -> not possible; substitute: duration bins
    bins = [-1, 0, 0.001, 0.01, 0.1, 1, 10, np.inf]
    labels = ["0s", "<1ms", "1-10ms", "10-100ms", "0.1-1s", "1-10s", ">=10s"]
    df["dur_bin"] = pd.cut(df["dur"], bins=bins, labels=labels)
    db = df.groupby("dur_bin", observed=True).agg(flows=("label", "size"), attack_rate=("label", "mean"))
    fig, ax1 = plt.subplots(figsize=(9, 4))
    ax1.bar(db.index.astype(str), db.flows, color="#b0bec5")
    ax1.set_ylabel("flows")
    ax2 = ax1.twinx()
    ax2.plot(db.index.astype(str), db.attack_rate * 100, color="#c62828", marker="o")
    ax2.set_ylabel("attack rate %", color="#c62828")
    ax2.grid(False)
    ax1.set_title("Flows and attack rate by duration bin (substitute for time trend - no timestamps)")
    save_fig(fig, "05_duration_bins")
    findings.append(("05_duration_bins",
        "No timestamps exist in this release, so hourly/daily spikes cannot be measured. As a substitute, "
        f"sub-millisecond flows ({db.loc['<1ms','flows']:,}) are {db.loc['<1ms','attack_rate']:.1%} attacks, "
        f"while 1-100 ms flows are almost all normal ({db.loc['1-10ms','attack_rate']:.1%} and "
        f"{db.loc['10-100ms','attack_rate']:.1%}) - a burst-like, automated signature."))

    # ---- 5. Recon behaviour (connection-context counters)
    ctx = ["ct_src_ltm", "ct_dst_ltm", "ct_dst_src_ltm", "ct_src_dport_ltm", "ct_srv_src", "ct_srv_dst"]
    rec = df.groupby("attack_cat", observed=True)[ctx].mean()
    fig, ax = plt.subplots(figsize=(11, 4.5))
    rec.loc[["Normal", "Reconnaissance", "Generic", "DoS", "Exploits"]].T.plot.bar(ax=ax)
    ax.set_title("Connection-context counters (mean, last 100 connections)")
    ax.set_ylabel("mean count")
    plt.setp(ax.get_xticklabels(), rotation=20)
    save_fig(fig, "05_recon_context")
    findings.append(("05_recon_context",
        f"Generic attacks are highly repetitive: mean ct_dst_src_ltm {rec.loc['Generic','ct_dst_src_ltm']:.1f} vs "
        f"{rec.loc['Normal','ct_dst_src_ltm']:.1f} for normal (same host pair hammered repeatedly). "
        f"Reconnaissance flows, by contrast, show LOW repetition ({rec.loc['Reconnaissance','ct_dst_src_ltm']:.1f}) - "
        "consistent with probes spread across many targets. Without IPs/ports, true distinct-port scan counts "
        "cannot be computed."))

    # ---- 6. TTL fingerprint
    ttl = df.groupby(["sttl", "dttl"]).agg(flows=("label", "size"), attack_rate=("label", "mean"))
    ttl = ttl[ttl.flows >= 1000].sort_values("flows", ascending=False)
    fig, ax = plt.subplots(figsize=(8, 4))
    lbl = [f"{a}/{b}" for a, b in ttl.index]
    sns.barplot(x=lbl, y=ttl.attack_rate * 100, ax=ax, color="#ef6c00")
    for i, f in enumerate(ttl.flows):
        ax.text(i, ttl.attack_rate.iloc[i] * 100 + 1, f"n={f:,}", ha="center", fontsize=9)
    ax.set_xlabel("sttl/dttl")
    ax.set_ylabel("attack rate %")
    ax.set_title("TTL fingerprints (pairs with >= 1,000 flows)")
    save_fig(fig, "05_ttl_fingerprint")
    findings.append(("05_ttl_fingerprint",
        f"sttl/dttl = 254/0 covers {ttl.loc[(254,0),'flows']:,} flows with a {ttl.loc[(254,0),'attack_rate']:.1%} attack "
        f"rate, while 31/29 ({ttl.loc[(31,29),'flows']:,} flows) is {ttl.loc[(31,29),'attack_rate']:.0%} attacks. "
        "These TTLs reflect the lab's attack-generator topology, so models will exploit them - a known "
        "UNSW-NB15 artefact that will not transfer to other networks."))

    # ---- 7. Statistical tests
    ct = pd.crosstab(df["attack_cat"], df["proto_grp"])
    chi2, p, dof, v = cramers_v(ct)
    ct_s = pd.crosstab(df["attack_cat"], df["service"])
    chi2_s, p_s, dof_s, v_s = cramers_v(ct_s)
    chi = {"attack_cat_vs_proto": {"chi2": chi2, "p_value": p, "dof": dof, "cramers_v": v},
           "attack_cat_vs_service": {"chi2": chi2_s, "p_value": p_s, "dof": dof_s, "cramers_v": v_s}}
    mw = pd.DataFrame([mann_whitney(df, c) for c in
                       ["sbytes", "dbytes", "dur", "spkts", "dpkts", "rate", "sttl", "smean"]])
    mw.to_csv(REPORTS_DIR / "metrics" / "mann_whitney.csv", index=False)
    print(mw[["feature", "median_attack", "median_normal", "rank_biserial", "effect"]].to_string(index=False))
    print(f"Chi-square attack_cat x proto: chi2={chi2:,.0f}, dof={dof}, p={p:.2e}, Cramer's V={v:.3f}")
    print(f"Chi-square attack_cat x service: chi2={chi2_s:,.0f}, dof={dof_s}, p={p_s:.2e}, Cramer's V={v_s:.3f}")

    # ---- 8. Correlation heatmap (Spearman on a 50k sample - stated)
    num = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl", "sload", "dload",
           "sinpkt", "smean", "dmean", "tcprtt", "ct_srv_src", "ct_state_ttl", "ct_dst_src_ltm",
           "ct_src_dport_ltm", "ct_srv_dst", "label"]
    sample = df[num].sample(50_000, random_state=SEED)
    corr = sample.corr(method="spearman")
    fig, ax = plt.subplots(figsize=(13, 11))
    sns.heatmap(corr, cmap="RdBu_r", center=0, annot=True, fmt=".1f", annot_kws={"size": 7}, ax=ax)
    ax.set_title("Spearman correlation (random 50,000-flow sample)")
    save_fig(fig, "05_correlation_heatmap")
    top_corr = corr["label"].drop("label").abs().sort_values(ascending=False).head(5)
    findings.append(("05_correlation_heatmap",
        "Strongest monotonic correlates of the attack label: " +
        ", ".join(f"{k} ({corr.loc[k,'label']:+.2f})" for k in top_corr.index) +
        ". Byte/packet counters are strongly inter-correlated (redundant), which matters for linear models."))

    sb = mw.set_index("feature")
    findings.append(("statistical_tests",
        f"Chi-square shows attack type depends strongly on protocol (chi2={chi2:,.0f}, dof={dof}, p~0 (below float precision), "
        f"Cramer's V={v:.2f}) and service (Cramer's V={v_s:.2f}). Mann-Whitney U: attack flows send fewer "
        f"bytes than normal flows (median sbytes {sb.loc['sbytes','median_attack']:.0f} vs "
        f"{sb.loc['sbytes','median_normal']:.0f}, rank-biserial {sb.loc['sbytes','rank_biserial']:+.2f}) and receive far "
        f"fewer (dbytes r={sb.loc['dbytes','rank_biserial']:+.2f}, {sb.loc['dbytes','effect']}). With n=257,673 every p-value "
        "is ~0, so effect sizes - not p-values - indicate practical importance."))

    md = ["# Threat pattern analysis - findings", "",
          "Generated by `src/threat_patterns.py`. Figures in `reports/figures/`.", ""]
    for fig_name, text_ in findings:
        ref = f"![{fig_name}](figures/{fig_name}.png)\n\n" if fig_name.startswith("05_") else ""
        md += [f"## {fig_name}", "", ref + text_, ""]
    md += ["## Mann-Whitney U (attack vs normal)", "",
           mw.drop(columns=["U"]).to_markdown(index=False, floatfmt=".4g"), ""]
    (REPORTS_DIR / "threat_patterns.md").write_text("\n".join(md), encoding="utf-8")

    out = {"chi_square": chi, "mann_whitney": mw.to_dict(orient="records"),
           "state": st.reset_index().to_dict(orient="records"),
           "duration_bins": db.reset_index().astype({"dur_bin": str}).to_dict(orient="records"),
           "ttl": ttl.reset_index().to_dict(orient="records"),
           "top_label_correlates": {k: float(corr.loc[k, "label"]) for k in top_corr.index},
           "findings": [{"figure": f, "text": t} for f, t in findings]}
    save_json(out, "threat_patterns")
    for f, t in findings:
        print(f"* {f}: {t}\n")
    return out


if __name__ == "__main__":
    run()
