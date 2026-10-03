"""Phase 2: exploratory data analysis on the RAW data (before cleaning)."""
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from load_data import detect_version, inspect_files, load_raw, memory_mb
from utils import PALETTE, banner, save_fig, save_json

LOG_COLS = ["dur", "sbytes", "dbytes", "spkts", "dpkts"]


def profile(df):
    feat_cols = [c for c in df.columns if c not in ("id", "split")]
    dup_within = int(df.duplicated(subset=feat_cols + ["split"]).sum())
    return {
        "shape": list(df.shape),
        "memory_mb": memory_mb(df),
        "dtypes": df.dtypes.astype(str).value_counts().to_dict(),
        "null_total": int(df.isna().sum().sum()),
        "nulls_by_col": {k: int(v) for k, v in df.isna().sum().items() if v > 0},
        "duplicate_rows_within_split": dup_within,
        "rows_by_split": df["split"].value_counts().to_dict(),
    }


def run():
    banner("PHASE 2 - EDA")
    version, _ = detect_version()
    print("Dataset version:", version, "(no srcip/dstip/ports/Stime/Ltime in this release)")
    print(inspect_files().to_string(index=False))
    df = load_raw()
    prof = profile(df)
    print(f"Shape {prof['shape']}, memory {prof['memory_mb']} MB, nulls {prof['null_total']}, "
          f"duplicates (within split, excl. id) {prof['duplicate_rows_within_split']:,}")

    df["traffic"] = np.where(df["label"] == 1, "Attack", "Normal")
    ratio = df["traffic"].value_counts()
    ratio_by_split = pd.crosstab(df["split"], df["traffic"], normalize="index").round(4)
    cats = df["attack_cat"].fillna("Normal").value_counts()
    prof.update({
        "traffic_counts": ratio.to_dict(),
        "attack_share_overall": round(float(df["label"].mean()), 4),
        "attack_share_by_split": ratio_by_split["Attack"].to_dict(),
        "attack_cat_counts": cats.to_dict(),
        "n_proto": int(df["proto"].nunique()),
        "n_service": int(df["service"].nunique()),
        "n_state": int(df["state"].nunique()),
        "top_proto": df["proto"].value_counts().head(10).to_dict(),
        "service_counts": df["service"].value_counts().to_dict(),
        "state_counts": df["state"].value_counts().to_dict(),
        "numeric_summary": df[LOG_COLS].describe().round(3).to_dict(),
    })
    save_json(prof, "eda_profile")

    # ---- Figure 1: normal vs attack
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    ratio.plot.bar(ax=axes[0], color=[PALETTE[i] for i in ratio.index])
    axes[0].set_title("Normal vs attack flows (train + test)")
    axes[0].set_ylabel("flows")
    for i, v in enumerate(ratio.values):
        axes[0].text(i, v, f"{v:,}\n({v / ratio.sum():.1%})", ha="center", va="bottom")
    ratio_by_split.plot.bar(stacked=True, ax=axes[1], color=[PALETTE["Attack"], PALETTE["Normal"]])
    axes[1].set_title("Share by official split")
    axes[1].set_ylim(0, 1.15)
    save_fig(fig, "02_normal_vs_attack")

    # ---- Figure 2: attack categories
    fig, ax = plt.subplots(figsize=(9, 4.5))
    sns.barplot(x=cats.values, y=cats.index, ax=ax, color="#c62828")
    ax.patches[list(cats.index).index("Normal")].set_color(PALETTE["Normal"])
    ax.set_xscale("log")
    ax.set_title("Flows per attack category (log scale)")
    for i, v in enumerate(cats.values):
        ax.text(v, i, f" {v:,}", va="center", fontsize=9)
    save_fig(fig, "02_attack_categories")

    # ---- Figure 3: proto / service / state distributions split by traffic
    fig, axes = plt.subplots(1, 3, figsize=(16, 4.5))
    top_proto = df["proto"].value_counts().head(10).index
    for ax, col, keep in zip(axes, ["proto", "service", "state"],
                             [top_proto, df["service"].unique(), df["state"].unique()]):
        sub = df[df[col].isin(keep)]
        order = sub[col].value_counts().index
        sns.countplot(data=sub, y=col, hue="traffic", order=order, ax=ax, palette=PALETTE)
        ax.set_xscale("log")
        ax.set_title(f"{col} (top values)" if col == "proto" else col)
    save_fig(fig, "02_proto_service_state")

    # ---- Figure 4: log-scale distributions
    fig, axes = plt.subplots(1, 5, figsize=(20, 4))
    for ax, col in zip(axes, LOG_COLS):
        for t, colr in PALETTE.items():
            vals = np.log1p(df.loc[df["traffic"] == t, col].astype(float))
            ax.hist(vals, bins=60, alpha=0.55, color=colr, label=t, density=True)
        ax.set_title(f"log1p({col})")
    axes[0].legend()
    save_fig(fig, "02_log_distributions")

    print("Normal vs attack:", ratio.to_dict())
    print("Attack share by split:", prof["attack_share_by_split"])
    print("Attack categories:", cats.to_dict())
    print(f"proto={prof['n_proto']} distinct, service={prof['n_service']}, state={prof['n_state']}")
    return prof


if __name__ == "__main__":
    run()
