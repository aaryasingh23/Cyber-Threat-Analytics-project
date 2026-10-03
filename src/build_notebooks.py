"""Generate the 7 analysis notebooks (thin wrappers around src/ with markdown explanations).

    python src/build_notebooks.py            # write notebooks/*.ipynb
    jupyter nbconvert --to notebook --execute --inplace notebooks/*.ipynb
"""
import nbformat as nbf

from config import ROOT

SETUP = """import sys, warnings
from pathlib import Path
warnings.filterwarnings('ignore')
SRC = Path.cwd().parent / 'src' if (Path.cwd().parent / 'src').exists() else Path.cwd() / 'src'
sys.path.insert(0, str(SRC))
import pandas as pd, json
from IPython.display import Image, Markdown, display
from config import FIG_DIR, METRICS_DIR, REPORTS_DIR, EXPORT_DIR
pd.set_option('display.max_columns', 60, 'display.width', 200)
def show(name, width=900):
    display(Image(filename=str(FIG_DIR / f'{name}.png'), width=width))"""

NB = {
    "01_eda": [
        ("md", "# 01 · Exploratory Data Analysis\n\n**Dataset:** UNSW-NB15 *official train/test release* "
               "(175,341 + 82,332 flows, 45 columns). This release has **no srcip/dstip, ports or timestamps**, "
               "so IP-level and time-based analysis is replaced by segment- and behaviour-based substitutes "
               "throughout the project.\n\nThis notebook calls `src/eda.py`, which loads the CSVs in chunks with "
               "downcast dtypes, profiles them and saves figures to `reports/figures/`."),
        ("code", "import eda\nprofile = eda.run()"),
        ("md", "## Data profile\nShape, memory, nulls and duplicates (duplicates = feature-identical rows ignoring `id`)."),
        ("code", "{k: profile[k] for k in ['shape','memory_mb','null_total','duplicate_rows_within_split','rows_by_split','attack_share_by_split']}"),
        ("md", "## Normal vs attack\nAttacks are the *majority* class in both splits, and the test split has a "
               "noticeably higher normal share - a distribution shift that later shows up as false positives."),
        ("code", "show('02_normal_vs_attack')"),
        ("md", "## Attack categories\nHeavily imbalanced: Generic and Exploits dominate; Worms has only a few hundred flows."),
        ("code", "show('02_attack_categories', 700)"),
        ("md", "## Protocol, service and state\n`service='-'` means no application protocol was identified."),
        ("code", "show('02_proto_service_state', 1100)"),
        ("md", "## Log-scale distributions\nBytes, packets and duration span many orders of magnitude, so models use `log1p` transforms."),
        ("code", "show('02_log_distributions', 1100)"),
    ],
    "02_cleaning": [
        ("md", "# 02 · Cleaning (Pandas)\n\nRuns `src/clean.py`. Problems are **flagged rather than dropped** so the "
               "official benchmark split stays intact. Every decision, with row counts, is written to "
               "`reports/cleaning_log.md`.\n\nSteps that the brief asked for but are impossible in this release "
               "(epoch conversion of Stime/Ltime, sport/dsport coercion, hour/day features) are logged as such."),
        ("code", "import clean\nsummary = clean.run()\nsummary"),
        ("md", "## Cleaning log"),
        ("code", "display(Markdown((REPORTS_DIR / 'cleaning_log.md').read_text(encoding='utf-8')))"),
        ("md", "## Cleaned dataset\nSaved as Parquet with categorical dtypes and derived features."),
        ("code", "from config import CLEAN_PARQUET\ndf = pd.read_parquet(CLEAN_PARQUET)\nprint(df.shape)\n"
                 "df[['dur','total_bytes','total_pkts','bytes_per_sec','pkts_per_sec','byte_ratio','is_duplicate','in_both_splits']].describe().T"),
    ],
    "03_sql_analysis": [
        ("md", "# 03 · Database & SQL analysis\n\nPostgreSQL is not installed on this machine, so the project uses "
               "**SQLite** through SQLAlchemy (`data/processed/nb15_threat.db`). `src/db.py`:\n\n"
               "1. creates the schema from `sql/schema.sql` (fact `network_flows`, `dim_attack_type` with severity "
               "weights, `segment_summary` as the IP-summary substitute),\n2. loads the cleaned data in 50k-row chunks "
               "and verifies the row count,\n3. runs the 19 queries in `sql/analysis_queries.sql` (CTEs, RANK, LAG, "
               "NTILE, rolling windows) and creates the dashboard views from `sql/views.sql`,\n4. exports each result "
               "to `powerbi/exports/sql/`."),
        ("code", "import db\nresults = db.run()"),
        ("md", "## Selected results"),
        ("code", "for q in ['q01_attack_vs_normal','q04_attack_rate_by_state','q05_attack_types_with_severity',"
                 "'q06_top_targeted_services','q07_suspicious_segments']:\n    display(Markdown(f'### {q}'))\n    display(results[q].head(12))"),
        ("md", "### Window functions: LAG over duration bins and rolling 3-bin attack rate over byte deciles\n"
               "Without timestamps, ordered behavioural bins replace the time axis."),
        ("code", "display(results['q13_duration_bins_lag'])\ndisplay(results['q14_bytes_ntile_rolling'].head(10))"),
        ("md", "### Scan-like and DoS-style behaviour from connection-context counters\nThe scan-like rule is "
               "deliberately reported even though it is weak - most flows it catches are normal."),
        ("code", "display(results['q08_scan_like_behaviour'])\ndisplay(results['q10_dos_patterns'])"),
    ],
    "04_threat_patterns": [
        ("md", "# 04 · Threat pattern analysis\n\nRuns `src/threat_patterns.py`: traffic profiles per attack type, "
               "protocol/service heatmaps, state anomalies, a duration-bin substitute for time spikes, "
               "connection-context (recon) behaviour, TTL fingerprints, chi-square and Mann-Whitney U tests with "
               "effect sizes, and a Spearman correlation heatmap."),
        ("code", "import threat_patterns\nres = threat_patterns.run()"),
        ("code", "for f in res['findings']:\n    display(Markdown(f\"### {f['figure']}\\n{f['text']}\"))\n"
                 "    if f['figure'].startswith('05_'):\n        show(f['figure'], 1000)"),
        ("md", "## Mann-Whitney U with rank-biserial effect sizes"),
        ("code", "pd.read_csv(METRICS_DIR / 'mann_whitney.csv')"),
        ("code", "res['chi_square']"),
    ],
    "05_anomaly_detection": [
        ("md", "# 05 · Anomaly detection (unsupervised)\n\n* Models are fit on **normal training traffic only**; 20% of "
               "those normals are held out to set the alert threshold (95th percentile -> ~5% target FPR).\n"
               "* Evaluation uses the full official **test split** (mixed traffic).\n"
               "* **Sampling:** LOF is fit on 20,000 normals, One-Class SVM on 10,000, autoencoder (sklearn MLP) on "
               "20,000. Isolation Forest uses all 44,800 fitting normals."),
        ("code", "import anomaly\nres = anomaly.run()"),
        ("code", "pd.DataFrame(res['comparison'])[['model','precision','recall_attack','f1','roc_auc','pr_auc','fpr','tp','fp','tn','fn']]"),
        ("code", "show('06_anomaly_roc_pr', 1000)\nshow('06_anomaly_confusion', 420)"),
        ("md", "## Which attacks look anomalous?\nVolume-style attacks (Generic, DoS) stand out; low-and-slow or "
               "payload-style attacks (Reconnaissance, Shellcode, Worms) resemble normal flows and are missed."),
        ("code", "pd.DataFrame(res['detection_by_category'])"),
    ],
    "06_supervised_ml": [
        ("md", "# 06 · Supervised ML\n\n**Split:** official train/test files - there are no timestamps for a "
               "time-based split, and the files are not shuffled together, so no shuffle leakage. Preprocessing "
               "is fit on train only.\n\n**Excluded features:** ids (row order follows class blocks), label / "
               "attack_cat, split, cleaning flags, TCP sequence numbers.\n\n**Imbalance:** `class_weight='balanced'`.\n\n"
               "Training all six models takes ~15-20 minutes, so by default this notebook **loads the results saved "
               "by the pipeline** (`python src/run_pipeline.py --only 7`). Set `RETRAIN = True` to retrain here."),
        ("code", "RETRAIN = False\nif RETRAIN:\n    import supervised\n    res = supervised.run()\nelse:\n"
                 "    res = json.loads((METRICS_DIR / 'supervised_results.json').read_text())\n"
                 "print('best binary:', res['best_binary'], '| best multiclass:', res['best_multiclass'])"),
        ("md", "## Binary: normal vs attack"),
        ("code", "pd.DataFrame(res['binary'])[['model','precision','recall_attack','f1','roc_auc','pr_auc','fpr','accuracy']]"),
        ("code", "show('07_binary_roc_pr', 1000)\nshow('07_binary_confusion', 420)"),
        ("code", "pd.DataFrame(res['binary_detection_by_category'])"),
        ("md", "## Multiclass: attack category"),
        ("code", "display(pd.DataFrame(res['multiclass']))\ndisplay(pd.DataFrame(res['per_class']))"),
        ("code", "show('07_multiclass_confusion', 800)"),
        ("md", "## Explainability\nImpurity / gain importance and SHAP (TreeExplainer on 2,000 random test flows)."),
        ("code", "show('07_importance_lgbm', 600)\nshow('07_shap_summary', 700)"),
    ],
    "07_risk_scoring": [
        ("md", "# 07 · Risk scoring & KPIs\n\n`risk = 100 x (0.40 anomaly + 0.30 model probability + 0.20 expected "
               "severity + 0.10 rule flags)`, computed on the out-of-sample test split. Severity uses the multiclass "
               "model's *predicted* class probabilities - never the true label. IP-level risk is replaced by "
               "segment-level risk (proto/service/state). See `src/risk.py` for the weight justification."),
        ("code", "import risk\nres = risk.run()"),
        ("code", "pd.DataFrame(res['bucket_distribution'])"),
        ("code", "pd.DataFrame(res['top_segments'])[['segment','flows','mean_risk','max_risk','critical_flows','segment_risk_bucket']]"),
        ("code", "pd.read_csv(METRICS_DIR / 'kpis.csv')"),
        ("md", "## Power BI previews\nGenerated by `src/powerbi.py` (`powerbi/previews/`)."),
        ("code", "import powerbi\n_ = powerbi.run()\nfrom config import PREVIEW_DIR\nfor p in sorted(PREVIEW_DIR.glob('*.png')):\n"
                 "    display(Image(filename=str(p), width=1000))"),
    ],
}


def build():
    out_dir = ROOT / "notebooks"
    out_dir.mkdir(exist_ok=True)
    for name, cells in NB.items():
        nb = nbf.v4.new_notebook()
        body = [nbf.v4.new_markdown_cell(src) if kind == "md" else nbf.v4.new_code_cell(src)
                for kind, src in cells]
        # title markdown first, then the setup cell, then the rest
        nb.cells = [body[0], nbf.v4.new_code_cell(SETUP)] + body[1:]
        nb.metadata["kernelspec"] = {"name": "python3", "display_name": "Python 3", "language": "python"}
        nbf.write(nb, out_dir / f"{name}.ipynb")
        print("wrote", name)


if __name__ == "__main__":
    build()
