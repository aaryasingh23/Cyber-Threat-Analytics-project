# Cybersecurity Threat Analytics & Network Intrusion Detection (UNSW-NB15)

An end-to-end, reproducible security analytics pipeline. It takes raw UNSW-NB15 network flows through
cleaning, a SQL database, threat-pattern analysis, anomaly detection, supervised ML and risk scoring, then
produces Power BI–ready data and a SOC-style insights report.

**🔴 Live dashboard: [cyber-threat-analytics-project.vercel.app](https://cyber-threat-analytics-project.vercel.app/)**

> **Dataset version used:** the official **train/test release** (175,341 + 82,332 flows, 45 columns).
> It contains **no source/destination IPs, ports or timestamps**. IP-level risk, port-scan counts and
> hourly/daily trends are therefore replaced with documented substitutes (protocol/service/state segments,
> the dataset's connection-context counters `ct_*`, and duration bins). **No data was fabricated, and no
> synthetic data is used.**

## Architecture

```mermaid
flowchart LR
    A[Raw CSVs<br/>data/raw] -->|chunked read,<br/>dtype downcast| B[EDA<br/>src/eda.py]
    A --> C[Cleaning<br/>src/clean.py]
    C -->|Parquet| D[(SQLite DB<br/>network_flows, dim_attack_type,<br/>segment_summary)]
    D --> E[19 SQL queries + views<br/>sql/]
    C --> F[Threat patterns + stats<br/>src/threat_patterns.py]
    C --> G[Anomaly detection<br/>IF / LOF / OCSVM / AE]
    C --> H[Supervised ML<br/>LR / RF / LightGBM + SHAP]
    G --> I[Risk scoring<br/>src/risk.py]
    H --> I
    I --> D
    I --> J[Power BI exports<br/>powerbi/exports]
    E --> J
    I --> K[Insights report<br/>reports/insights_report.md]
```

## Project structure

```
project 1/
├── data/
│   ├── raw/                 UNSW_NB15_training-set.csv, UNSW_NB15_testing-set.csv, NUSW-NB15_features.csv
│   └── processed/           flows_clean.parquet, anomaly_scores.parquet, model_predictions.parquet,
│                            flow_risk.parquet, nb15_threat.db (SQLite)
├── notebooks/               01_eda … 07_risk_scoring (executed, with outputs)
├── sql/                     schema.sql, analysis_queries.sql (19 queries), views.sql
├── src/
│   ├── config.py            paths, seeds, severity weights, risk weights
│   ├── load_data.py         version detection, chunked loading, downcasting
│   ├── eda.py               Phase 2
│   ├── clean.py             Phase 3 (+ reports/cleaning_log.md)
│   ├── db.py                Phase 4 (schema, chunked load, queries, views, CSV exports)
│   ├── threat_patterns.py   Phase 5
│   ├── features.py          feature selection / leakage rules / preprocessing
│   ├── models.py            shared metrics + plots
│   ├── anomaly.py           Phase 6
│   ├── supervised.py        Phase 7
│   ├── risk.py              Phase 8
│   ├── powerbi.py           Phase 10 (exports + dashboard previews)
│   ├── report.py            Phase 11 (insights report from saved metrics)
│   ├── build_notebooks.py   generates the notebooks
│   └── run_pipeline.py      one-command runner
├── powerbi/
│   ├── exports/             CSV/Parquet tables for Power BI (+ exports/sql/ query results)
│   ├── previews/            PNG mock-ups of the 5 dashboard pages
│   ├── dax_measures.md
│   └── dashboard_build_guide.md
├── reports/
│   ├── figures/             all charts
│   ├── metrics/             JSON/CSV results of every phase
│   ├── cleaning_log.md, sql_results.md, threat_patterns.md
│   └── insights_report.md   SOC-style final report
├── requirements.txt
└── README.md
```

## How to run

```bash
python -m venv .venv
```

```bash
.venv\Scripts\pip install -r requirements.txt
```

```bash
.venv\Scripts\python src/run_pipeline.py
```

The full run takes about 10 minutes on a laptop (most of it is the multiclass models in Phase 7). You can also run part of it:

```bash
.venv\Scripts\python src/run_pipeline.py --from 6
```

```bash
.venv\Scripts\python src/run_pipeline.py --only 8 10 11
```

Rebuild and re-execute the notebooks after the pipeline:

```bash
.venv\Scripts\python src/build_notebooks.py
```

```bash
.venv\Scripts\python -m nbconvert --to notebook --execute --inplace notebooks/01_eda.ipynb
```

(Repeat the second command for each notebook. Notebook 06 loads saved supervised results unless you set `RETRAIN = True`.)

**Database:** SQLite is used because PostgreSQL wasn't installed. To use PostgreSQL, set
`NB15_DB_URL=postgresql+psycopg2://user:pass@host:5432/db`. Note that `run_script` uses SQLite's
`executescript`, so run `sql/schema.sql` with `psql` first.

**Windows note:** on machines with *Smart App Control*, newer SciPy DLLs and the `jupyter.exe` launcher
can be blocked. That's why `scipy==1.15.3` is pinned, and why notebooks run through `python -m nbconvert`.

## Live dashboard

**Live demo:** https://cyber-threat-analytics-project.vercel.app/

The dashboard is a static page (`dashboard/index.html`) deployed on Vercel with no build step:
`vercel.json` serves the `dashboard/` folder, and `.vercelignore` keeps the Python pipeline out of the
deployment. Every push to `main` redeploys automatically. To redeploy elsewhere: open vercel.com →
**Add New → Project** → import this repo → **Deploy** (settings come from `vercel.json`).

## Web dashboard

Phase 12 (`src/web_dashboard.py`) builds an interactive, self-contained dashboard at
`dashboard/index.html`. Double-click it to open it in any browser. It has KPIs, risk buckets, a service × attack
heatmap, suspicious segments, a highest-risk flow table, model comparison, SHAP features and
recommendations, with **Service** and **True class** filters over the 82,332 risk-scored test flows.
All numbers are embedded from the pipeline outputs. Only Chart.js and Google Fonts load from the internet.

## Methodology highlights

- **No leakage.** The official train/test files are used as-is: there are no timestamps for a time split,
  and the files are never shuffled together. Scalers and encoders are fit on train only. Row ids, labels,
  `attack_cat`, cleaning flags and random TCP sequence numbers are excluded from features.
- **Anomaly models** are trained on *normal* training traffic only. Alert thresholds come from held-out
  normal flows (95th percentile), never from the test set.
- **Imbalance** is handled with `class_weight='balanced'`. Metrics focus on recall, FPR, precision and
  PR-AUC; accuracy is never reported alone.
- **Sampling is stated explicitly.** LOF uses 20k flows, One-Class SVM 10k, the autoencoder 20k, SHAP
  2,000, and the Spearman heatmap a 50k sample.
- **Risk score** = `100 × (0.40·anomaly + 0.30·P(attack) + 0.20·expected severity + 0.10·rule flags)`,
  computed out-of-sample on the 82,332 test flows. The weights are justified in `src/risk.py` and the report.

## Results (held-out test split, 82,332 flows)

**Binary detection (threshold 0.5 for supervised; 95th-percentile-of-normal for anomaly)**

| Family                 | Model              |   Precision |   Recall (attack) |    F1 |   ROC-AUC |   PR-AUC |   FPR |
|:-----------------------|:-------------------|------------:|------------------:|------:|----------:|---------:|------:|
| Supervised binary      | LightGBM           |       0.869 |             0.973 | 0.918 |     0.985 |    0.989 | 0.179 |
| Supervised binary      | RandomForest       |       0.846 |             0.979 | 0.907 |     0.984 |    0.988 | 0.219 |
| Supervised binary      | LogisticRegression |       0.839 |             0.939 | 0.886 |     0.966 |    0.974 | 0.221 |
| Anomaly (unsupervised) | IsolationForest    |       0.913 |             0.663 | 0.768 |     0.868 |    0.894 | 0.077 |
| Anomaly (unsupervised) | LocalOutlierFactor |       0.897 |             0.600 | 0.719 |     0.787 |    0.812 | 0.085 |
| Anomaly (unsupervised) | Autoencoder        |       0.638 |             0.153 | 0.247 |     0.696 |    0.666 | 0.106 |
| Anomaly (unsupervised) | OneClassSVM        |       0.718 |             0.202 | 0.315 |     0.627 |    0.631 | 0.097 |

**Multiclass (attack_cat)**

| Model              |   Macro-F1 |   Weighted-F1 |   Macro recall |   Accuracy |
|:-------------------|-----------:|--------------:|---------------:|-----------:|
| RandomForest       |      0.525 |         0.769 |          0.599 |      0.726 |
| LightGBM           |      0.517 |         0.752 |          0.614 |      0.701 |
| LogisticRegression |      0.365 |         0.689 |          0.569 |      0.624 |

**Risk buckets** (risk score ROC-AUC vs labels: 0.973)

| risk_bucket   |   flows |   pct_flows |   attack_precision |
|:--------------|--------:|------------:|-------------------:|
| Low           |   14746 |       17.91 |             0.0113 |
| Medium        |   18308 |       22.24 |             0.109  |
| High          |   12408 |       15.07 |             0.5255 |
| Critical      |   36870 |       44.78 |             0.994  |

**KPIs**

| kpi                                       | value                                     |
|:------------------------------------------|:------------------------------------------|
| Total flows (train+test)                  | 257673                                    |
| Attack flows                              | 164673                                    |
| Attack rate %                             | 63.91                                     |
| Flows risk-scored (test split)            | 82332                                     |
| Critical-risk flows                       | 36870                                     |
| High-risk flows                           | 12408                                     |
| Critical + High share %                   | 59.85                                     |
| High/Critical-risk segments               | 139                                       |
| Top attack type                           | Generic                                   |
| Top attack type flows                     | 58871                                     |
| Top targeted service                      | dns                                       |
| Top targeted service attack flows         | 58100                                     |
| Detection rate (recall) - LightGBM        | 97.29                                     |
| False positive rate - LightGBM            | 17.91                                     |
| PR-AUC - LightGBM                         | 0.9892                                    |
| Anomaly detector recall - IsolationForest | 66.31                                     |
| Peak attack hour                          | N/A - no timestamps in train/test release |
| Top targeted port                         | N/A - no ports in train/test release      |
| Unique attacking IPs / targeted hosts     | N/A - no IPs in train/test release        |

Full details: [reports/insights_report.md](reports/insights_report.md).

## Screenshots / figures

| File | Shows |
|---|---|
| `powerbi/previews/page1_security_overview.png` … `page5_risk_recommendations.png` | Intended Power BI pages |
| `reports/figures/02_*.png` | EDA: class balance, categories, protocol/service/state, log distributions |
| `reports/figures/05_*.png` | Threat patterns: boxplots, heatmaps, state, duration bins, recon context, TTL, correlations |
| `reports/figures/06_*.png` | Anomaly ROC/PR curves and confusion matrix |
| `reports/figures/07_*.png` | Supervised ROC/PR, confusion matrices, feature importance, SHAP |

## Limitations

- UNSW-NB15 is **lab-generated (2015)** and doesn't represent a modern enterprise network.
- **TTL artefacts** (`sttl`, `ct_state_ttl`) nearly encode the label. Models overfit to this dataset and
  must be re-validated on local traffic.
- The **train/test distribution shift** causes a high false-positive rate (~18%) for the supervised models.
- There are **no IPs, ports or timestamps**, so IP risk, port-scan counts and time trends are approximated.
- 93,824 duplicate flows were kept to preserve the benchmark, and 4,247 test rows also appear in train.
- Evaluation is label-based. DoS, Analysis and Backdoor have overlapping feature vectors, which limits
  multiclass performance.

## Future work

- Re-run on the full UNSW-NB15 release (with IPs and timestamps) for true per-host risk, distinct-port scan
  detection and hourly trends.
- Validate on other datasets (CIC-IDS2017/2018, a local Zeek/NetFlow capture) and test a model without TTL features.
- Tune thresholds on recent local traffic and add probability calibration.
- Stream scoring (Kafka + model service) and automated Power BI refresh.
- Add a PyTorch autoencoder and sequence models once timestamps are available.
