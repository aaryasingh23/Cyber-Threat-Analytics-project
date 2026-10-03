# Power BI dashboard build guide – UNSW-NB15 Threat Analytics

This guide builds a 5-page report from the files in `powerbi/exports/`. PNG mock-ups of each page are in
`powerbi/previews/` (`page1_…png` to `page5_…png`). Use them as the target layout.

> **Data note:** this dataset version has no IPs, ports or timestamps. "Suspicious IPs" becomes
> **suspicious segments** (protocol / service / state), and the time trend becomes **duration bins**.
> KPIs that can't exist (peak hour, top port, unique IPs) are shown as *N/A* with the reason.

---

## 0. Import and model the data (≈10 min)

1. **Get Data → Text/CSV** and load these files from `powerbi/exports/`. Keep the file name as the table name.

   | Table | Grain | Rows |
   |---|---|---|
   | `flow_sample` | one row per **test-split flow**, with predictions and risk score (use `flow_sample.parquet` for faster loads: Get Data → Parquet) | 82,332 |
   | `attack_by_type` | one row per attack category, **all 257,673 flows** | 10 |
   | `dim_attack_type` | category → severity weight, level, description | 10 |
   | `protocol_service_matrix` | proto × service × attack_cat counts | 965 |
   | `attack_by_state` | state × attack_cat counts | 51 |
   | `attack_by_duration_bin` | duration bin × attack_cat counts | 59 |
   | `top_risky_segments` | top 50 segments ranked by Critical flows | 50 |
   | `risk_bucket_distribution` | Low/Medium/High/Critical summary | 4 |
   | `model_metrics` | supervised + anomaly binary metrics | 7 |
   | `model_metrics_multiclass`, `per_class_report` | multiclass results | 3 / 10 |
   | `feature_importance` | top 30 features (mean abs SHAP, LightGBM gain) | 30 |
   | `confusion_matrix_binary` | actual × predicted counts (best binary model) | 4 |
   | `kpis` | KPI name / value / unit (long format) | 19 |
   | `recommendations` | finding, evidence, action, priority | 8 |

   The SQL query results in `powerbi/exports/sql/` are optional extras.

2. **Power Query fixes:**
   - `flow_sample[risk_bucket]`, `pred_attack_cat`, `attack_cat`, `proto`, `service`, `state` → Text.
   - `risk_score`, `p_attack`, `anomaly_score_norm`, `exp_severity` → Decimal number.
   - `kpis[value]` → leave as **Text**, because the column mixes numbers and text.
3. **Sort orders** (Column tools → Sort by column):
   - In `flow_sample`, add a calculated column
     `Risk Order = SWITCH(flow_sample[risk_bucket],"Low",1,"Medium",2,"High",3,"Critical",4)`
     and sort `risk_bucket` by it.
   - Sort `risk_bucket_distribution[risk_bucket]` by `sort_order`.
   - Sort `attack_by_duration_bin[dur_bin]` by `dur_bin_order`.
4. **Relationships** (Model view):
   - `dim_attack_type[attack_cat]` 1 → * `flow_sample[attack_cat]` (active, single direction)
   - `dim_attack_type[attack_cat]` 1 → * `attack_by_type[attack_cat]`
   - `dim_attack_type[attack_cat]` 1 → * `protocol_service_matrix[attack_cat]`
   - `dim_attack_type[attack_cat]` 1 → * `attack_by_state[attack_cat]`
   - `dim_attack_type[attack_cat]` 1 → * `attack_by_duration_bin[attack_cat]`
   - Keep `model_metrics`, `kpis`, `recommendations`, `feature_importance`, `top_risky_segments` disconnected.
5. Create the `_Measures` table and paste the measures from **`dax_measures.md`**.

## Theme and colour scheme

| Use | Colour |
|---|---|
| Critical / attack | `#C62828` (red) |
| High | `#EF6C00` (orange) |
| Medium | `#F9A825` (yellow) |
| Low / normal | `#2E7D32` (green) |
| Neutral / model visuals | `#1565C0` (blue), anomaly models `#8E24AA` (purple) |
| Background (dark theme, optional) | `#0F1B2D` page, `#17263C` cards, `#E8EEF6` text |

Apply the risk colours everywhere `risk_bucket` appears: Format → Data colors → set each bucket, or use
conditional formatting → Field value → `[Risk Bucket Color]`. Use the same red/green for Attack/Normal on
every page.

**Global slicers** (add on each page and sync with View → Sync slicers):
`dim_attack_type[attack_cat]`, `flow_sample[service]`, `flow_sample[proto]`, `flow_sample[risk_bucket]`.
Slicers on `flow_sample` filter only test-split visuals. Mark those visuals' titles with "(test split)".

---

## Page 1 – Security Overview

| Visual | Fields | Notes |
|---|---|---|
| 6 KPI cards | `[Total Flows]`, `[Attack Rate]`, `[Critical Flows]`, `[Detection Rate (Recall)]`, `[False Positive Rate]`, `[Top Attack Type]` | Format rates as %, 1 decimal. Card colours: red for Attack Rate/Critical, green for Detection, orange for FPR |
| Donut: Normal vs attack | Legend `flow_sample[traffic]`, Values count of `flow_id` | Red/green |
| Bar: attack flows by type | Y `attack_by_type[attack_cat]` (filter ≠ Normal), X `flows` | Colour by `severity_weight` (gradient light→dark red); tooltip `description` |
| Column: flows by risk bucket | X `risk_bucket_distribution[risk_bucket]`, Y `flows` | Risk colours; tooltip `attack_precision` |
| Text box | "Dataset: UNSW-NB15 train/test release (2015, lab-generated). No IPs/timestamps." | Footer |

## Page 2 – Threat Analysis

| Visual | Fields | Notes |
|---|---|---|
| Matrix heatmap | Rows `protocol_service_matrix[service]`, Columns `attack_cat`, Values `flows` (Show value as → % of row total) | Conditional formatting → background colour, white→red |
| Bar: flows by state | Axis `attack_by_state[state]`, Values `flows`, Legend `attack_cat` | Top 6 states (Top N filter) |
| Stacked column: duration bins | Axis `attack_by_duration_bin[dur_bin]`, Values `flows`, Legend `attack_cat` (or Normal vs attack) | Title: "Duration profile (time-trend substitute)" |
| Scatter: traffic profile | X `attack_by_type[avg_sbytes]` (log axis), Y `avg_rate` (log axis), Size `flows`, Legend `attack_cat` | Shows Generic = small/fast, Exploits = heavy |
| Table | `attack_by_type`: attack_cat, severity_level, flows, avg_dur, avg_sbytes | |

## Page 3 – Suspicious Segments & Network Patterns

| Visual | Fields | Notes |
|---|---|---|
| Bar: top segments | Y `top_risky_segments[segment]`, X `critical_flows` | Top 15 filter; colour by `segment_risk_bucket` |
| Table: segment detail | segment, flows, critical_flows, mean_risk, max_risk, true_attack_flows, distinct_pred_attack_types | Conditional formatting on `mean_risk` (green→red) |
| Clustered column: rule flags | Values average of `flag_high_pkt_rate`, `flag_rare_proto`, `flag_burst_context`; Legend `flow_sample[traffic]` | Shows which rules separate attacks |
| Histogram: risk score | `flow_sample[risk_score]` binned (New group → bin size 5), Legend `traffic` | |
| Card | `[High-Risk Segments]` | |

**Drill-through:** create a hidden page **"Segment detail"** with drill-through fields `flow_sample[proto]`,
`flow_sample[service]` and `flow_sample[state]`. Add a table of `flow_sample` (flow_id, risk_score,
risk_bucket, pred_attack_cat, attack_cat, sbytes, dbytes, rate, dur) sorted by risk_score, plus
cards for `[Avg Risk Score]`, `[Critical Flows]` and `[Detection Rate (Recall)]`. Right-click any segment
bar → Drill through → Segment detail. Add a second drill-through page **"Attack type detail"** keyed on
`dim_attack_type[attack_cat]`.

## Page 4 – Anomaly & Model Performance

| Visual | Fields | Notes |
|---|---|---|
| Clustered bar: recall vs FPR | Axis `model_metrics[model]`, Values `recall_attack`, `fpr` | Legend/colour by `family` (blue supervised, purple anomaly) |
| Column: PR-AUC | Axis `model`, Values `pr_auc` | Title states the prevalence baseline (~0.55) |
| Matrix: confusion | Rows `confusion_matrix_binary[actual]`, Columns `predicted`, Values `flows` | Background colour scale |
| Table: per-class report | `per_class_report`: class, precision, recall, f1-score, support | Highlight F1 < 0.3 in red |
| Bar: top features | Y `feature_importance[feature]`, X `mean_abs_shap` | Top 12 |
| Cards | `[Detection Rate (Recall)]`, `[False Positive Rate]`, `[Precision]`, `[Anomaly Flag Rate]` | These respond to slicers, so pick an attack type to see its detection rate |

## Page 5 – Risk & Recommendations

| Visual | Fields | Notes |
|---|---|---|
| Donut: risk bucket share | `risk_bucket_distribution[risk_bucket]`, `flows` | Risk colours |
| Bar: critical flows by predicted type | Axis `flow_sample[pred_attack_cat]`, Values count, filter `risk_bucket = Critical` | |
| Card | `[Critical Precision]` | Shows how trustworthy Critical alerts are |
| Table: recommendations | `recommendations`: priority, finding, evidence, recommended_action | Conditional font colour on priority (Critical red, High orange, Medium yellow); word-wrap on |
| Table: top critical flows | `flow_sample` filtered to Critical, Top 100 by risk_score | |

---

## Finishing touches

- **Tooltips:** add `dim_attack_type[description]` and `severity_level` to every attack-type visual.
- **Bookmarks:** "All traffic" and "Critical only" (with the risk_bucket slicer set) as toggle buttons on page 1.
- **Page navigation:** add buttons (Insert → Buttons → Navigator → Page navigator).
- **Validation:** with no slicers, `[Detection Rate (Recall)]` and `[False Positive Rate]` should match the
  LightGBM row in `model_metrics` (recall_attack ≈ 0.973, fpr ≈ 0.179). `[Critical Flows]` should equal
  the Critical row in `risk_bucket_distribution`.
- Save as `powerbi/UNSW-NB15_Threat_Analytics.pbix`.
