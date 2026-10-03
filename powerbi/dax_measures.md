# DAX measures – UNSW-NB15 Threat Analytics

All measures assume the tables are imported from `powerbi/exports/` with their file names as table names
(`flow_sample`, `attack_by_type`, `kpis`, `dim_attack_type`, `top_risky_segments`, `risk_bucket_distribution`,
`model_metrics`, `model_metrics_multiclass`, `per_class_report`, `protocol_service_matrix`, `attack_by_state`,
`attack_by_duration_bin`, `feature_importance`, `confusion_matrix_binary`).

> **Two grains, on purpose.**
> `attack_by_type`, `protocol_service_matrix`, `attack_by_state` and `attack_by_duration_bin` cover **all 257,673 flows** (train + test).
> `flow_sample` is the **82,332-flow test split**, the only flows with out-of-sample risk scores and predictions.
> Measures say which grain they use. Don't mix them in one visual.

Create a blank table named `_Measures` (Home → Enter data → load an empty table), then add the measures below.

## 1. Volume & attack-rate (all flows: `attack_by_type`)

```DAX
Total Flows =
SUM ( attack_by_type[flows] )

Attack Flows =
CALCULATE ( SUM ( attack_by_type[flows] ), attack_by_type[attack_cat] <> "Normal" )

Normal Flows =
CALCULATE ( SUM ( attack_by_type[flows] ), attack_by_type[attack_cat] = "Normal" )

Attack Rate =
DIVIDE ( [Attack Flows], [Total Flows] )          -- format as %

Severity Weighted Attacks =
SUMX ( attack_by_type, attack_by_type[flows] * attack_by_type[severity_weight] )

Top Attack Type =
VAR t =
    TOPN ( 1, FILTER ( attack_by_type, attack_by_type[attack_cat] <> "Normal" ), attack_by_type[flows], DESC )
RETURN
    MAXX ( t, attack_by_type[attack_cat] )

Attack Share of Type =
DIVIDE (
    SUM ( attack_by_type[flows] ),
    CALCULATE ( [Attack Flows], ALL ( attack_by_type ) )
)
```

## 2. Risk (test split: `flow_sample`)

```DAX
Scored Flows =
COUNTROWS ( flow_sample )

Critical Flows =
CALCULATE ( COUNTROWS ( flow_sample ), flow_sample[risk_bucket] = "Critical" )

High Risk Flows =
CALCULATE ( COUNTROWS ( flow_sample ), flow_sample[risk_bucket] = "High" )

Critical + High Share =
DIVIDE ( [Critical Flows] + [High Risk Flows], [Scored Flows] )

Avg Risk Score =
AVERAGE ( flow_sample[risk_score] )

Max Risk Score =
MAX ( flow_sample[risk_score] )

Critical Precision =
-- share of Critical flows that really are attacks (validates the score)
DIVIDE (
    CALCULATE ( SUM ( flow_sample[label] ), flow_sample[risk_bucket] = "Critical" ),
    [Critical Flows]
)

Rule Flag Hits =
SUMX ( flow_sample, flow_sample[flag_high_pkt_rate] + flow_sample[flag_rare_proto] + flow_sample[flag_burst_context] )

Risk Bucket Color =
-- use as conditional-formatting "Field value"
SWITCH (
    SELECTEDVALUE ( flow_sample[risk_bucket] ),
    "Critical", "#C62828",
    "High",     "#EF6C00",
    "Medium",   "#F9A825",
    "Low",      "#2E7D32",
    "#90A4AE"
)

High-Risk Segments =
CALCULATE (
    COUNTROWS ( top_risky_segments ),
    top_risky_segments[segment_risk_bucket] IN { "High", "Critical" }
)
```

## 3. Detection performance (test split: `flow_sample`)

```DAX
True Positives =
CALCULATE ( COUNTROWS ( flow_sample ), flow_sample[label] = 1, flow_sample[pred_attack] = 1 )

False Positives =
CALCULATE ( COUNTROWS ( flow_sample ), flow_sample[label] = 0, flow_sample[pred_attack] = 1 )

False Negatives =
CALCULATE ( COUNTROWS ( flow_sample ), flow_sample[label] = 1, flow_sample[pred_attack] = 0 )

True Negatives =
CALCULATE ( COUNTROWS ( flow_sample ), flow_sample[label] = 0, flow_sample[pred_attack] = 0 )

Detection Rate (Recall) =
DIVIDE ( [True Positives], [True Positives] + [False Negatives] )

False Positive Rate =
DIVIDE ( [False Positives], [False Positives] + [True Negatives] )

Precision =
DIVIDE ( [True Positives], [True Positives] + [False Positives] )

F1 Score =
DIVIDE ( 2 * [Precision] * [Detection Rate (Recall)], [Precision] + [Detection Rate (Recall)] )

Missed Attacks =
[False Negatives]

Anomaly Flag Rate =
DIVIDE ( SUM ( flow_sample[anomaly_flag] ), [Scored Flows] )
```

These measures recompute recall and FPR from `flow_sample`, so they respond to slicers such as attack type and service.
The static values in `model_metrics` should match the unfiltered measure values. That makes a useful sanity check.

## 4. Model comparison (`model_metrics`)

```DAX
Best PR-AUC =
MAX ( model_metrics[pr_auc] )

Best Model (PR-AUC) =
VAR t = TOPN ( 1, model_metrics, model_metrics[pr_auc], DESC )
RETURN MAXX ( t, model_metrics[model] )

Selected Model Recall =
SELECTEDVALUE ( model_metrics[recall_attack] )

Selected Model FPR =
SELECTEDVALUE ( model_metrics[fpr] )
```

## 5. KPI card helper (`kpis`)

The `kpis` table is long-format (`kpi`, `value`, `unit`). To show one KPI on a card:

```DAX
KPI Value =
SELECTEDVALUE ( kpis[value] )
```

Put `KPI Value` on a card and add a visual-level filter `kpis[kpi] = "<kpi name>"`.
Text KPIs marked *N/A* (peak hour, ports, IPs) show why the metric doesn't exist in this dataset version.
