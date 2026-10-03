-- =====================================================================
-- Dashboard views. Sections are separated by "-- @stage:" markers:
--   base -> created in Phase 4 (only needs network_flows / dim tables)
--   risk -> created in Phase 8 after flow_risk / segment_risk are loaded
-- =====================================================================

-- @stage: base
DROP VIEW IF EXISTS v_kpi_overview;
CREATE VIEW v_kpi_overview AS
SELECT COUNT(*)                                   AS total_flows,
       SUM(label)                                 AS attack_flows,
       ROUND(100.0 * AVG(label), 2)               AS attack_rate_pct,
       COUNT(DISTINCT CASE WHEN label = 1 THEN attack_cat END) AS attack_types,
       COUNT(DISTINCT proto)                      AS protocols,
       COUNT(DISTINCT service)                    AS services
FROM network_flows;

DROP VIEW IF EXISTS v_attack_by_type;
CREATE VIEW v_attack_by_type AS
SELECT f.attack_cat, d.severity_level, d.severity_weight, d.description,
       COUNT(*) AS flows,
       ROUND(AVG(f.sbytes), 1) AS avg_sbytes,
       ROUND(AVG(f.dur), 4)    AS avg_dur,
       ROUND(AVG(f.spkts), 1)  AS avg_spkts
FROM network_flows f
JOIN dim_attack_type d ON d.attack_cat = f.attack_cat
GROUP BY f.attack_cat, d.severity_level, d.severity_weight, d.description;

DROP VIEW IF EXISTS v_protocol_service_matrix;
CREATE VIEW v_protocol_service_matrix AS
SELECT proto, service, attack_cat, COUNT(*) AS flows, SUM(label) AS attack_flows
FROM network_flows
GROUP BY proto, service, attack_cat;

DROP VIEW IF EXISTS v_attack_by_state;
CREATE VIEW v_attack_by_state AS
SELECT state, attack_cat, COUNT(*) AS flows
FROM network_flows
GROUP BY state, attack_cat;

DROP VIEW IF EXISTS v_attack_by_duration_bin;
CREATE VIEW v_attack_by_duration_bin AS
SELECT CASE
         WHEN dur = 0      THEN '0: 0s'
         WHEN dur < 0.001  THEN '1: <1ms'
         WHEN dur < 0.01   THEN '2: 1-10ms'
         WHEN dur < 0.1    THEN '3: 10-100ms'
         WHEN dur < 1      THEN '4: 0.1-1s'
         WHEN dur < 10     THEN '5: 1-10s'
         ELSE                   '6: >=10s'
       END AS dur_bin,
       attack_cat, COUNT(*) AS flows, SUM(label) AS attack_flows
FROM network_flows
GROUP BY 1, attack_cat;

-- @stage: risk
DROP VIEW IF EXISTS v_risk_bucket_distribution;
CREATE VIEW v_risk_bucket_distribution AS
SELECT risk_bucket,
       COUNT(*) AS flows,
       SUM(label) AS true_attacks,
       ROUND(AVG(risk_score), 2) AS avg_risk,
       ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS pct_flows
FROM flow_risk
GROUP BY risk_bucket;

DROP VIEW IF EXISTS v_top_risky_segments;
CREATE VIEW v_top_risky_segments AS
SELECT * FROM segment_risk ORDER BY max_risk DESC, mean_risk DESC LIMIT 50;

DROP VIEW IF EXISTS v_critical_flows;
CREATE VIEW v_critical_flows AS
SELECT r.flow_id, r.risk_score, r.risk_bucket, r.pred_attack_cat, r.attack_cat,
       f.proto, f.service, f.state, f.sbytes, f.dbytes, f.rate, f.dur
FROM flow_risk r
JOIN network_flows f ON f.flow_id = r.flow_id
WHERE r.risk_bucket = 'Critical';
