-- =====================================================================
-- UNSW-NB15 Threat Analytics - analysis queries (SQLite 3.25+ / PostgreSQL)
-- Each query starts with "-- name:" and "-- desc:" lines. src/db.py parses
-- this file, runs every query and writes the result to
-- powerbi/exports/sql/<name>.csv.
--
-- Data note: this release has no IPs, ports or timestamps, so
--   * "top suspicious source IPs"   -> top suspicious traffic SEGMENTS
--   * "port-scan detection"         -> scan-like behaviour from the
--                                       connection-context counters
--                                       (ct_dst_src_ltm, ct_src_dport_ltm)
--   * "DoS: many flows to one dstip" -> ct_dst_ltm / ct_srv_dst counters
--   * hourly/daily trends, LAG and rolling counts are computed over
--     ordered behavioural bins (duration, bytes) instead of time.
-- The ct_* counters are pre-computed by the dataset authors over the last
-- 100 connections, so they still capture per-host behaviour.
-- =====================================================================

-- name: q01_attack_vs_normal
-- desc: Overall attack vs normal share (all flows)
SELECT CASE label WHEN 1 THEN 'Attack' ELSE 'Normal' END AS traffic,
       COUNT(*) AS flows,
       ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS pct
FROM network_flows
GROUP BY label
ORDER BY flows DESC;

-- name: q02_attack_rate_by_protocol
-- desc: Attack rate per protocol (protocols with >= 100 flows)
SELECT proto,
       COUNT(*) AS flows,
       SUM(label) AS attack_flows,
       ROUND(100.0 * AVG(label), 2) AS attack_rate_pct
FROM network_flows
GROUP BY proto
HAVING COUNT(*) >= 100
ORDER BY flows DESC
LIMIT 20;

-- name: q03_attack_rate_by_service
-- desc: Attack rate per application service
SELECT service,
       COUNT(*) AS flows,
       SUM(label) AS attack_flows,
       ROUND(100.0 * AVG(label), 2) AS attack_rate_pct
FROM network_flows
GROUP BY service
ORDER BY flows DESC;

-- name: q04_attack_rate_by_state
-- desc: Attack rate per connection state
SELECT state,
       COUNT(*) AS flows,
       SUM(label) AS attack_flows,
       ROUND(100.0 * AVG(label), 2) AS attack_rate_pct
FROM network_flows
GROUP BY state
ORDER BY flows DESC;

-- name: q05_attack_types_with_severity
-- desc: Flows per attack category joined to the severity dimension, with share of attacks
SELECT f.attack_cat,
       d.severity_level,
       d.severity_weight,
       COUNT(*) AS flows,
       ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS pct_of_attacks,
       ROUND(COUNT(*) * d.severity_weight, 1) AS weighted_impact
FROM network_flows f
JOIN dim_attack_type d ON d.attack_cat = f.attack_cat
WHERE f.label = 1
GROUP BY f.attack_cat, d.severity_level, d.severity_weight
ORDER BY weighted_impact DESC;

-- name: q06_top_targeted_services
-- desc: Services most targeted by attacks (identified services only) with dominant attack type
WITH svc AS (
    SELECT service, attack_cat, COUNT(*) AS n
    FROM network_flows
    WHERE label = 1 AND service <> 'none'
    GROUP BY service, attack_cat
),
ranked AS (
    SELECT service, attack_cat, n,
           SUM(n) OVER (PARTITION BY service) AS attack_flows,
           ROW_NUMBER() OVER (PARTITION BY service ORDER BY n DESC) AS rn
    FROM svc
)
SELECT service, attack_flows, attack_cat AS dominant_attack, n AS dominant_flows,
       ROUND(100.0 * n / attack_flows, 1) AS dominant_pct
FROM ranked
WHERE rn = 1
ORDER BY attack_flows DESC;

-- name: q07_suspicious_segments
-- desc: Top suspicious traffic segments (proto/service/state) - substitute for top source IPs
SELECT proto, service, state,
       COUNT(*) AS flows,
       SUM(label) AS attack_flows,
       ROUND(100.0 * AVG(label), 2) AS attack_rate_pct,
       COUNT(DISTINCT CASE WHEN label = 1 THEN attack_cat END) AS distinct_attack_types
FROM network_flows
GROUP BY proto, service, state
HAVING COUNT(*) >= 50
ORDER BY attack_flows DESC
LIMIT 25;

-- name: q08_scan_like_behaviour
-- desc: Scan-like flows: many connections between the same host pair (ct_dst_src_ltm>=10) spread over different ports (ct_src_dport_ltm<=2) with no response bytes
SELECT attack_cat,
       COUNT(*) AS scan_like_flows,
       ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS pct_of_scan_like,
       ROUND(AVG(ct_dst_src_ltm), 1) AS avg_pair_conns,
       ROUND(AVG(spkts), 1) AS avg_spkts
FROM network_flows
WHERE ct_dst_src_ltm >= 10 AND ct_src_dport_ltm <= 2 AND dbytes = 0
GROUP BY attack_cat
ORDER BY scan_like_flows DESC;

-- name: q09_recon_profile
-- desc: Connection-context profile per class (how 'busy' the source/destination hosts are)
SELECT attack_cat,
       COUNT(*) AS flows,
       ROUND(AVG(ct_src_ltm), 2)       AS avg_src_conns,
       ROUND(AVG(ct_dst_ltm), 2)       AS avg_dst_conns,
       ROUND(AVG(ct_dst_src_ltm), 2)   AS avg_pair_conns,
       ROUND(AVG(ct_src_dport_ltm), 2) AS avg_src_same_dport,
       ROUND(AVG(ct_srv_dst), 2)       AS avg_srv_dst_conns
FROM network_flows
GROUP BY attack_cat
ORDER BY avg_pair_conns DESC;

-- name: q10_dos_patterns
-- desc: DoS-style concentration: flows hitting a destination already seen >= 20 times in the last 100 connections
WITH thr AS (
    SELECT attack_cat, label,
           CASE WHEN ct_dst_ltm >= 20 OR ct_srv_dst >= 20 THEN 1 ELSE 0 END AS hot_dst,
           rate, spkts, sbytes
    FROM network_flows
)
SELECT attack_cat,
       COUNT(*) AS flows,
       SUM(hot_dst) AS hot_destination_flows,
       ROUND(100.0 * AVG(hot_dst), 2) AS hot_destination_pct,
       ROUND(AVG(rate), 0) AS avg_pkt_rate,
       ROUND(AVG(sbytes), 0) AS avg_sbytes
FROM thr
GROUP BY attack_cat
ORDER BY hot_destination_pct DESC;

-- name: q11_services_above_avg_attack_rate
-- desc: CTE - services whose attack rate exceeds the overall attack rate
WITH overall AS (SELECT AVG(label) AS rate FROM network_flows),
svc AS (
    SELECT service, COUNT(*) AS flows, AVG(label) AS rate
    FROM network_flows GROUP BY service
)
SELECT svc.service, svc.flows,
       ROUND(100.0 * svc.rate, 2) AS attack_rate_pct,
       ROUND(100.0 * overall.rate, 2) AS overall_rate_pct,
       ROUND(100.0 * (svc.rate - overall.rate), 2) AS lift_pct_points
FROM svc CROSS JOIN overall
WHERE svc.rate > overall.rate
ORDER BY lift_pct_points DESC;

-- name: q12_rank_attacks_within_service
-- desc: Window RANK - top 3 attack categories within each service
WITH c AS (
    SELECT service, attack_cat, COUNT(*) AS flows
    FROM network_flows WHERE label = 1
    GROUP BY service, attack_cat
)
SELECT * FROM (
    SELECT service, attack_cat, flows,
           RANK() OVER (PARTITION BY service ORDER BY flows DESC) AS rnk
    FROM c
) t
WHERE rnk <= 3
ORDER BY service, rnk;

-- name: q13_duration_bins_lag
-- desc: Window LAG - attack rate across ordered duration bins and change vs previous bin (substitute for time trend)
WITH b AS (
    SELECT CASE
             WHEN dur = 0      THEN '0: 0s'
             WHEN dur < 0.001  THEN '1: <1ms'
             WHEN dur < 0.01   THEN '2: 1-10ms'
             WHEN dur < 0.1    THEN '3: 10-100ms'
             WHEN dur < 1      THEN '4: 0.1-1s'
             WHEN dur < 10     THEN '5: 1-10s'
             ELSE                   '6: >=10s'
           END AS dur_bin,
           label
    FROM network_flows
),
agg AS (
    SELECT dur_bin, COUNT(*) AS flows, ROUND(100.0 * AVG(label), 2) AS attack_rate_pct
    FROM b GROUP BY dur_bin
)
SELECT dur_bin, flows, attack_rate_pct,
       LAG(attack_rate_pct) OVER (ORDER BY dur_bin) AS prev_bin_rate,
       ROUND(attack_rate_pct - LAG(attack_rate_pct) OVER (ORDER BY dur_bin), 2) AS change_pts
FROM agg
ORDER BY dur_bin;

-- name: q14_bytes_ntile_rolling
-- desc: NTILE(20) of source bytes with a rolling 3-bin average attack rate (rolling count over an ordered axis)
WITH t AS (
    SELECT label, sbytes, NTILE(20) OVER (ORDER BY sbytes) AS bytes_bin
    FROM network_flows
),
agg AS (
    SELECT bytes_bin, MIN(sbytes) AS min_sbytes, MAX(sbytes) AS max_sbytes,
           COUNT(*) AS flows, SUM(label) AS attack_flows
    FROM t GROUP BY bytes_bin
)
SELECT bytes_bin, min_sbytes, max_sbytes, flows, attack_flows,
       ROUND(100.0 * attack_flows / flows, 2) AS attack_rate_pct,
       SUM(attack_flows) OVER (ORDER BY bytes_bin ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) AS rolling3_attack_flows,
       ROUND(100.0 * SUM(attack_flows) OVER (ORDER BY bytes_bin ROWS BETWEEN 2 PRECEDING AND CURRENT ROW)
             / SUM(flows) OVER (ORDER BY bytes_bin ROWS BETWEEN 2 PRECEDING AND CURRENT ROW), 2) AS rolling3_attack_rate_pct
FROM agg
ORDER BY bytes_bin;

-- name: q15_ttl_signature
-- desc: Source/destination TTL combinations and their attack rate (TTL fingerprints of attack tooling)
SELECT sttl, dttl, COUNT(*) AS flows,
       SUM(label) AS attack_flows,
       ROUND(100.0 * AVG(label), 2) AS attack_rate_pct
FROM network_flows
GROUP BY sttl, dttl
HAVING COUNT(*) >= 200
ORDER BY flows DESC
LIMIT 15;

-- name: q16_high_rate_flows
-- desc: CTE threshold - flows above the 99th percentile packet rate of NORMAL training traffic
WITH normal AS (
    SELECT rate, ROW_NUMBER() OVER (ORDER BY rate) AS rn, COUNT(*) OVER () AS n
    FROM network_flows WHERE label = 0 AND split = 'train'
),
p99 AS (SELECT MIN(rate) AS thr FROM normal WHERE rn >= 0.99 * n)
SELECT f.attack_cat, COUNT(*) AS high_rate_flows,
       ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS pct_of_high_rate,
       ROUND((SELECT thr FROM p99), 1) AS rate_threshold
FROM network_flows f
WHERE f.rate > (SELECT thr FROM p99)
GROUP BY f.attack_cat
ORDER BY high_rate_flows DESC;

-- name: q17_land_attack_indicator
-- desc: is_sm_ips_ports (src == dst IP and port) - LAND-style indicator
SELECT is_sm_ips_ports, COUNT(*) AS flows, SUM(label) AS attack_flows,
       ROUND(100.0 * AVG(label), 2) AS attack_rate_pct
FROM network_flows
GROUP BY is_sm_ips_ports;

-- name: q18_split_distribution
-- desc: Class mix per official split (checks for distribution shift between train and test)
SELECT attack_cat,
       SUM(CASE WHEN split = 'train' THEN 1 ELSE 0 END) AS train_flows,
       SUM(CASE WHEN split = 'test'  THEN 1 ELSE 0 END) AS test_flows,
       ROUND(100.0 * SUM(CASE WHEN split = 'train' THEN 1 ELSE 0 END)
             / SUM(SUM(CASE WHEN split = 'train' THEN 1 ELSE 0 END)) OVER (), 2) AS train_pct,
       ROUND(100.0 * SUM(CASE WHEN split = 'test' THEN 1 ELSE 0 END)
             / SUM(SUM(CASE WHEN split = 'test' THEN 1 ELSE 0 END)) OVER (), 2) AS test_pct
FROM network_flows
GROUP BY attack_cat
ORDER BY train_flows DESC;

-- name: q19_data_quality_flags
-- desc: Data-quality flags raised during cleaning
SELECT 'duplicate_in_split' AS flag, SUM(is_duplicate) AS rows_flagged FROM network_flows
UNION ALL SELECT 'test_row_seen_in_train', SUM(in_both_splits) FROM network_flows
UNION ALL SELECT 'zero_duration', SUM(flag_zero_duration) FROM network_flows
UNION ALL SELECT 'invalid_ftp_login', SUM(flag_invalid_ftp_login) FROM network_flows
UNION ALL SELECT 'label_mismatch', SUM(flag_label_mismatch) FROM network_flows;
