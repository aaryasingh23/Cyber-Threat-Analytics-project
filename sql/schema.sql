-- =====================================================================
-- UNSW-NB15 Threat Analytics - database schema (SQLite dialect)
-- Portable to PostgreSQL: swap INTEGER PRIMARY KEY -> BIGINT PRIMARY KEY,
-- REAL -> DOUBLE PRECISION.
--
-- NOTE ON THIS DATASET VERSION
-- The official train/test release has NO srcip, dstip, sport, dsport,
-- stime or ltime columns. Indexes on those columns (requested in the
-- project brief) are therefore replaced by indexes on the analytical
-- dimensions that do exist (attack_cat, proto, service, state, split).
-- An ip_summary table is NOT created because there are no IPs; the
-- equivalent grain here is segment_summary (proto x service x state).
-- The DDL you would use with the full release is kept, commented out,
-- at the bottom of this file.
-- =====================================================================

DROP VIEW IF EXISTS v_kpi_overview;
DROP TABLE IF EXISTS network_flows;
DROP TABLE IF EXISTS dim_attack_type;
DROP TABLE IF EXISTS segment_summary;

-- ---------------------------------------------------------------------
-- Dimension: attack types with severity weight (0-1) and description
-- ---------------------------------------------------------------------
CREATE TABLE dim_attack_type (
    attack_cat      TEXT PRIMARY KEY,
    severity_weight REAL NOT NULL CHECK (severity_weight BETWEEN 0 AND 1),
    severity_level  TEXT NOT NULL,
    description     TEXT NOT NULL
);

-- ---------------------------------------------------------------------
-- Fact: one row per network flow (cleaned)
-- ---------------------------------------------------------------------
CREATE TABLE network_flows (
    flow_id                 INTEGER PRIMARY KEY,
    orig_id                 INTEGER NOT NULL,
    split                   TEXT    NOT NULL CHECK (split IN ('train','test')),
    dur                     REAL,
    proto                   TEXT    NOT NULL,
    service                 TEXT    NOT NULL,
    state                   TEXT    NOT NULL,
    spkts                   INTEGER,
    dpkts                   INTEGER,
    sbytes                  INTEGER,
    dbytes                  INTEGER,
    rate                    REAL,
    sttl                    INTEGER,
    dttl                    INTEGER,
    sload                   REAL,
    dload                   REAL,
    sloss                   INTEGER,
    dloss                   INTEGER,
    sinpkt                  REAL,
    dinpkt                  REAL,
    sjit                    REAL,
    djit                    REAL,
    swin                    INTEGER,
    stcpb                   INTEGER,
    dtcpb                   INTEGER,
    dwin                    INTEGER,
    tcprtt                  REAL,
    synack                  REAL,
    ackdat                  REAL,
    smean                   INTEGER,
    dmean                   INTEGER,
    trans_depth             INTEGER,
    response_body_len       INTEGER,
    ct_srv_src              INTEGER,
    ct_state_ttl            INTEGER,
    ct_dst_ltm              INTEGER,
    ct_src_dport_ltm        INTEGER,
    ct_dst_sport_ltm        INTEGER,
    ct_dst_src_ltm          INTEGER,
    is_ftp_login            INTEGER,
    ct_ftp_cmd              INTEGER,
    ct_flw_http_mthd        INTEGER,
    ct_src_ltm              INTEGER,
    ct_srv_dst              INTEGER,
    is_sm_ips_ports         INTEGER,
    attack_cat              TEXT    NOT NULL REFERENCES dim_attack_type(attack_cat),
    label                   INTEGER NOT NULL CHECK (label IN (0,1)),
    flag_label_mismatch     INTEGER,
    flag_negative           INTEGER,
    flag_invalid_ftp_login  INTEGER,
    flag_zero_duration      INTEGER,
    is_duplicate            INTEGER,
    in_both_splits          INTEGER,
    is_attack               INTEGER,
    total_bytes             INTEGER,
    total_pkts              INTEGER,
    bytes_per_sec           REAL,
    pkts_per_sec            REAL,
    byte_ratio              REAL,
    src_byte_share          REAL,
    bytes_per_pkt           REAL
);

CREATE INDEX ix_flows_attack_cat ON network_flows(attack_cat);
CREATE INDEX ix_flows_proto      ON network_flows(proto);
CREATE INDEX ix_flows_service    ON network_flows(service);
CREATE INDEX ix_flows_state      ON network_flows(state);
CREATE INDEX ix_flows_split      ON network_flows(split);
CREATE INDEX ix_flows_label      ON network_flows(label);

-- ---------------------------------------------------------------------
-- Segment summary (substitute for ip_summary): proto x service x state
-- Populated by src/db.py after the fact table is loaded.
-- ---------------------------------------------------------------------
CREATE TABLE segment_summary (
    proto               TEXT NOT NULL,
    service             TEXT NOT NULL,
    state               TEXT NOT NULL,
    flows               INTEGER NOT NULL,
    attack_flows        INTEGER NOT NULL,
    attack_rate         REAL NOT NULL,
    distinct_attack_types INTEGER NOT NULL,
    avg_sbytes          REAL,
    avg_rate            REAL,
    PRIMARY KEY (proto, service, state)
);

-- ---------------------------------------------------------------------
-- Full-release equivalents (NOT executed - columns absent here)
-- ---------------------------------------------------------------------
-- CREATE INDEX ix_flows_srcip ON network_flows(srcip);
-- CREATE INDEX ix_flows_dstip ON network_flows(dstip);
-- CREATE INDEX ix_flows_stime ON network_flows(stime);
-- CREATE TABLE ip_summary (
--     srcip TEXT PRIMARY KEY, flows INTEGER, attack_flows INTEGER,
--     distinct_dstip INTEGER, distinct_dsport INTEGER, distinct_attack_types INTEGER,
--     first_seen TIMESTAMP, last_seen TIMESTAMP
-- );
