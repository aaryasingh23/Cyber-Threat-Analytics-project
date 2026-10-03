"""Central configuration: paths, seeds and domain constants used by every phase."""
from pathlib import Path

# ---------------------------------------------------------------- paths
ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"
SQL_DIR = ROOT / "sql"
REPORTS_DIR = ROOT / "reports"
FIG_DIR = REPORTS_DIR / "figures"
METRICS_DIR = REPORTS_DIR / "metrics"
POWERBI_DIR = ROOT / "powerbi"
EXPORT_DIR = POWERBI_DIR / "exports"
PREVIEW_DIR = POWERBI_DIR / "previews"

TRAIN_FILE = RAW_DIR / "UNSW_NB15_training-set.csv"
TEST_FILE = RAW_DIR / "UNSW_NB15_testing-set.csv"
FEATURES_FILE = RAW_DIR / "NUSW-NB15_features.csv"

CLEAN_PARQUET = PROCESSED_DIR / "flows_clean.parquet"
ANOMALY_PARQUET = PROCESSED_DIR / "anomaly_scores.parquet"
PREDICTIONS_PARQUET = PROCESSED_DIR / "model_predictions.parquet"
RISK_PARQUET = PROCESSED_DIR / "flow_risk.parquet"
DB_PATH = PROCESSED_DIR / "nb15_threat.db"
DB_URL = f"sqlite:///{DB_PATH.as_posix()}"

for _d in (PROCESSED_DIR, FIG_DIR, METRICS_DIR, EXPORT_DIR, PREVIEW_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------- reproducibility
SEED = 42
CHUNK_SIZE = 50_000  # rows per chunk when reading CSVs / loading the DB

# ---------------------------------------------------------------- domain constants
CATEGORICAL_COLS = ["proto", "service", "state"]
LABEL_COL = "label"
CAT_COL = "attack_cat"

# Canonical attack category names (fixes spelling variants seen in other releases).
ATTACK_CAT_FIXES = {
    "backdoors": "Backdoor",
    "backdoor": "Backdoor",
    "shellcode": "Shellcode",
    "worms": "Worms",
    "fuzzers": "Fuzzers",
    "exploits": "Exploits",
    "generic": "Generic",
    "dos": "DoS",
    "reconnaissance": "Reconnaissance",
    "analysis": "Analysis",
    "normal": "Normal",
}

# Severity weight (0-1) + short description for every class.
# Weights reflect potential impact if the activity succeeds:
#   code execution / persistence / self-propagation  -> highest
#   availability impact (DoS)                          -> high
#   generic crypto / cipher attacks                    -> medium
#   discovery / probing / fuzzing                      -> lower (precursor activity)
ATTACK_TYPES = {
    "Normal":         (0.00, "Benign traffic"),
    "Worms":          (1.00, "Self-replicating malware that spreads to other hosts"),
    "Backdoor":       (0.95, "Bypasses authentication to give covert persistent access"),
    "Shellcode":      (0.90, "Payload used to exploit a vulnerability and gain a shell"),
    "Exploits":       (0.85, "Exploitation of known vulnerabilities (OS, apps, services)"),
    "DoS":            (0.75, "Attempts to make a service or host unavailable"),
    "Generic":        (0.60, "Technique that works against block ciphers regardless of structure"),
    "Reconnaissance": (0.50, "Scanning / probing to gather information about targets"),
    "Analysis":       (0.45, "Port scans, spam and HTML-file penetration attempts"),
    "Fuzzers":        (0.40, "Feeding random data to crash or find bugs in programs/networks"),
}
SEVERITY = {k: v[0] for k, v in ATTACK_TYPES.items()}

# Risk score weights (Phase 8) - see reports/insights_report.md for the justification.
RISK_WEIGHTS = {"anomaly": 0.40, "model_prob": 0.30, "severity": 0.20, "rules": 0.10}
RISK_BUCKETS = [(0, 25, "Low"), (25, 50, "Medium"), (50, 75, "High"), (75, 100.0001, "Critical")]
RISK_COLORS = {"Low": "#2e7d32", "Medium": "#f9a825", "High": "#ef6c00", "Critical": "#c62828"}
