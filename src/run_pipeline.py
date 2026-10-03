"""Run the whole project end to end with one command.

    python src/run_pipeline.py                 # all phases
    python src/run_pipeline.py --from 6        # resume from Phase 6
    python src/run_pipeline.py --only 8 10 11  # selected phases

Phase 9 (synthetic enrichment) is intentionally skipped - the project uses real UNSW-NB15 data only.
"""
import argparse
import sys
import time
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
warnings.filterwarnings("ignore", category=FutureWarning)

import anomaly  # noqa: E402
import clean  # noqa: E402
import db  # noqa: E402
import eda  # noqa: E402
import powerbi  # noqa: E402
import report  # noqa: E402
import risk  # noqa: E402
import supervised  # noqa: E402
import threat_patterns  # noqa: E402
import web_dashboard  # noqa: E402
from load_data import detect_version, inspect_files  # noqa: E402
from utils import banner  # noqa: E402


def phase1():
    banner("PHASE 1 - SETUP CHECK")
    v, _ = detect_version()
    print("Dataset version:", v)
    print(inspect_files().to_string(index=False))


PHASES = {
    1: ("Setup check", phase1),
    2: ("EDA", eda.run),
    3: ("Cleaning", clean.run),
    4: ("Database + SQL", db.run),
    5: ("Threat patterns", threat_patterns.run),
    6: ("Anomaly detection", anomaly.run),
    7: ("Supervised ML", supervised.run),
    8: ("Risk scoring", risk.run),
    10: ("Power BI exports", powerbi.run),
    11: ("Insights report", report.run),
    12: ("Web dashboard", web_dashboard.run),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="start", type=int, default=1)
    ap.add_argument("--only", nargs="*", type=int)
    args = ap.parse_args()
    todo = args.only or [p for p in PHASES if p >= args.start]
    t0 = time.perf_counter()
    for p in todo:
        name, fn = PHASES[p]
        t = time.perf_counter()
        fn()
        print(f"--- Phase {p} ({name}) finished in {time.perf_counter() - t:.0f}s")
    print(f"\nPipeline complete in {time.perf_counter() - t0:.0f}s")


if __name__ == "__main__":
    main()
