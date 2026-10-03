"""Small shared helpers: JSON metrics, figure saving, pretty printing."""
import json
import time
from contextlib import contextmanager

import matplotlib

matplotlib.use("Agg")  # headless: scripts never open windows
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

from config import FIG_DIR, METRICS_DIR

sns.set_theme(style="whitegrid", context="notebook")
PALETTE = {"Normal": "#2e7d32", "Attack": "#c62828"}


def _to_builtin(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return None if np.isnan(o) else float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    if isinstance(o, (np.bool_,)):
        return bool(o)
    raise TypeError(f"Not serialisable: {type(o)}")


def save_json(obj, name):
    path = METRICS_DIR / f"{name}.json"
    path.write_text(json.dumps(obj, indent=2, default=_to_builtin), encoding="utf-8")
    return path


def load_json(name):
    return json.loads((METRICS_DIR / f"{name}.json").read_text(encoding="utf-8"))


def save_fig(fig, name, dpi=120):
    path = FIG_DIR / f"{name}.png"
    fig.tight_layout()
    fig.savefig(path, dpi=dpi, bbox_inches="tight")
    plt.close(fig)
    return path


@contextmanager
def timer(label):
    t0 = time.perf_counter()
    yield
    print(f"   [{label}] {time.perf_counter() - t0:.1f}s")


def banner(text):
    print("\n" + "=" * 78 + f"\n{text}\n" + "=" * 78)
