"""Phase 1 helpers: inspect the dataset folder, detect the UNSW-NB15 version, load raw data.

Two public releases exist:
  * Full version  : UNSW-NB15_1..4.csv (no header, ~2.5M rows, has srcip/dstip/ports/Stime/Ltime)
  * Train/test    : UNSW_NB15_training-set.csv + UNSW_NB15_testing-set.csv (header row,
                    257,673 rows, NO IPs / ports / timestamps)
This project was built on the train/test release; the loader refuses to guess if neither is found.
"""
import pandas as pd

from config import CHUNK_SIZE, FEATURES_FILE, RAW_DIR, TEST_FILE, TRAIN_FILE


def detect_version(raw_dir=RAW_DIR):
    files = sorted(p.name for p in raw_dir.glob("*.csv"))
    if any(f.startswith("UNSW-NB15_") and f[-5].isdigit() for f in files):
        version = "full"
    elif TRAIN_FILE.exists() and TEST_FILE.exists():
        version = "train_test"
    else:
        raise FileNotFoundError(f"No UNSW-NB15 files found in {raw_dir}. Found: {files}")
    return version, files


def inspect_files(raw_dir=RAW_DIR):
    """Print a quick inventory (size, rows, header) of every CSV in the raw folder."""
    rows = []
    for p in sorted(raw_dir.glob("*.csv")):
        with open(p, "r", encoding="utf-8-sig", errors="replace") as fh:
            header = fh.readline().strip()
            n = sum(1 for _ in fh)
        rows.append({"file": p.name, "size_mb": round(p.stat().st_size / 1e6, 2),
                     "data_rows": n, "first_line": header[:80]})
    return pd.DataFrame(rows)


def feature_descriptions():
    """Official feature dictionary (column name -> type/description)."""
    df = pd.read_csv(FEATURES_FILE, encoding="latin-1")
    df.columns = [c.strip() for c in df.columns]
    df["Name"] = df["Name"].str.strip().str.lower()
    return df[["Name", "Type", "Description"]]


def downcast(df):
    """Shrink numeric dtypes (int64->int32/16/8, float64->float32) to save memory."""
    for c in df.select_dtypes(include="integer").columns:
        df[c] = pd.to_numeric(df[c], downcast="integer")
    for c in df.select_dtypes(include="floating").columns:
        df[c] = pd.to_numeric(df[c], downcast="float")
    return df


def read_csv_chunked(path, chunksize=CHUNK_SIZE):
    """Read a CSV in chunks, downcasting each chunk, then concatenate.

    The train/test release is small (~47 MB) but the same code path scales to the
    2.5M-row full release without blowing up memory.
    """
    parts = []
    for chunk in pd.read_csv(path, chunksize=chunksize, encoding="utf-8-sig", low_memory=False):
        chunk.columns = [c.strip().lower() for c in chunk.columns]
        parts.append(downcast(chunk))
    df = pd.concat(parts, ignore_index=True)
    # Re-downcast: concat can upcast if chunks chose different widths.
    return downcast(df)


def load_raw():
    """Load both official splits and tag each row with its split."""
    version, _ = detect_version()
    if version != "train_test":
        raise NotImplementedError("Full-version loader not needed for this dataset.")
    train = read_csv_chunked(TRAIN_FILE)
    test = read_csv_chunked(TEST_FILE)
    train["split"] = "train"
    test["split"] = "test"
    df = pd.concat([train, test], ignore_index=True)
    return downcast(df)


def memory_mb(df):
    return round(df.memory_usage(deep=True).sum() / 1e6, 1)


if __name__ == "__main__":
    v, files = detect_version()
    print("Detected version:", v)
    print(inspect_files().to_string(index=False))
    raw = load_raw()
    print(raw.shape, memory_mb(raw), "MB")
    print(raw.dtypes.value_counts())
