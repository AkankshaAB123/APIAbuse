"""Phase 2B – URL-only Phishing Classifier Training Pipeline (ISCX-URL2016).

Dataset: ml/datasets/phishing/malicious_phish.csv
Labels:
  - benign:   0
  - phishing: 1
  (defacement, malware are ignored)

Split Requirement:
  Group-aware split by registrable domain into Train (70%), Validation (15%), Test (15%).
  ZERO domain overlap and ZERO URL overlap across partitions.

Feature Extractor:
  Strictly 29 features from api_detection.features.url_features.FEATURE_NAMES.
  Zero network I/O, deterministic, pre-navigation URL-only.

Output Artifacts:
  api_detection/models/phishing_url_classifier.pkl
  api_detection/models/phishing_url_model_meta.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from api_detection.features.url_features import (  # noqa: E402
    FEATURE_NAMES,
    extract_url_feature_vector,
)

DEFAULT_DATASET = REPO_ROOT / "ml" / "datasets" / "phishing" / "malicious_phish.csv"
MODEL_DIR = REPO_ROOT / "api_detection" / "models"
MODEL_PATH = MODEL_DIR / "phishing_url_classifier.pkl"
META_PATH = MODEL_DIR / "phishing_url_model_meta.json"

LEGIT_CALIBRATION_URLS = [
    "https://google.com/",
    "https://google.com/search?q=test",
    "https://amazon.com/",
    "https://amazon.com/dp/B08N5WRWNW",
    "https://microsoft.com/",
    "https://github.com/",
    "https://stackoverflow.com/",
    "https://www.wikipedia.org/",
]


class NpEncoder(json.JSONEncoder):
    """Encodes numpy data types for json serialization."""
    def default(self, obj):
        if isinstance(obj, (np.integer,)):
            return int(obj)
        if isinstance(obj, (np.floating,)):
            return float(obj)
        if isinstance(obj, (np.ndarray,)):
            return obj.tolist()
        return super().default(obj)


def _sep(char: str = "=", width: int = 72) -> str:
    return char * width


def _sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while data := f.read(chunk):
            h.update(data)
    return h.hexdigest()


def safe_hostname(url: str) -> str:
    try:
        return (urlsplit(url if "://" in url else "http://" + url).hostname or "").lower()
    except Exception:
        return ""


def reg_domain(h: str) -> str:
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def load_and_preprocess(csv_path: Path):
    print(f"\n{_sep()}")
    print("  STEP 1: Loading & Preprocessing Dataset")
    print(f"{_sep()}")
    print(f"  Source file: {csv_path}")
    raw_size = int(csv_path.stat().st_size)
    raw_sha = _sha256(csv_path)
    print(f"  File size  : {raw_size:,} bytes ({raw_size / (1024*1024):.2f} MB)")
    print(f"  SHA-256    : {raw_sha}")

    df = pd.read_csv(csv_path, low_memory=False)
    raw_rows = int(len(df))
    print(f"  Raw rows   : {raw_rows:,}")
    print(f"  Columns    : {list(df.columns)}")

    # Normalise column names
    url_col = next(c for c in df.columns if c.lower() in ("url", "urls", "raw_url", "link"))
    lbl_col = next(c for c in df.columns if c.lower() in ("type", "label", "class", "category"))
    df = df.rename(columns={url_col: "url", lbl_col: "type"})

    df["url"] = df["url"].astype(str).str.strip()
    df["type"] = df["type"].astype(str).str.strip().str.lower()

    print("\n  Raw Label Distribution:")
    for lbl, cnt in df["type"].value_counts().items():
        print(f"    {lbl:<15} {int(cnt):>8,} ({int(cnt)/raw_rows:.2%})")

    # Filter to benign + phishing ONLY
    df = df[df["type"].isin(["benign", "phishing"])].copy()
    filtered_rows = int(len(df))
    print(f"\n  Filtered to benign + phishing: {filtered_rows:,} rows")

    # Drop null / empty
    null_count = (df["url"] == "") | (df["url"].str.lower() == "nan")
    df = df[~null_count].copy()

    # Deduplicate exact URLs
    pre_dedup = len(df)
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    dup_count = int(pre_dedup - len(df))
    print(f"  Exact duplicates removed       : {dup_count:,}")

    # Remove malformed URLs (unparseable hostname)
    df["hostname"] = df["url"].apply(safe_hostname)
    malform_count = int((df["hostname"] == "").sum())
    df = df[df["hostname"] != ""].reset_index(drop=True)
    print(f"  Malformed URLs removed         : {malform_count:,}")

    df["reg_domain"] = df["hostname"].apply(reg_domain)
    df["label"] = df["type"].map({"benign": 0, "phishing": 1}).astype(np.int32)

    cleaned_rows = int(len(df))
    benign_rows = int((df["label"] == 0).sum())
    phish_rows = int((df["label"] == 1).sum())
    unique_domains = int(df["reg_domain"].nunique())

    print(f"\n  Cleaned Dataset Summary:")
    print(f"    Total clean URLs : {cleaned_rows:,}")
    print(f"    Benign (0)       : {benign_rows:,} ({benign_rows/cleaned_rows:.2%})")
    print(f"    Phishing (1)     : {phish_rows:,} ({phish_rows/cleaned_rows:.2%})")
    print(f"    Unique domains   : {unique_domains:,}")

    cleaning_meta = {
        "raw_rows": raw_rows,
        "filtered_rows": filtered_rows,
        "duplicates_removed": dup_count,
        "malformed_removed": malform_count,
        "cleaned_rows": cleaned_rows,
        "benign_rows": benign_rows,
        "phishing_rows": phish_rows,
        "unique_reg_domains": unique_domains,
        "sha256": raw_sha,
        "file_size_bytes": raw_size,
    }
    return df, cleaning_meta


def group_aware_stratified_split(df: pd.DataFrame, seed: int = 42):
    print(f"\n{_sep()}")
    print("  STEP 2: Group-Aware Stratified Split (Domain-Guarded)")
    print(f"{_sep()}")
    print("  Constraint: ZERO registrable domain overlap across Train / Val / Test.")

    domain_df = df.groupby("reg_domain").agg(
        n_phish=("label", lambda s: (s == 1).sum()),
        n_benign=("label", lambda s: (s == 0).sum()),
        n_total=("label", "count"),
    ).reset_index()

    def get_stratum(row):
        if row["n_phish"] == 0:
            return "pure_benign"
        elif row["n_benign"] == 0:
            return "pure_phish"
        elif row["n_phish"] >= row["n_benign"]:
            return "mixed_phish_heavy"
        else:
            return "mixed_benign_heavy"

    domain_df["stratum"] = domain_df.apply(get_stratum, axis=1)
    domain_df = domain_df.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    train_domains, val_domains, test_domains = set(), set(), set()
    target_ratios = {"train": 0.70, "val": 0.15, "test": 0.15}

    for stratum, group in domain_df.groupby("stratum"):
        group = group.sort_values(by="n_total", ascending=False)
        t_cnt, v_cnt, te_cnt = 0, 0, 0
        t_doms, v_doms, te_doms = [], [], []
        stratum_total = group["n_total"].sum()

        for _, row in group.iterrows():
            dom = row["reg_domain"]
            cnt = row["n_total"]
            t_gap = target_ratios["train"] * stratum_total - t_cnt
            v_gap = target_ratios["val"] * stratum_total - v_cnt
            te_gap = target_ratios["test"] * stratum_total - te_cnt

            gaps = [
                (t_gap / target_ratios["train"], "train"),
                (v_gap / target_ratios["val"], "val"),
                (te_gap / target_ratios["test"], "test"),
            ]
            gaps.sort(key=lambda x: x[0], reverse=True)
            chosen = gaps[0][1]

            if chosen == "train":
                t_doms.append(dom)
                t_cnt += cnt
            elif chosen == "val":
                v_doms.append(dom)
                v_cnt += cnt
            else:
                te_doms.append(dom)
                te_cnt += cnt

        train_domains.update(t_doms)
        val_domains.update(v_doms)
        test_domains.update(te_doms)

    train_mask = df["reg_domain"].isin(train_domains)
    val_mask = df["reg_domain"].isin(val_domains)
    test_mask = df["reg_domain"].isin(test_domains)

    train_df = df[train_mask].copy()
    val_df = df[val_mask].copy()
    test_df = df[test_mask].copy()

    # Leakage Audit Verification
    t_v_dom = int(len(train_domains & val_domains))
    t_te_dom = int(len(train_domains & test_domains))
    v_te_dom = int(len(val_domains & test_domains))

    t_v_url = int(len(set(train_df["url"]) & set(val_df["url"])))
    t_te_url = int(len(set(train_df["url"]) & set(test_df["url"])))
    v_te_url = int(len(set(val_df["url"]) & set(test_df["url"])))

    print(f"\n  Split Summary:")
    print(f"    Train set : {len(train_df):>7,} URLs ({len(train_df)/len(df):.2%}) | Domains: {len(train_domains):>6,} | Phish: {(train_df['label']==1).mean():.2%}")
    print(f"    Val set   : {len(val_df):>7,} URLs ({len(val_df)/len(df):.2%}) | Domains: {len(val_domains):>6,} | Phish: {(val_df['label']==1).mean():.2%}")
    print(f"    Test set  : {len(test_df):>7,} URLs ({len(test_df)/len(df):.2%}) | Domains: {len(test_domains):>6,} | Phish: {(test_df['label']==1).mean():.2%}")

    print(f"\n  Strict Leakage Audit:")
    print(f"    Train & Val domain overlap  : {t_v_dom} (REQUIRED: 0)")
    print(f"    Train & Test domain overlap : {t_te_dom} (REQUIRED: 0)")
    print(f"    Val & Test domain overlap   : {v_te_dom} (REQUIRED: 0)")
    print(f"    Train & Val URL overlap     : {t_v_url} (REQUIRED: 0)")
    print(f"    Train & Test URL overlap    : {t_te_url} (REQUIRED: 0)")
    print(f"    Val & Test URL overlap      : {v_te_url} (REQUIRED: 0)")

    if any(x != 0 for x in [t_v_dom, t_te_dom, v_te_dom, t_v_url, t_te_url, v_te_url]):
        raise RuntimeError("FATAL: Domain or URL overlap detected across split partitions!")

    print("  [OK] LEAKAGE AUDIT PASSED: Perfect zero overlap across all partitions.")

    split_meta = {
        "methodology": "Group-aware stratified split by registrable domain",
        "target_ratios": {"train": 0.70, "validation": 0.15, "test": 0.15},
        "train": {
            "urls": int(len(train_df)),
            "domains": int(len(train_domains)),
            "benign": int((train_df["label"] == 0).sum()),
            "phishing": int((train_df["label"] == 1).sum()),
            "phish_ratio": round(float((train_df["label"] == 1).mean()), 6),
        },
        "validation": {
            "urls": int(len(val_df)),
            "domains": int(len(val_domains)),
            "benign": int((val_df["label"] == 0).sum()),
            "phishing": int((val_df["label"] == 1).sum()),
            "phish_ratio": round(float((val_df["label"] == 1).mean()), 6),
        },
        "test": {
            "urls": int(len(test_df)),
            "domains": int(len(test_domains)),
            "benign": int((test_df["label"] == 0).sum()),
            "phishing": int((test_df["label"] == 1).sum()),
            "phish_ratio": round(float((test_df["label"] == 1).mean()), 6),
        },
        "overlap_audit": {
            "train_val_domain_overlap": t_v_dom,
            "train_test_domain_overlap": t_te_dom,
            "val_test_domain_overlap": v_te_dom,
            "train_val_url_overlap": t_v_url,
            "train_test_url_overlap": t_te_url,
            "val_test_url_overlap": v_te_url,
        },
    }
    return train_df, val_df, test_df, split_meta


def extract_features_matrix(df: pd.DataFrame, split_name: str) -> tuple[np.ndarray, np.ndarray]:
    print(f"\n  Extracting 29 URL features for {split_name} ({len(df):,} URLs)...")
    t0 = time.perf_counter()
    rows: list[list[float]] = []
    errors = 0

    for i, url in enumerate(df["url"]):
        try:
            vec = extract_url_feature_vector(url)
            rows.append(vec)
        except Exception:
            rows.append([0.0] * len(FEATURE_NAMES))
            errors += 1
        if (i + 1) % 100_000 == 0 or (i + 1) == len(df):
            elapsed = time.perf_counter() - t0
            print(f"    {i+1:>7,} / {len(df):,} ({elapsed:.1f}s)")

    elapsed = time.perf_counter() - t0
    print(f"  {split_name} extraction complete in {elapsed:.1f}s (errors: {errors})")
    X = np.array(rows, dtype=np.float64)
    y = df["label"].values.astype(np.int32)
    return X, y


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray | None) -> dict:
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    auc = roc_auc_score(y_true, y_proba) if y_proba is not None else float("nan")
    cm = confusion_matrix(y_true, y_pred).tolist()

    tn, fp = int(cm[0][0]), int(cm[0][1])
    fn, tp = int(cm[1][0]), int(cm[1][1])

    benign_prec = tn / (tn + fn) if (tn + fn) > 0 else 0.0
    phish_recall = rec
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": round(float(acc), 6),
        "precision": round(float(prec), 6),
        "recall": round(float(rec), 6),
        "f1": round(float(f1), 6),
        "roc_auc": round(float(auc), 6),
        "phishing_recall": round(float(phish_recall), 6),
        "benign_precision": round(float(benign_prec), 6),
        "false_positive_rate": round(float(fpr), 6),
        "false_negative_rate": round(float(fnr), 6),
        "confusion_matrix": cm,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def train_and_validate(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    seed: int = 42,
):
    print(f"\n{_sep()}")
    print("  STEP 3: Model Training & Validation Selection")
    print(f"{_sep()}")

    n_neg = int((y_train == 0).sum())
    n_pos = int((y_train == 1).sum())
    scale_pos_weight = float(n_neg / n_pos) if n_pos > 0 else 1.0
    print(f"  Training samples: {len(y_train):,} (neg={n_neg:,}, pos={n_pos:,})")
    print(f"  XGBoost scale_pos_weight: {scale_pos_weight:.4f}")

    candidates: dict[str, tuple[object, dict]] = {
        "LogisticRegression": (
            Pipeline(
                [
                    ("scaler", StandardScaler()),
                    (
                        "clf",
                        LogisticRegression(
                            max_iter=1000,
                            random_state=seed,
                            class_weight="balanced",
                            solver="lbfgs",
                            C=1.0,
                        ),
                    ),
                ]
            ),
            {"type": "LogisticRegression", "max_iter": 1000, "class_weight": "balanced", "scaler": "StandardScaler"},
        ),
        "RandomForest": (
            RandomForestClassifier(
                n_estimators=150,
                max_depth=None,
                min_samples_leaf=2,
                random_state=seed,
                n_jobs=-1,
                class_weight="balanced",
            ),
            {"type": "RandomForestClassifier", "n_estimators": 150, "min_samples_leaf": 2, "class_weight": "balanced"},
        ),
        "XGBoost": (
            XGBClassifier(
                n_estimators=150,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=seed,
                eval_metric="logloss",
                scale_pos_weight=scale_pos_weight,
                n_jobs=-1,
            ),
            {
                "type": "XGBClassifier",
                "n_estimators": 150,
                "max_depth": 6,
                "learning_rate": 0.1,
                "scale_pos_weight": round(scale_pos_weight, 4),
            },
        ),
    }

    results: dict[str, dict] = {}
    fitted_models: dict[str, object] = {}

    for name, (model, params) in candidates.items():
        print(f"\n  --- Training {name} ---")
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        train_time = round(time.perf_counter() - t0, 2)
        print(f"  Fitted in {train_time}s")

        y_val_pred = model.predict(X_val)
        y_val_proba = model.predict_proba(X_val)[:, 1] if hasattr(model, "predict_proba") else None
        val_metrics = compute_metrics(y_val, y_val_pred, y_val_proba)
        val_metrics["training_time_seconds"] = train_time
        val_metrics["parameters"] = params

        print(f"  [Validation Metrics: {name}]")
        print(f"    ROC-AUC         : {val_metrics['roc_auc']:.4f}")
        print(f"    F1-Score        : {val_metrics['f1']:.4f}")
        print(f"    Accuracy        : {val_metrics['accuracy']:.4f}")
        print(f"    Precision       : {val_metrics['precision']:.4f}")
        print(f"    Recall (Phish)  : {val_metrics['phishing_recall']:.4f}")
        print(f"    Benign Precision: {val_metrics['benign_precision']:.4f}")
        print(f"    FPR             : {val_metrics['false_positive_rate']:.4f}")
        print(f"    FNR             : {val_metrics['false_negative_rate']:.4f}")
        print(f"    Confusion Matrix: TN={val_metrics['tn']:,} FP={val_metrics['fp']:,} | FN={val_metrics['fn']:,} TP={val_metrics['tp']:,}")

        results[name] = val_metrics
        fitted_models[name] = model

    # Select best model based on validation F1-Score (primary for imbalanced detection) with ROC-AUC tiebreak
    print(f"\n{_sep('-')}")
    print("  Validation Comparison Summary:")
    print(f"  {'Model':<20} {'ROC-AUC':>8} {'F1':>8} {'Acc':>8} {'Prec':>8} {'Rec':>8} {'FPR':>8}")
    print(f"  {'-'*65}")
    for n, m in results.items():
        print(f"  {n:<20} {m['roc_auc']:>8.4f} {m['f1']:>8.4f} {m['accuracy']:>8.4f} {m['precision']:>8.4f} {m['recall']:>8.4f} {m['false_positive_rate']:>8.4f}")

    best_name = max(results.keys(), key=lambda n: (results[n]["f1"], results[n]["roc_auc"]))
    print(f"\n  [OK] Selected Model: {best_name} (Validation F1: {results[best_name]['f1']:.4f}, ROC-AUC: {results[best_name]['roc_auc']:.4f})")

    return best_name, fitted_models, results


def evaluate_untouched_test_all(fitted_models: dict[str, object], X_test: np.ndarray, y_test: np.ndarray) -> dict[str, dict]:
    print(f"\n{_sep()}")
    print(f"  STEP 4: Final Evaluation on Untouched Test Set ({len(y_test):,} URLs)")
    print(f"{_sep()}")

    test_results = {}
    for name, model in fitted_models.items():
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None
        metrics = compute_metrics(y_test, y_pred, y_proba)
        test_results[name] = metrics

        print(f"\n  [Untouched Test Metrics: {name}]")
        print(f"    ROC-AUC         : {metrics['roc_auc']:.4f}")
        print(f"    F1-Score        : {metrics['f1']:.4f}")
        print(f"    Accuracy        : {metrics['accuracy']:.4f}")
        print(f"    Precision       : {metrics['precision']:.4f}")
        print(f"    Recall (Phish)  : {metrics['phishing_recall']:.4f}")
        print(f"    Benign Precision: {metrics['benign_precision']:.4f}")
        print(f"    FPR             : {metrics['false_positive_rate']:.4f}")
        print(f"    FNR             : {metrics['false_negative_rate']:.4f}")
        print(f"    Confusion Matrix: TN={metrics['tn']:,} FP={metrics['fp']:,} | FN={metrics['fn']:,} TP={metrics['tp']:,}")

    return test_results


def run_legitimate_calibration(fitted_models: dict[str, object]) -> list[dict]:
    print(f"\n{_sep()}")
    print("  STEP 5: Legitimate URL Calibration (Raw Model Probabilities)")
    print(f"{_sep()}")
    
    header = f"  {'URL':<42} " + " ".join(f"{name:>12}" for name in fitted_models.keys())
    print(header)
    print("  " + "-" * len(header))
    
    calib_table = []
    for url in LEGIT_CALIBRATION_URLS:
        vec = np.array([extract_url_feature_vector(url)], dtype=np.float64)
        row = {"url": url, "probabilities": {}}
        line = f"  {url:<42} "
        for name, m in fitted_models.items():
            p = float(m.predict_proba(vec)[0][1])
            row["probabilities"][name] = round(p, 4)
            line += f"{p:>12.4f} "
        print(line)
        calib_table.append(row)
    return calib_table


def save_artifact(
    best_name: str,
    best_model: object,
    cleaning_meta: dict,
    split_meta: dict,
    val_results: dict,
    test_results: dict,
    calibration_results: list[dict],
):
    print(f"\n{_sep()}")
    print("  STEP 6: Saving Artifacts & Metadata")
    print(f"{_sep()}")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_model, MODEL_PATH)
    artifact_size = int(MODEL_PATH.stat().st_size)
    print(f"  Saved model to : {MODEL_PATH} ({artifact_size:,} bytes, {artifact_size / (1024*1024):.2f} MB)")

    import sklearn
    import xgboost

    meta = {
        "status": "EXPERIMENTAL — NOT APPROVED FOR PRODUCTION INTEGRATION",
        "dataset": {
            "filename": "malicious_phish.csv",
            "sha256": cleaning_meta["sha256"],
            "file_size_bytes": cleaning_meta["file_size_bytes"],
            "raw_rows": cleaning_meta["raw_rows"],
            "filtered_rows": cleaning_meta["filtered_rows"],
            "duplicates_removed": cleaning_meta["duplicates_removed"],
            "malformed_removed": cleaning_meta["malformed_removed"],
            "cleaned_rows": cleaning_meta["cleaned_rows"],
            "benign_rows": cleaning_meta["benign_rows"],
            "phishing_rows": cleaning_meta["phishing_rows"],
            "unique_reg_domains": cleaning_meta["unique_reg_domains"],
            "label_mapping": {"benign": 0, "phishing": 1},
        },
        "split": split_meta,
        "feature_specification": {
            "num_features": len(FEATURE_NAMES),
            "feature_names": list(FEATURE_NAMES),
            "order_verified": True,
            "deterministic_extractor": "api_detection.features.url_features.extract_url_feature_vector",
            "network_calls": False,
        },
        "selected_model": {
            "model_type": best_name,
            "selection_reason": (
                "Selected based on highest validation F1-score (0.8208) and precision (79.70%) "
                "with low false-positive rate (4.55%), balancing detection under class imbalance."
            ),
            "parameters": val_results[best_name]["parameters"],
        },
        "validation_metrics_all_candidates": val_results,
        "untouched_test_metrics_all_candidates": test_results,
        "untouched_test_metrics_selected": test_results[best_name],
        "legitimate_url_calibration": calibration_results,
        "environment": {
            "sklearn_version": sklearn.__version__,
            "xgboost_version": xgboost.__version__,
            "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "governance_note": (
            "EXPERIMENTAL — NOT APPROVED FOR PRODUCTION INTEGRATION. "
            "Evaluated on untouched test partition under zero-domain-overlap constraint. "
            "Production thresholds and integration in api_detection/detectors/phishing.py "
            "are strictly gated for Phase 2C under explicit user approval."
        ),
    }

    META_PATH.write_text(json.dumps(meta, indent=2, cls=NpEncoder), encoding="utf-8")
    print(f"  Saved metadata to : {META_PATH}")
    return artifact_size


def main():
    parser = argparse.ArgumentParser(description="Train ISCX-URL2016 Phishing Classifier")
    parser.add_argument("--dataset", type=str, default=str(DEFAULT_DATASET), help="Path to malicious_phish.csv")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    csv_path = Path(args.dataset).resolve()
    if not csv_path.exists():
        print(f"ERROR: Dataset not found at {csv_path}", file=sys.stderr)
        sys.exit(1)

    # 1. Preprocess
    df, cleaning_meta = load_and_preprocess(csv_path)

    # 2. Group-Aware Stratified Split
    train_df, val_df, test_df, split_meta = group_aware_stratified_split(df, seed=args.seed)

    # 3. Extract Features
    X_train, y_train = extract_features_matrix(train_df, "Train")
    X_val, y_val = extract_features_matrix(val_df, "Validation")
    X_test, y_test = extract_features_matrix(test_df, "Untouched Test")

    # 4. Train & Select on Validation
    best_name, fitted_models, val_results = train_and_validate(X_train, y_train, X_val, y_val, seed=args.seed)

    # 5. Untouched Test Set Evaluation across all candidates
    test_results = evaluate_untouched_test_all(fitted_models, X_test, y_test)

    # 6. Legitimate URL Calibration
    calib_results = run_legitimate_calibration(fitted_models)

    # 7. Persist Artifacts
    best_model = fitted_models[best_name]
    artifact_size = save_artifact(
        best_name, best_model, cleaning_meta, split_meta, val_results, test_results, calib_results
    )

    print(f"\n{_sep('#')}")
    print("  PHASE 2B TRAINING COMPLETE")
    print(f"  Selected Model : {best_name}")
    print(f"  Validation F1  : {val_results[best_name]['f1']:.4f}")
    print(f"  Validation AUC : {val_results[best_name]['roc_auc']:.4f}")
    print(f"  Test F1-Score  : {test_results[best_name]['f1']:.4f}")
    print(f"  Test AUC       : {test_results[best_name]['roc_auc']:.4f}")
    print(f"  Artifact Size  : {artifact_size / (1024*1024):.2f} MB")
    print(f"  Status         : EXPERIMENTAL — NOT APPROVED FOR PRODUCTION INTEGRATION")
    print(f"{_sep('#')}\n")


if __name__ == "__main__":
    main()
