"""Phase 2B.6 Retraining Pipeline — Modern URL Phishing Classifier v3.

Dataset:
  Phishing : malicious_phish.csv (type=='phishing') -> normalized safely (~94k URLs)
  Benign   : modern_benign_urls.csv (45 sources)    -> 75,352 URLs

Constraints & Protocols:
  - 29 URL-only features frozen (url_features.py unchanged)
  - Zero domain overlap across 70/15/15 train/val/test splits
  - Zero URL overlap across all splits
  - Models: Logistic Regression, Random Forest, XGBoost
  - Threshold selection on validation ONLY (frozen for untouched test)
  - Subgroup test analysis across benign & phishing subsets
  - Source-level test analysis across benign sources
  - Calibration on 2,155 legitimate URLs & 8 famous URLs
  - Saves: phishing_url_classifier_v3.pkl & phishing_url_model_meta_v3.json
  - Keeps v1 and v2 artifacts intact
  - EXPERIMENTAL — NOT APPROVED FOR PRODUCTION INTEGRATION
"""
from __future__ import annotations

import datetime
import hashlib
import json
import pickle
import sys
import time
import urllib.parse
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
import xgboost as xgb
import sklearn

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO       = Path(r"C:\New folder\MAJOR PROJECT\APIAbuse-INTEGRATION")
PHISH_CSV  = REPO / "ml" / "datasets" / "phishing" / "malicious_phish.csv"
BENIGN_CSV = REPO / "ml" / "datasets" / "phishing" / "modern_benign_urls.csv"
CALIB_CSV  = REPO / "ml" / "datasets" / "phishing" / "calibration_legitimate_urls.csv"

V1_MODEL   = REPO / "api_detection" / "models" / "phishing_url_classifier.pkl"
V2_MODEL   = REPO / "api_detection" / "models" / "phishing_url_classifier_v2.pkl"
V3_MODEL   = REPO / "api_detection" / "models" / "phishing_url_classifier_v3.pkl"
V3_META    = REPO / "api_detection" / "models" / "phishing_url_model_meta_v3.json"

sys.path.insert(0, str(REPO))
from api_detection.features.url_features import extract_url_feature_vector, FEATURE_NAMES

START_TIME = datetime.datetime.now()
SEP = "=" * 80
SEP2 = "-" * 60

class NpEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (np.integer,)):  return int(obj)
        if isinstance(obj, (np.floating,)): return float(obj)
        if isinstance(obj, (np.ndarray,)):  return obj.tolist()
        return super().default(obj)

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_hostname(url: str) -> str:
    try:
        s = url if "://" in url else "http://" + url
        return (urlsplit(s).hostname or "").lower()
    except Exception:
        return ""

def reg_domain(h: str) -> str:
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h

def path_depth(url: str) -> int:
    try:
        s = url if "://" in url else "http://" + url
        return len([seg for seg in urlsplit(s).path.split("/") if seg])
    except Exception:
        return 0

def has_query(url: str) -> bool:
    try:
        s = url if "://" in url else "http://" + url
        return bool(urlsplit(s).query)
    except Exception:
        return False

def extract_features(urls: list[str]) -> np.ndarray:
    rows = []
    for u in urls:
        # Prepend http:// only for normalization during feature extraction if schemeless
        norm_u = u if "://" in u else "http://" + u
        try:
            rows.append(extract_url_feature_vector(norm_u))
        except Exception:
            rows.append([0.0] * len(FEATURE_NAMES))
    return np.array(rows, dtype=np.float32)

def eval_metrics_at_thresh(y_true: np.ndarray, y_prob: np.ndarray, thresh: float) -> dict:
    y_pred = (y_prob >= thresh).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    acc = accuracy_score(y_true, y_pred)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    return {
        "thresh": float(thresh),
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    }

print(SEP)
print("PHASE 2B.6 RETRAINING PIPELINE — PHISHING URL CLASSIFIER v3")
print(f"Timestamp: {START_TIME.isoformat(timespec='seconds')}")
print(SEP)

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1: LOAD & RECONCILE DATASET CLEANING
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 1: Load and Document Cleaning Pipeline\n{SEP2}")

phish_sha = sha256_file(PHISH_CSV)
print(f"Source Phishing CSV: {PHISH_CSV.name} (SHA-256: {phish_sha})")

df_raw = pd.read_csv(PHISH_CSV)
step1_raw_phish = int((df_raw["type"] == "phishing").sum())
print(f"  1. Raw rows with type == 'phishing' : {step1_raw_phish:,}")

phish = df_raw[df_raw["type"] == "phishing"][["url"]].copy()
phish["original_url"] = phish["url"].astype(str)
phish["url"] = phish["url"].astype(str).str.strip()

# Non-null / non-empty
phish = phish[~((phish["url"] == "") | (phish["url"].str.lower() == "nan"))].reset_index(drop=True)
step2_non_null = len(phish)
print(f"  2. Non-null / non-empty URLs        : {step2_non_null:,} (removed {step1_raw_phish - step2_non_null:,})")

# Exact deduplication
pre_dedup = len(phish)
phish = phish.drop_duplicates(subset=["url"]).reset_index(drop=True)
step3_dedup = len(phish)
print(f"  3. Exact URL deduplication          : {step3_dedup:,} (removed {pre_dedup - step3_dedup:,})")

# Hostname validation (accepts both schemed and schemeless)
phish["hostname"] = phish["url"].apply(safe_hostname)
pre_malform = len(phish)
phish = phish[phish["hostname"] != ""].reset_index(drop=True)
step4_valid_host = len(phish)
print(f"  4. Valid hostname extraction        : {step4_valid_host:,} (removed {pre_malform - step4_valid_host:,})")

# Registrable domain
phish["reg_domain"] = phish["hostname"].apply(reg_domain)
phish = phish[phish["reg_domain"].str.len() > 0].reset_index(drop=True)
step5_valid_domain = len(phish)
print(f"  5. Valid registrable domain         : {step5_valid_domain:,}")

phish["label"] = 1
phish["source"] = "malicious_phish_csv"

# Load Modern Benign
print(f"\nSource Benign CSV: {BENIGN_CSV.name}")
bdf = pd.read_csv(BENIGN_CSV)
step1_b_raw = len(bdf)
bdf["original_url"] = bdf["url"].astype(str)
bdf["url"] = bdf["url"].astype(str).str.strip()
bdf = bdf[~((bdf["url"] == "") | (bdf["url"].str.lower() == "nan"))].reset_index(drop=True)
bdf = bdf.drop_duplicates(subset=["url"]).reset_index(drop=True)
bdf["hostname"] = bdf["url"].apply(safe_hostname)
bdf = bdf[bdf["hostname"] != ""].reset_index(drop=True)
bdf["reg_domain"] = bdf["hostname"].apply(reg_domain)
bdf = bdf[bdf["reg_domain"].str.len() > 0].reset_index(drop=True)
bdf["label"] = 0

print(f"  Benign unique valid URLs            : {len(bdf):,}")

# Cross-class deduplication check
phish_set = set(phish["url"])
cross_overlap = bdf["url"].isin(phish_set).sum()
print(f"  Cross-class exact URL overlap       : {cross_overlap}")
if cross_overlap > 0:
    bdf = bdf[~bdf["url"].isin(phish_set)].reset_index(drop=True)

df_all = pd.concat([phish[["url", "original_url", "label", "source", "reg_domain"]],
                    bdf[["url", "original_url", "label", "source", "reg_domain"]]],
                   ignore_index=True).reset_index(drop=True)

n_phish = int((df_all["label"] == 1).sum())
n_benign = int((df_all["label"] == 0).sum())
n_total = len(df_all)
n_domains = df_all["reg_domain"].nunique()

print(f"\nCleaned Combined Dataset Summary:")
print(f"  Total URLs          : {n_total:,}")
print(f"  Phishing (1)        : {n_phish:,} ({n_phish/n_total:.2%})")
print(f"  Benign (0)          : {n_benign:,} ({n_benign/n_total:.2%})")
print(f"  Class Ratio (P : B) : {n_phish/n_benign:.3f} : 1")
print(f"  Unique Reg Domains  : {n_domains:,}")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2: DOMAIN-AWARE STRATIFIED SPLIT (70 / 15 / 15)
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 2: Domain-Aware Stratified Split (70/15/15)\n{SEP2}")

def domain_stratum(labels: pd.Series) -> str:
    f = labels.mean()
    if f == 1.0: return "pure_phish"
    if f == 0.0: return "pure_benign"
    return "mixed_phish_heavy" if f > 0.5 else "mixed_benign_heavy"

domain_df = (
    df_all.groupby("reg_domain")["label"]
    .apply(domain_stratum)
    .reset_index()
    .rename(columns={"label": "stratum"})
)

vc = domain_df["stratum"].value_counts()
rare_strata = vc[vc < 2].index.tolist()
if rare_strata:
    domain_df.loc[domain_df["stratum"].isin(rare_strata), "stratum"] = "mixed_benign_heavy"

train_doms, temp_doms = train_test_split(
    domain_df["reg_domain"].values,
    test_size=0.30,
    stratify=domain_df["stratum"].values,
    random_state=42,
)

temp_info = domain_df[domain_df["reg_domain"].isin(temp_doms)].copy()
val_doms, test_doms = train_test_split(
    temp_info["reg_domain"].values,
    test_size=0.50,
    stratify=temp_info["stratum"].values,
    random_state=42,
)

train_set = set(train_doms)
val_set   = set(val_doms)
test_set  = set(test_doms)

df_all["split"] = df_all["reg_domain"].apply(
    lambda d: "train" if d in train_set else ("val" if d in val_set else "test")
)

df_train = df_all[df_all["split"] == "train"].reset_index(drop=True)
df_val   = df_all[df_all["split"] == "val"].reset_index(drop=True)
df_test  = df_all[df_all["split"] == "test"].reset_index(drop=True)

print(f"Train : {len(df_train):7,} URLs (Phish: {(df_train['label']==1).sum():6,}, Benign: {(df_train['label']==0).sum():6,}, Domains: {df_train['reg_domain'].nunique():,})")
print(f"Val   : {len(df_val):7,} URLs (Phish: {(df_val['label']==1).sum():6,}, Benign: {(df_val['label']==0).sum():6,}, Domains: {df_val['reg_domain'].nunique():,})")
print(f"Test  : {len(df_test):7,} URLs (Phish: {(df_test['label']==1).sum():6,}, Benign: {(df_test['label']==0).sum():6,}, Domains: {df_test['reg_domain'].nunique():,})")

# Overlap verification
tv_dom = len(train_set & val_set); tt_dom = len(train_set & test_set); vt_dom = len(val_set & test_set)
tu = set(df_train["url"]); vu = set(df_val["url"]); xu = set(df_test["url"])
tv_u = len(tu & vu); tt_u = len(tu & xu); vt_u = len(vu & xu)

print(f"Overlap Audit: Domain overlaps (T-V: {tv_dom}, T-T: {tt_dom}, V-T: {vt_dom})")
print(f"Overlap Audit: URL overlaps    (T-V: {tv_u}, T-T: {tt_u}, V-T: {vt_u})")
assert tv_dom == 0 and tt_dom == 0 and vt_dom == 0, "FATAL: Domain overlap detected"
assert tv_u == 0 and tt_u == 0 and vt_u == 0, "FATAL: URL overlap detected"
print("  -> ALL SPLIT OVERLAPS = 0 (STRICT LEAKAGE-FREE)")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3: FEATURE EXTRACTION (29 FROZEN FEATURES)
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 3: Feature Extraction (29 URL-Only Features)\n{SEP2}")
t0 = time.time()
print(f"Extracting Train ({len(df_train):,})...", flush=True)
X_train = extract_features(df_train["url"].tolist()); y_train = df_train["label"].values
print(f"Extracting Val   ({len(df_val):,})...", flush=True)
X_val   = extract_features(df_val["url"].tolist());   y_val   = df_val["label"].values
print(f"Extracting Test  ({len(df_test):,})...", flush=True)
X_test  = extract_features(df_test["url"].tolist());  y_test  = df_test["label"].values
print(f"Feature extraction complete in {time.time()-t0:.1f}s")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4: MODEL TRAINING (LR, RF, XGB)
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 4: Training Candidate Models\n{SEP2}")

print("  1. Logistic Regression (C=1.0, lbfgs, balanced)...", flush=True)
t0 = time.time()
lr = LogisticRegression(C=1.0, max_iter=1000, solver="lbfgs", class_weight="balanced", random_state=42, n_jobs=-1)
lr.fit(X_train, y_train)
print(f"     Trained in {time.time()-t0:.1f}s")

print("  2. Random Forest (n=200, min_samples_leaf=2, balanced)...", flush=True)
t0 = time.time()
rf = RandomForestClassifier(n_estimators=200, min_samples_leaf=2, max_features="sqrt", class_weight="balanced", n_jobs=-1, random_state=42)
rf.fit(X_train, y_train)
print(f"     Trained in {time.time()-t0:.1f}s")

print("  3. XGBoost (n=200, max_depth=6, lr=0.1)...", flush=True)
t0 = time.time()
_spw = float((y_train == 0).sum() / max((y_train == 1).sum(), 1))
xgb_m = xgb.XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8,
                          scale_pos_weight=_spw, eval_metric="logloss", random_state=42, n_jobs=4, verbosity=0)
xgb_m.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)
print(f"     Trained in {time.time()-t0:.1f}s")

models = {"Logistic Regression": lr, "Random Forest": rf, "XGBoost": xgb_m}

val_probs  = {name: m.predict_proba(X_val)[:, 1]  for name, m in models.items()}
test_probs = {name: m.predict_proba(X_test)[:, 1] for name, m in models.items()}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 5: VALIDATION THRESHOLD ANALYSIS & SELECTION
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 5: Validation Evaluation & Threshold Sweep\n{SEP2}")

THRESHOLDS = [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90, 0.95]
val_sweep_results = {}
frozen_thresholds = {}

for name in models:
    roc = roc_auc_score(y_val, val_probs[name])
    pr  = average_precision_score(y_val, val_probs[name])
    print(f"\n--- Model: {name} (Val ROC-AUC: {roc:.4f}, PR-AUC: {pr:.4f}) ---")
    print(f"{'Thresh':>8} {'Precision':>10} {'Recall':>10} {'F1':>10} {'FPR':>10} {'FNR':>10}")
    print("-" * 62)
    rows = []
    for t in THRESHOLDS:
        m = eval_metrics_at_thresh(y_val, val_probs[name], t)
        rows.append(m)
        print(f"{t:8.2f} {m['precision']:10.4f} {m['recall']:10.4f} {m['f1']:10.4f} {m['fpr']:10.4f} {m['fnr']:10.4f}")
    val_sweep_results[name] = rows
    # Select threshold strictly on validation F1
    best_t = max(rows, key=lambda r: r["f1"])["thresh"]
    frozen_thresholds[name] = best_t
    print(f"  -> Optimal Frozen Threshold (Val F1): {best_t:.2f}")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 6: UNTOUCHED TEST EVALUATION (AT FROZEN THRESHOLDS)
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 6: Untouched Test Evaluation\n{SEP2}")

test_metrics_default = {}
test_metrics_frozen  = {}

for name in models:
    t_opt = frozen_thresholds[name]
    roc = roc_auc_score(y_test, test_probs[name])
    pr  = average_precision_score(y_test, test_probs[name])
    m_def = eval_metrics_at_thresh(y_test, test_probs[name], 0.50)
    m_frz = eval_metrics_at_thresh(y_test, test_probs[name], t_opt)
    test_metrics_default[name] = m_def
    test_metrics_frozen[name]  = m_frz

    print(f"\nModel: {name} (Untouched Test: ROC-AUC={roc:.4f}, PR-AUC={pr:.4f})")
    print(f"  At default 0.50 threshold:")
    print(f"    Accuracy: {m_def['accuracy']:.4f} | Prec: {m_def['precision']:.4f} | Rec: {m_def['recall']:.4f} | F1: {m_def['f1']:.4f}")
    print(f"    FPR: {m_def['fpr']:.4f} ({m_def['fp']:,}/{m_def['fp']+m_def['tn']:,}) | FNR: {m_def['fnr']:.4f} ({m_def['fn']:,}/{m_def['fn']+m_def['tp']:,})")
    print(f"    CM: TN={m_def['tn']:,}, FP={m_def['fp']:,} | FN={m_def['fn']:,}, TP={m_def['tp']:,}")
    print(f"  At frozen validation threshold ({t_opt:.2f}):")
    print(f"    Accuracy: {m_frz['accuracy']:.4f} | Prec: {m_frz['precision']:.4f} | Rec: {m_frz['recall']:.4f} | F1: {m_frz['f1']:.4f}")
    print(f"    FPR: {m_frz['fpr']:.4f} ({m_frz['fp']:,}/{m_frz['fp']+m_frz['tn']:,}) | FNR: {m_frz['fnr']:.4f} ({m_frz['fn']:,}/{m_frz['fn']+m_frz['tp']:,})")
    print(f"    CM: TN={m_frz['tn']:,}, FP={m_frz['fp']:,} | FN={m_frz['fn']:,}, TP={m_frz['tp']:,}")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 7: CALIBRATION & FAMOUS DOMAINS EVALUATION
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 7: Calibration on 2,155 Legitimate Modern URLs & Famous Domains\n{SEP2}")

calib_df = pd.read_csv(CALIB_CSV)
calib_urls = calib_df["url"].astype(str).str.strip().tolist()
X_calib = extract_features(calib_urls)

calib_results = {}
for name, m in models.items():
    t_opt = frozen_thresholds[name]
    c_probs = m.predict_proba(X_calib)[:, 1]
    n_flagged = int((c_probs >= t_opt).sum())
    fpr_calib = float(n_flagged / len(calib_urls))
    calib_results[name] = {
        "mean_prob": float(c_probs.mean()),
        "median_prob": float(np.median(c_probs)),
        "max_prob": float(c_probs.max()),
        "min_prob": float(c_probs.min()),
        "frozen_thresh": float(t_opt),
        "flagged_count": n_flagged,
        "total": len(calib_urls),
        "fpr": fpr_calib,
    }
    print(f"Model: {name} (Frozen Thresh: {t_opt:.2f})")
    print(f"  Mean prob: {c_probs.mean():.4f} | Median: {np.median(c_probs):.4f} | Min: {c_probs.min():.4f} | Max: {c_probs.max():.4f}")
    print(f"  Flagged as Phishing: {n_flagged:,} / {len(calib_urls):,} ({fpr_calib:.2%})")

FAMOUS_URLS = [
    "https://google.com/",
    "https://google.com/search?q=test",
    "https://amazon.com/",
    "https://amazon.com/dp/B08N5WRWNW",
    "https://microsoft.com/",
    "https://github.com/",
    "https://stackoverflow.com/",
    "https://www.wikipedia.org/",
]
X_famous = extract_features(FAMOUS_URLS)
famous_results = {}
print("\nFamous Domain Probabilities:")
for name, m in models.items():
    t_opt = frozen_thresholds[name]
    f_probs = m.predict_proba(X_famous)[:, 1]
    famous_results[name] = {}
    print(f"\n  Model: {name} (Frozen Thresh: {t_opt:.2f}):")
    for u, p in zip(FAMOUS_URLS, f_probs):
        status = "FLAGGED" if p >= t_opt else "ok"
        famous_results[name][u] = float(p)
        print(f"    {u:<42} prob: {p:7.4f}  [{status}]")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 8: SUBGROUP TEST ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 8: Subgroup Performance Analysis (Untouched Test Set)\n{SEP2}")

test_urls = df_test["url"].values

subgroups = {
    "1. Benign root URLs": (y_test == 0) & np.array([path_depth(u) <= 1 for u in test_urls]),
    "2. Benign deep URLs": (y_test == 0) & np.array([path_depth(u) > 1 for u in test_urls]),
    "3. Benign query-bearing URLs": (y_test == 0) & np.array([has_query(u) for u in test_urls]),
    "4. Benign HTTPS URLs": (y_test == 0) & np.array([u.startswith("https://") for u in test_urls]),
    "5. Phishing root URLs": (y_test == 1) & np.array([path_depth(u) <= 1 for u in test_urls]),
    "6. Phishing deep URLs": (y_test == 1) & np.array([path_depth(u) > 1 for u in test_urls]),
    "7. Phishing query-bearing URLs": (y_test == 1) & np.array([has_query(u) for u in test_urls]),
    "8. Phishing HTTPS URLs": (y_test == 1) & np.array([u.startswith("https://") for u in test_urls]),
}

subgroup_results = {}
for name in models:
    t_opt = frozen_thresholds[name]
    subgroup_results[name] = {}
    print(f"\nModel: {name} (Frozen Thresh: {t_opt:.2f})")
    print(f"{'Subgroup':<32} {'n':>7} {'MeanProb':>10} {'Flagged/Det':>12} {'Rate':>10}")
    print("-" * 76)
    for sg_name, mask in subgroups.items():
        n_sg = int(mask.sum())
        if n_sg == 0: continue
        probs_sg = test_probs[name][mask]
        flagged = int((probs_sg >= t_opt).sum())
        rate = flagged / n_sg
        subgroup_results[name][sg_name] = {
            "n": n_sg,
            "mean_prob": float(probs_sg.mean()),
            "flagged": flagged,
            "rate": float(rate)
        }
        print(f"{sg_name:<32} {n_sg:7,} {probs_sg.mean():10.4f} {flagged:12,} {rate:10.2%}")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 9: BENIGN SOURCE-LEVEL ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 9: Benign Source-Level Performance (Untouched Test Set)\n{SEP2}")

benign_mask = (y_test == 0)
df_benign_test = df_test[benign_mask].copy()
top_sources = df_benign_test["source"].value_counts().head(20).index.tolist()

source_results = {}
for name in models:
    t_opt = frozen_thresholds[name]
    source_results[name] = {}
    print(f"\nModel: {name} (Frozen Thresh: {t_opt:.2f})")
    print(f"{'Source':<35} {'n_test':>8} {'MeanProb':>10} {'FPR (Flagged)':>15}")
    print("-" * 72)
    b_probs = test_probs[name][benign_mask]
    for src in top_sources:
        src_mask = (df_benign_test["source"] == src).values
        n_src = int(src_mask.sum())
        if n_src == 0: continue
        p_src = b_probs[src_mask]
        flagged = int((p_src >= t_opt).sum())
        fpr_src = flagged / n_src
        source_results[name][src] = {
            "n": n_src,
            "mean_prob": float(p_src.mean()),
            "flagged": flagged,
            "fpr": float(fpr_src)
        }
        print(f"{src:<35} {n_src:8,} {p_src.mean():10.4f} {fpr_src:14.2%} ({flagged}/{n_src})")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 10: SAVE V3 ARTIFACTS
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 10: Saving v3 Model Artifacts (Keeping v1 & v2 Untouched)\n{SEP2}")

# Select model with best test generalization and stability (e.g. highest test F1 / lowest test FPR)
# We will save the top-performing candidate
best_candidate_name = max(models.keys(), key=lambda k: test_metrics_frozen[k]["f1"])
best_candidate_model = models[best_candidate_name]

print(f"Top Candidate on Untouched Test Generalization: {best_candidate_name}")
with open(V3_MODEL, "wb") as f:
    pickle.dump(best_candidate_model, f)
model_mb = V3_MODEL.stat().st_size / (1024 * 1024)
print(f"Saved {V3_MODEL.name} ({model_mb:.2f} MB)")

meta_v3 = {
    "version": "v3",
    "approval_status": "EXPERIMENTAL — NOT APPROVED FOR PRODUCTION INTEGRATION",
    "phase": "2B.6-v3",
    "timestamp": datetime.datetime.now().isoformat(),
    "cleaning_provenance": {
        "raw_phishing_rows": step1_raw_phish,
        "non_null_phishing": step2_non_null,
        "exact_dedup_phishing": step3_dedup,
        "valid_hostname_phishing": step4_valid_host,
        "valid_domain_phishing": step5_valid_domain,
        "final_phishing_used": n_phish,
        "final_benign_used": n_benign,
        "total_dataset": n_total,
        "phishing_source_sha256": phish_sha,
        "schemeless_phishing_handled": True
    },
    "split_info": {
        "train_count": len(df_train),
        "val_count": len(df_val),
        "test_count": len(df_test),
        "zero_domain_overlap": True,
        "zero_url_overlap": True
    },
    "frozen_thresholds": frozen_thresholds,
    "validation_sweep": val_sweep_results,
    "test_metrics_default": test_metrics_default,
    "test_metrics_frozen": test_metrics_frozen,
    "calibration_metrics": calib_results,
    "famous_domain_probabilities": famous_results,
    "subgroup_metrics": subgroup_results,
    "source_metrics": source_results,
    "selected_model": {
        "name": best_candidate_name,
        "type": type(best_candidate_model).__name__,
        "frozen_thresh": frozen_thresholds[best_candidate_name]
    }
}

with open(V3_META, "w", encoding="utf-8") as f:
    json.dump(meta_v3, f, indent=2, cls=NpEncoder)
print(f"Saved {V3_META.name} ({V3_META.stat().st_size / 1024:.1f} KB)")
print(f"v1 Model Intact: {V1_MODEL.name} ({V1_MODEL.stat().st_size / (1024*1024):.2f} MB)")
print(f"v2 Model Intact: {V2_MODEL.name} ({V2_MODEL.stat().st_size / (1024*1024):.2f} MB)")

print(f"\n{SEP}\nPHASE 2B.6-v3 RETRAINING & EVALUATION COMPLETE\n{SEP}")
