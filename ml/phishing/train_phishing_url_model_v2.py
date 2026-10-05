"""Phase 2B.6 Training Pipeline — Modern URL Phishing Classifier v2.

Training corpus:
  Phishing : malicious_phish.csv  (type=='phishing')  → label=1
  Benign   : modern_benign_urls.csv                   → label=0

Split    : Registrable-domain grouped, 70/15/15, zero domain overlap.
Features : Existing 29 URL-only features (api_detection.features.url_features).
Candidates: Logistic Regression, Random Forest, XGBoost.
Selection : Validation ROC-AUC (calibration set NOT used for selection).

Artifacts saved:
  api_detection/models/phishing_url_classifier_v2.pkl
  api_detection/models/phishing_url_model_meta_v2.json

EXPERIMENTAL — NOT APPROVED FOR PRODUCTION INTEGRATION.
Old model NOT deleted or overwritten.
"""
from __future__ import annotations

import datetime
import json
import pickle
import sys
import urllib.parse
import warnings
from pathlib import Path

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

warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO       = Path(r"C:\New folder\MAJOR PROJECT\APIAbuse-INTEGRATION")
PHISH_CSV  = REPO / "ml" / "datasets" / "phishing" / "malicious_phish.csv"
BENIGN_CSV = REPO / "ml" / "datasets" / "phishing" / "modern_benign_urls.csv"
CALIB_CSV  = REPO / "ml" / "datasets" / "phishing" / "calibration_legitimate_urls.csv"
OLD_MODEL  = REPO / "api_detection" / "models" / "phishing_url_classifier.pkl"
OLD_META   = REPO / "api_detection" / "models" / "phishing_url_model_meta.json"
V2_MODEL   = REPO / "api_detection" / "models" / "phishing_url_classifier_v2.pkl"
V2_META    = REPO / "api_detection" / "models" / "phishing_url_model_meta_v2.json"

sys.path.insert(0, str(REPO))
from api_detection.features.url_features import (  # noqa: E402
    extract_url_feature_vector,
    FEATURE_NAMES,
)

TRAIN_START = datetime.datetime.now()
SEP  = "=" * 72
SEP2 = "─" * 50


# ── JSON encoder for numpy types ───────────────────────────────────────────────
class NpEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):  return int(obj)
        if isinstance(obj, np.floating): return float(obj)
        if isinstance(obj, np.ndarray):  return obj.tolist()
        return super().default(obj)


# ── URL utility helpers ────────────────────────────────────────────────────────
def reg_domain(url: str) -> str:
    try:
        h = urllib.parse.urlparse(url).hostname or ""
        parts = h.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else h
    except Exception:
        return ""

def is_valid_url(url: str) -> bool:
    u = str(url).strip()
    return u.startswith("http://") or u.startswith("https://")

def path_depth(url: str) -> int:
    try:
        return len([s for s in urllib.parse.urlparse(url).path.split("/") if s])
    except Exception:
        return 0

def has_query(url: str) -> bool:
    try:
        return bool(urllib.parse.urlparse(url).query)
    except Exception:
        return False

def has_digits_in_path(url: str) -> bool:
    try:
        return any(c.isdigit() for c in urllib.parse.urlparse(url).path)
    except Exception:
        return False

def has_subdomain(url: str) -> bool:
    try:
        h = urllib.parse.urlparse(url).hostname or ""
        return len(h.split(".")) > 2
    except Exception:
        return False


# ── Metrics helpers ───────────────────────────────────────────────────────────
def full_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.50) -> dict:
    y_pred = (y_prob >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return {
        "n":          int(len(y_true)),
        "n_positive": int(y_true.sum()),
        "n_negative": int((1 - y_true).sum()),
        "accuracy":   float(accuracy_score(y_true, y_pred)),
        "precision":  float(precision_score(y_true, y_pred, zero_division=0)),
        "recall":     float(recall_score(y_true, y_pred, zero_division=0)),
        "f1":         float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc":    float(roc_auc_score(y_true, y_prob)),
        "pr_auc":     float(average_precision_score(y_true, y_prob)),
        "fpr":        float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
        "fnr":        float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0,
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }

def subgroup_summary(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.50) -> dict:
    n = len(y_true)
    if n == 0:
        return {"n": 0}
    y_pred = (y_prob >= threshold).astype(int)
    n_phish  = int(y_true.sum())
    n_benign = n - n_phish
    mean_prob = float(y_prob.mean())
    if n_phish == 0:
        n_flagged = int(y_pred.sum())
        return {
            "n": n, "all_class": "benign",
            "mean_prob": mean_prob,
            "flagged_as_phishing": n_flagged,
            "false_positive_rate": float(n_flagged / n),
        }
    if n_benign == 0:
        detected = int(y_pred.sum())
        return {
            "n": n, "all_class": "phishing",
            "mean_prob": mean_prob,
            "detected": detected,
            "detection_rate": float(detected / n),
            "missed": n - detected,
        }
    m = full_metrics(y_true, y_prob, threshold)
    m["mean_prob"] = mean_prob
    return m

def extract_features(urls) -> np.ndarray:
    rows = []
    for u in urls:
        try:
            rows.append(extract_url_feature_vector(u))
        except Exception:
            rows.append([0.0] * len(FEATURE_NAMES))
    return np.array(rows, dtype=np.float32)


# ══════════════════════════════════════════════════════════════════════════════
print(SEP)
print("PHASE 2B.6 — TRAINING PIPELINE v2")
print(f"Started : {TRAIN_START.isoformat(timespec='seconds')}")
print(f"Features: {list(FEATURE_NAMES)}")
print(SEP)

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1  Load + clean data
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 1: Load + clean data\n{SEP2}")

phdf = pd.read_csv(PHISH_CSV)
phish_raw = phdf[phdf["type"] == "phishing"][["url"]].copy()
phish_raw["label"] = 1
phish_raw["url"] = phish_raw["url"].astype(str).str.strip()
phish_raw = phish_raw[phish_raw["url"].apply(is_valid_url)].copy()
phish_raw = phish_raw.drop_duplicates(subset=["url"]).reset_index(drop=True)

bdf = pd.read_csv(BENIGN_CSV)
benign_raw = bdf[["url"]].copy()
benign_raw["label"] = 0
benign_raw["url"] = benign_raw["url"].astype(str).str.strip()
benign_raw = benign_raw[benign_raw["url"].apply(is_valid_url)].copy()
benign_raw = benign_raw.drop_duplicates(subset=["url"]).reset_index(drop=True)

# Check cross-class URL overlap (URLs that appear in both phishing and benign)
phish_url_set = set(phish_raw["url"])
cross_overlap = benign_raw["url"].isin(phish_url_set).sum()
if cross_overlap > 0:
    print(f"  NOTE: {cross_overlap:,} URLs appear in both classes — removing from benign.")
    benign_raw = benign_raw[~benign_raw["url"].isin(phish_url_set)].reset_index(drop=True)

print(f"  Phishing unique : {len(phish_raw):,}")
print(f"  Benign unique   : {len(benign_raw):,}")
print(f"  Cross-class URL overlap : {cross_overlap:,}")

df = pd.concat([phish_raw, benign_raw], ignore_index=True).reset_index(drop=True)
raw_count = len(df)
df["reg_domain"] = df["url"].apply(reg_domain)
df = df[df["reg_domain"].str.len() > 0].reset_index(drop=True)

n_phish_total  = int((df["label"] == 1).sum())
n_benign_total = int((df["label"] == 0).sum())
n_total        = len(df)
n_domains_all  = df["reg_domain"].nunique()

print(f"  Cleaned : {n_total:,} (removed {raw_count - n_total:,})")
print(f"  Phishing: {n_phish_total:,}   Benign: {n_benign_total:,}")
print(f"  Unique reg domains: {n_domains_all:,}")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2  Domain-grouped stratified split  70 / 15 / 15
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 2: Domain-grouped split (70/15/15)\n{SEP2}")

def domain_stratum(labels: pd.Series) -> str:
    f = labels.mean()
    if f == 1.0: return "pure_phish"
    if f == 0.0: return "pure_benign"
    return "mixed_phish_heavy" if f > 0.5 else "mixed_benign_heavy"

domain_df = (
    df.groupby("reg_domain")["label"]
    .apply(domain_stratum)
    .reset_index()
    .rename(columns={"label": "stratum"})
)

# Collapse any strata with <2 members (can't stratify-split on singleton)
vc = domain_df["stratum"].value_counts()
rare_strata = vc[vc < 2].index.tolist()
if rare_strata:
    print(f"  Collapsing rare strata {rare_strata} → mixed_benign_heavy")
    domain_df.loc[domain_df["stratum"].isin(rare_strata), "stratum"] = "mixed_benign_heavy"

print(f"  Domain strata: {domain_df['stratum'].value_counts().to_dict()}")

# 70 / 30 split of domains
train_doms, temp_doms = train_test_split(
    domain_df["reg_domain"].values,
    test_size=0.30,
    stratify=domain_df["stratum"].values,
    random_state=42,
)

# 15 / 15 split of temp
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

df["split"] = df["reg_domain"].apply(
    lambda d: "train" if d in train_set else ("val" if d in val_set else "test")
)

df_train = df[df["split"] == "train"].reset_index(drop=True)
df_val   = df[df["split"] == "val"].reset_index(drop=True)
df_test  = df[df["split"] == "test"].reset_index(drop=True)

for pname, part in [("Train", df_train), ("Val", df_val), ("Test", df_test)]:
    ph = int((part["label"] == 1).sum())
    be = int((part["label"] == 0).sum())
    nd = part["reg_domain"].nunique()
    print(f"  {pname:5s}: {len(part):7,} URLs  phishing={ph:6,}  benign={be:6,}  domains={nd:,}")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3  Zero-overlap verification
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 3: Zero-overlap verification\n{SEP2}")

td = set(df_train["reg_domain"]); vd = set(df_val["reg_domain"]); xd = set(df_test["reg_domain"])
tu = set(df_train["url"]);        vu = set(df_val["url"]);        xu = set(df_test["url"])

tv_dom = len(td & vd); tt_dom = len(td & xd); vt_dom = len(vd & xd)
tv_url = len(tu & vu); tt_url = len(tu & xu); vt_url = len(vu & xu)

print(f"  Domain overlaps: Train-Val={tv_dom}  Train-Test={tt_dom}  Val-Test={vt_dom}")
print(f"  URL overlaps   : Train-Val={tv_url}  Train-Test={tt_url}  Val-Test={vt_url}")

assert tv_dom == 0 and tt_dom == 0 and vt_dom == 0, "FATAL: domain overlap detected"
assert tv_url == 0 and tt_url == 0 and vt_url == 0, "FATAL: URL overlap detected"
print("  ALL OVERLAPS = 0  ✓")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4  Feature extraction (29 URL features)
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 4: Feature extraction ({len(FEATURE_NAMES)} features)\n{SEP2}")

print(f"  Extracting train ({len(df_train):,})...", flush=True)
X_train = extract_features(df_train["url"]); y_train = df_train["label"].values
print(f"    X_train: {X_train.shape}  positives={y_train.sum():,}/{len(y_train):,}")

print(f"  Extracting val   ({len(df_val):,})...", flush=True)
X_val = extract_features(df_val["url"]); y_val = df_val["label"].values
print(f"    X_val  : {X_val.shape}  positives={y_val.sum():,}/{len(y_val):,}")

print(f"  Extracting test  ({len(df_test):,})...", flush=True)
X_test = extract_features(df_test["url"]); y_test = df_test["label"].values
print(f"    X_test : {X_test.shape}  positives={y_test.sum():,}/{len(y_test):,}")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5  Train candidates
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 5: Training candidates\n{SEP2}")

print("  [LR] Logistic Regression...", flush=True)
lr = LogisticRegression(
    C=1.0, max_iter=1000, solver="lbfgs",
    class_weight="balanced", random_state=42, n_jobs=-1,
)
lr.fit(X_train, y_train)
print("    Done.")

print("  [RF] Random Forest (n=200)...", flush=True)
rf = RandomForestClassifier(
    n_estimators=200, min_samples_leaf=2, max_features="sqrt",
    class_weight="balanced", n_jobs=-1, random_state=42,
)
rf.fit(X_train, y_train)
print("    Done.")

print("  [XGB] XGBoost (n=200)...", flush=True)
_spw = float((y_train == 0).sum() / max((y_train == 1).sum(), 1))
xgb_model = xgb.XGBClassifier(
    n_estimators=200, max_depth=6, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8,
    scale_pos_weight=_spw,
    eval_metric="logloss", random_state=42,
    n_jobs=4, verbosity=0,
)
xgb_model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)
print("    Done.")

CANDIDATES = {"LR": lr, "RF": rf, "XGB": xgb_model}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 6  Validation evaluation → model selection
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 6: Validation evaluation\n{SEP2}")

val_metrics = {}
for cname, model in CANDIDATES.items():
    prob = model.predict_proba(X_val)[:, 1]
    m = full_metrics(y_val, prob)
    val_metrics[cname] = m
    print(f"  {cname}: ROC-AUC={m['roc_auc']:.4f}  F1={m['f1']:.4f}  "
          f"Prec={m['precision']:.4f}  Rec={m['recall']:.4f}  "
          f"FPR={m['fpr']:.4f}  PR-AUC={m['pr_auc']:.4f}")

best_name  = max(val_metrics, key=lambda k: val_metrics[k]["roc_auc"])
best_model = CANDIDATES[best_name]
print(f"\n  → SELECTED: {best_name}  (val ROC-AUC={val_metrics[best_name]['roc_auc']:.4f})")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 7  Untouched test evaluation (all candidates)
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 7: Untouched test evaluation (all candidates)\n{SEP2}")

test_metrics = {}
test_probs   = {}
for cname, model in CANDIDATES.items():
    prob = model.predict_proba(X_test)[:, 1]
    test_probs[cname] = prob
    m = full_metrics(y_test, prob)
    test_metrics[cname] = m
    print(f"  {cname}:")
    print(f"    Accuracy={m['accuracy']:.4f}  Precision={m['precision']:.4f}  "
          f"Recall={m['recall']:.4f}  F1={m['f1']:.4f}")
    print(f"    ROC-AUC={m['roc_auc']:.4f}  PR-AUC={m['pr_auc']:.4f}  "
          f"FPR={m['fpr']:.4f}  FNR={m['fnr']:.4f}")
    print(f"    TP={m['tp']:,}  TN={m['tn']:,}  FP={m['fp']:,}  FN={m['fn']:,}")
    print(f"    Confusion matrix: TN={m['tn']:,} FP={m['fp']:,} | FN={m['fn']:,} TP={m['tp']:,}")

best_prob_test = test_probs[best_name]


# ══════════════════════════════════════════════════════════════════════════════
# STEP 8  Subgroup analysis (selected model on test set)
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 8: Subgroup analysis ({best_name} on test set)\n{SEP2}")

test_urls   = df_test["url"].values
test_labels = y_test

# Precompute boolean masks
is_root_mask   = np.array([path_depth(u) <= 1 for u in test_urls])
is_deep_mask   = ~is_root_mask
is_query_mask  = np.array([has_query(u)           for u in test_urls])
is_https_mask  = np.array([u.startswith("https://") for u in test_urls])
is_digits_mask = np.array([has_digits_in_path(u)  for u in test_urls])
is_sub_mask    = np.array([has_subdomain(u)        for u in test_urls])
is_benign_mask  = test_labels == 0
is_phish_mask   = test_labels == 1

def sg(mask: np.ndarray, label: str) -> dict:
    if mask.sum() == 0:
        print(f"  {label:<45}: n=0  (skipped)")
        return {"n": 0, "label": label}
    y_ = test_labels[mask]
    p_ = best_prob_test[mask]
    res = subgroup_summary(y_, p_)
    res["label"] = label
    ac = res.get("all_class", "mixed")
    if ac == "benign":
        print(f"  {label:<45}: n={res['n']:6,}  mean_prob={res['mean_prob']:.4f}  "
              f"FPR={res['false_positive_rate']:.4f}  flagged={res['flagged_as_phishing']:,}")
    elif ac == "phishing":
        print(f"  {label:<45}: n={res['n']:6,}  mean_prob={res['mean_prob']:.4f}  "
              f"DetRate={res['detection_rate']:.4f}  detected={res['detected']:,}")
    else:
        print(f"  {label:<45}: n={res['n']:6,}  AUC={res.get('roc_auc',0):.4f}  "
              f"F1={res.get('f1',0):.4f}  FPR={res.get('fpr',0):.4f}")
    return res

subgroup_results: dict = {}

print("  ── BENIGN SUBGROUPS ──")
subgroup_results["benign_all"]       = sg(is_benign_mask,                            "benign_all")
subgroup_results["benign_root"]      = sg(is_benign_mask & is_root_mask,             "benign_root_home")
subgroup_results["benign_deep"]      = sg(is_benign_mask & is_deep_mask,             "benign_deep")
subgroup_results["benign_query"]     = sg(is_benign_mask & is_query_mask,            "benign_query_bearing")
subgroup_results["benign_https"]     = sg(is_benign_mask & is_https_mask,            "benign_https")
subgroup_results["benign_digits"]    = sg(is_benign_mask & is_digits_mask,           "benign_digits_in_path")
subgroup_results["benign_subdomain"] = sg(is_benign_mask & is_sub_mask,             "benign_has_subdomain")

print("  ── PHISHING SUBGROUPS ──")
subgroup_results["phishing_all"]     = sg(is_phish_mask,                             "phishing_all")
subgroup_results["phishing_root"]    = sg(is_phish_mask & is_root_mask,              "phishing_root")
subgroup_results["phishing_deep"]    = sg(is_phish_mask & is_deep_mask,              "phishing_deep")
subgroup_results["phishing_https"]   = sg(is_phish_mask & is_https_mask,             "phishing_https")
subgroup_results["phishing_query"]   = sg(is_phish_mask & is_query_mask,             "phishing_query_bearing")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 9  Calibration evaluation (calibration set NOT used for training/selection)
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 9: Calibration evaluation\n{SEP2}")

calib_df    = pd.read_csv(CALIB_CSV)
calib_urls  = calib_df["url"].astype(str).str.strip().tolist()
X_calib     = extract_features(calib_urls)
calib_probs = best_model.predict_proba(X_calib)[:, 1]

calib_metrics = {
    "n":           int(len(calib_probs)),
    "mean":        float(calib_probs.mean()),
    "median":      float(np.median(calib_probs)),
    "p90":         float(np.percentile(calib_probs, 90)),
    "p95":         float(np.percentile(calib_probs, 95)),
    "p99":         float(np.percentile(calib_probs, 99)),
    "min":         float(calib_probs.min()),
    "max":         float(calib_probs.max()),
    "pct_gte_050": float((calib_probs >= 0.50).mean()),
    "pct_gte_070": float((calib_probs >= 0.70).mean()),
    "pct_gte_080": float((calib_probs >= 0.80).mean()),
    "pct_gte_090": float((calib_probs >= 0.90).mean()),
    "pct_gte_095": float((calib_probs >= 0.95).mean()),
}
print(f"  n={calib_metrics['n']:,}")
print(f"  mean={calib_metrics['mean']:.4f}  median={calib_metrics['median']:.4f}  "
      f"min={calib_metrics['min']:.4f}  max={calib_metrics['max']:.4f}")
print(f"  p90={calib_metrics['p90']:.4f}  p95={calib_metrics['p95']:.4f}  p99={calib_metrics['p99']:.4f}")
print(f"  >=0.50: {calib_metrics['pct_gte_050']:.2%}  >=0.70: {calib_metrics['pct_gte_070']:.2%}  "
      f">=0.80: {calib_metrics['pct_gte_080']:.2%}  >=0.90: {calib_metrics['pct_gte_090']:.2%}  "
      f">=0.95: {calib_metrics['pct_gte_095']:.2%}")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 10  Famous domain probabilities
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 10: Famous domain probabilities\n{SEP2}")

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
X_famous     = extract_features(FAMOUS_URLS)
famous_probs = best_model.predict_proba(X_famous)[:, 1]
famous_results: dict[str, float] = {}

print(f"  {'URL':<48} {'Phish Prob':>10}  Flag")
print(f"  {'─'*48} {'─'*10}  {'─'*4}")
for url, prob in zip(FAMOUS_URLS, famous_probs):
    famous_results[url] = float(prob)
    flag = "WARN" if prob >= 0.50 else "ok"
    print(f"  {url:<48} {prob:>10.4f}  {flag}")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 11  Comparison with old experimental model
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 11: Comparison with old experimental model\n{SEP2}")

old_summary: dict = {}

try:
    with open(OLD_META, encoding="utf-8") as f:
        old_meta = json.load(f)

    # Try to extract metrics from various known metadata structures
    def _pull(d, *keys):
        for k in keys:
            if k in d: return d[k]
        return None

    old_test  = old_meta.get("selected_model", {}).get("test", old_meta)
    old_calib = old_meta.get("calibration", {})

    old_summary = {
        "test_roc_auc": _pull(old_test, "roc_auc", "test_roc_auc"),
        "test_f1":      _pull(old_test, "f1",      "test_f1"),
        "test_fpr":     _pull(old_test, "fpr",     "test_fpr"),
        "model_type":   old_meta.get("selected_model", {}).get("name",
                        old_meta.get("model_type", "RandomForest")),
        "training_dataset": "malicious_phish.csv (phishing + 2016-benign)",
    }
    print(f"  OLD model metadata:")
    print(f"    Type          : {old_summary['model_type']}")
    print(f"    Dataset       : {old_summary['training_dataset']}")
    print(f"    Test ROC-AUC  : {old_summary['test_roc_auc']}")
    print(f"    Test F1       : {old_summary['test_f1']}")
    print(f"    Test FPR      : {old_summary['test_fpr']}")
except Exception as e:
    print(f"  Could not read old metadata: {e}")

# Run old model on calibration set for direct FPR comparison
old_calib_fpr = None
try:
    with open(OLD_MODEL, "rb") as f:
        old_model_obj = pickle.load(f)
    old_calib_probs = old_model_obj.predict_proba(X_calib)[:, 1]
    old_calib_fpr = float((old_calib_probs >= 0.50).mean())
    old_summary["calib_fpr_gte_050"] = old_calib_fpr
    print(f"\n  Calibration FPR comparison (>=0.50):")
    print(f"    OLD model : {old_calib_fpr:.2%}")
    print(f"    NEW model : {calib_metrics['pct_gte_050']:.2%}")
    improvement = old_calib_fpr - calib_metrics["pct_gte_050"]
    print(f"    Reduction : {improvement:.2%} {'↓ (improvement)' if improvement > 0 else '↑ (worse)'}")
except Exception as e:
    print(f"  Could not load old model for calibration comparison: {e}")

comparison = {
    "old_model": old_summary,
    "new_model": {
        "type":         f"{best_name} ({type(best_model).__name__})",
        "training_dataset": "malicious_phish.csv(phishing) + modern_benign_urls.csv",
        "test_roc_auc": test_metrics[best_name]["roc_auc"],
        "test_f1":      test_metrics[best_name]["f1"],
        "test_fpr":     test_metrics[best_name]["fpr"],
        "calib_fpr_gte_050": calib_metrics["pct_gte_050"],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 12  Save artifacts
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP2}\nSTEP 12: Saving artifacts\n{SEP2}")

with open(V2_MODEL, "wb") as f:
    pickle.dump(best_model, f)
model_mb = V2_MODEL.stat().st_size / (1024 * 1024)
print(f"  Saved model : {V2_MODEL.name}  ({model_mb:.2f} MB)")

TRAIN_END = datetime.datetime.now()

hp = {}
try:
    hp = {k: (v if isinstance(v, (int, float, str, bool, type(None))) else str(v))
          for k, v in best_model.get_params().items()}
except Exception:
    pass

meta_v2 = {
    "approval_status":         "EXPERIMENTAL — NOT APPROVED FOR PRODUCTION INTEGRATION",
    "phase":                   "2B.6",
    "training_timestamp":      TRAIN_START.isoformat(),
    "training_completed":      TRAIN_END.isoformat(),
    "training_duration_s":     round((TRAIN_END - TRAIN_START).total_seconds(), 1),
    "training_script":         "ml/phishing/train_phishing_url_model_v2.py",

    "source_datasets": {
        "phishing": {
            "file":             "ml/datasets/phishing/malicious_phish.csv",
            "filter":           "type=='phishing'",
            "label":            1,
            "url_count":        n_phish_total,
            "acquisition":      "user-provided (2026-09)",
        },
        "benign": {
            "file":             "ml/datasets/phishing/modern_benign_urls.csv",
            "label":            0,
            "url_count":        n_benign_total,
            "sources":          45,
            "acquisition_dates": ["2026-09-24", "2026-09-25"],
        },
        "calibration_set":      {
            "file":             "ml/datasets/phishing/calibration_legitimate_urls.csv",
            "note":             "NOT used for training or model selection",
        },
    },

    "class_counts": {
        "total": n_total,
        "phishing": n_phish_total,
        "benign": n_benign_total,
        "class_ratio_phish_to_benign": round(n_phish_total / max(n_benign_total, 1), 4),
    },

    "split": {
        "method":               "registrable-domain-grouped stratified (70/15/15)",
        "random_state":         42,
        "train_urls":           int(len(df_train)),
        "train_phishing":       int((df_train["label"] == 1).sum()),
        "train_benign":         int((df_train["label"] == 0).sum()),
        "train_domains":        int(df_train["reg_domain"].nunique()),
        "val_urls":             int(len(df_val)),
        "val_phishing":         int((df_val["label"] == 1).sum()),
        "val_benign":           int((df_val["label"] == 0).sum()),
        "val_domains":          int(df_val["reg_domain"].nunique()),
        "test_urls":            int(len(df_test)),
        "test_phishing":        int((df_test["label"] == 1).sum()),
        "test_benign":          int((df_test["label"] == 0).sum()),
        "test_domains":         int(df_test["reg_domain"].nunique()),
        "domain_overlap_verified": True,
        "url_overlap_verified":    True,
        "train_val_domain_overlap":  0,
        "train_test_domain_overlap": 0,
        "val_test_domain_overlap":   0,
        "train_val_url_overlap":     0,
        "train_test_url_overlap":    0,
        "val_test_url_overlap":      0,
    },

    "features": {
        "count":     len(FEATURE_NAMES),
        "names":     list(FEATURE_NAMES),
        "extractor": "api_detection.features.url_features.extract_url_features",
        "modified_from_v1": False,
        "feature_types":    "URL-string-only, zero network I/O",
    },

    "all_candidates": {
        name: {"val": val_metrics[name], "test": test_metrics[name]}
        for name in CANDIDATES
    },

    "selected_model": {
        "name":               best_name,
        "type":               type(best_model).__name__,
        "selection_criterion": "validation ROC-AUC",
        "hyperparameters":    hp,
        "val":                val_metrics[best_name],
        "test":               test_metrics[best_name],
    },

    "subgroup_metrics": subgroup_results,

    "calibration": {
        "dataset":  "ml/datasets/phishing/calibration_legitimate_urls.csv",
        "note":     "NOT used for training or model selection",
        "metrics":  calib_metrics,
        "famous_domains": famous_results,
    },

    "comparison_vs_v1": comparison,

    "software_versions": {
        "sklearn":  sklearn.__version__,
        "xgboost":  xgb.__version__,
        "numpy":    np.__version__,
        "pandas":   pd.__version__,
        "python":   sys.version.split()[0],
    },
}

with open(V2_META, "w", encoding="utf-8") as f:
    json.dump(meta_v2, f, indent=2, cls=NpEncoder)
print(f"  Saved meta  : {V2_META.name}  ({V2_META.stat().st_size / 1024:.1f} KB)")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 13  Final report
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{SEP}")
print("FINAL REPORT — PHASE 2B.6")
print(SEP)
print(f"  Completed : {TRAIN_END.isoformat(timespec='seconds')}")
print(f"  Duration  : {(TRAIN_END - TRAIN_START).total_seconds():.0f}s")

print(f"\n  ── DATA ──")
print(f"  Total URLs (cleaned) : {n_total:,}")
print(f"  Phishing             : {n_phish_total:,}")
print(f"  Benign               : {n_benign_total:,}")
print(f"  Class ratio          : {n_phish_total/n_benign_total:.3f}:1")

print(f"\n  ── SPLIT ──")
print(f"  Train : {len(df_train):,}  (ph={int((df_train.label==1).sum()):,}  be={int((df_train.label==0).sum()):,}  dom={df_train.reg_domain.nunique():,})")
print(f"  Val   : {len(df_val):,}   (ph={int((df_val.label==1).sum()):,}  be={int((df_val.label==0).sum()):,}  dom={df_val.reg_domain.nunique():,})")
print(f"  Test  : {len(df_test):,}   (ph={int((df_test.label==1).sum()):,}  be={int((df_test.label==0).sum()):,}  dom={df_test.reg_domain.nunique():,})")
print(f"  Domain overlap (all pairs) : 0  ✓")
print(f"  URL overlap    (all pairs) : 0  ✓")

print(f"\n  ── ALL CANDIDATE VALIDATION ──")
for cname in CANDIDATES:
    m = val_metrics[cname]
    sel = "← SELECTED" if cname == best_name else ""
    print(f"  {cname:3s}: AUC={m['roc_auc']:.4f}  F1={m['f1']:.4f}  FPR={m['fpr']:.4f}  PR-AUC={m['pr_auc']:.4f}  {sel}")

print(f"\n  ── ALL CANDIDATE TEST ──")
for cname in CANDIDATES:
    m = test_metrics[cname]
    sel = "← SELECTED" if cname == best_name else ""
    print(f"  {cname:3s}: AUC={m['roc_auc']:.4f}  F1={m['f1']:.4f}  Prec={m['precision']:.4f}  Rec={m['recall']:.4f}  FPR={m['fpr']:.4f}  FNR={m['fnr']:.4f}  {sel}")

print(f"\n  ── SELECTED MODEL TEST (detail) ──")
m = test_metrics[best_name]
print(f"  Model : {best_name} ({type(best_model).__name__})")
print(f"  Accuracy  : {m['accuracy']:.4f}")
print(f"  Precision : {m['precision']:.4f}")
print(f"  Recall    : {m['recall']:.4f}")
print(f"  F1        : {m['f1']:.4f}")
print(f"  ROC-AUC   : {m['roc_auc']:.4f}")
print(f"  PR-AUC    : {m['pr_auc']:.4f}")
print(f"  FPR       : {m['fpr']:.4f}")
print(f"  FNR       : {m['fnr']:.4f}")
print(f"  TP={m['tp']:,}  TN={m['tn']:,}  FP={m['fp']:,}  FN={m['fn']:,}")

print(f"\n  ── CALIBRATION ──")
print(f"  n={calib_metrics['n']:,}  mean={calib_metrics['mean']:.4f}  median={calib_metrics['median']:.4f}")
print(f"  min={calib_metrics['min']:.4f}  max={calib_metrics['max']:.4f}")
print(f"  >=0.50: {calib_metrics['pct_gte_050']:.2%}  >=0.70: {calib_metrics['pct_gte_070']:.2%}  "
      f">=0.80: {calib_metrics['pct_gte_080']:.2%}  >=0.90: {calib_metrics['pct_gte_090']:.2%}  "
      f">=0.95: {calib_metrics['pct_gte_095']:.2%}")

print(f"\n  ── FAMOUS DOMAINS ──")
for url, prob in famous_results.items():
    flag = "WARN" if prob >= 0.50 else "ok"
    print(f"  {url:<48} {prob:.4f}  [{flag}]")

print(f"\n  ── VS OLD MODEL ──")
print(f"  OLD : dataset=malicious_phish.csv(2016-benign+phishing)  "
      f"AUC={old_summary.get('test_roc_auc')}  F1={old_summary.get('test_f1')}  "
      f"FPR={old_summary.get('test_fpr')}  CalibFPR={old_calib_fpr}")
print(f"  NEW : dataset=malicious_phish.csv(phishing)+modern_benign  "
      f"AUC={test_metrics[best_name]['roc_auc']:.4f}  F1={test_metrics[best_name]['f1']:.4f}  "
      f"FPR={test_metrics[best_name]['fpr']:.4f}  CalibFPR={calib_metrics['pct_gte_050']:.4f}")

print(f"\n  ── ARTIFACTS ──")
print(f"  {V2_MODEL.name}  ({model_mb:.2f} MB)")
print(f"  {V2_META.name}   ({V2_META.stat().st_size/1024:.1f} KB)")
print(f"  OLD model intact: {OLD_MODEL.name}  ({OLD_MODEL.stat().st_size/1024/1024:.2f} MB)")

print(f"\n{SEP}")
print("STATUS : EXPERIMENTAL — NOT APPROVED FOR PRODUCTION INTEGRATION")
print("ACTION : DO NOT start Phase 2C. Awaiting explicit approval.")
print("NOTE   : Old model not deleted or overwritten.")
print(SEP)
