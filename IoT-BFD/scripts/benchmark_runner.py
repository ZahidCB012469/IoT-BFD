"""
Benchmark runner for comparing models and resource metrics.
Saves results to: /home/ioht22/contiki-ng/FYP/results/benchmark_results.csv
"""

import os
import time
import psutil
import tracemalloc
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

RESULT_DIR = os.path.join(os.path.dirname(__file__), 'results')
os.makedirs(RESULT_DIR, exist_ok=True)

# Paths
DATASET_PATH = '/home/ioht22/contiki-ng/FYP/pcaps/finalcsv/multi_device_iot23_dataset.csv'
UNENC_PATH = '/home/ioht22/contiki-ng/FYP/pcaps/finalcsv/unencrypted_mirai_features.csv'
ENC_PATH = '/home/ioht22/contiki-ng/FYP/pcaps/finalcsv/encrypted_c2_features.csv'

print('Loading primary dataset:', DATASET_PATH)
if not os.path.exists(DATASET_PATH):
    raise FileNotFoundError(DATASET_PATH)

df = pd.read_csv(DATASET_PATH)
# Map labels to binary
if 'label' not in df.columns:
    raise ValueError('dataset missing label column')

df['label_bin'] = df['label'].map({'Benign':0, 'C&C':1, 'C2':1, 'Malicious':1}).fillna(0).astype(int)

# Drop obvious non-behavioural columns if present
drop_cols = ['src_ip','dst_ip','dst_port','ja3','ja3s','sni','tls_version','alpn','device_type','label']
X = df.drop(columns=[c for c in drop_cols if c in df.columns], errors='ignore')
X = X.select_dtypes(include=[np.number]).fillna(0)
y = df['label_bin']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)

models = {}
models['RandomForest'] = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1)
models['GradientBoosting'] = GradientBoostingClassifier(n_estimators=200, max_depth=10, random_state=42)
try:
    # pyrefly: ignore [missing-import]
    import xgboost as xgb
    models['XGBoost'] = xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss', n_jobs=-1, random_state=42)
except Exception:
    print('XGBoost not available; skipping')
models['MLP'] = MLPClassifier(hidden_layer_sizes=(128,64), max_iter=300, random_state=42)

results = []
proc = psutil.Process()

for name, model in models.items():
    print(f'Running benchmark for {name}')
    # Training time
    tracemalloc.start()
    t0 = time.perf_counter()
    model.fit(X_train, y_train)
    t1 = time.perf_counter()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    train_time = t1 - t0
    peak_mem_mb = peak / (1024**2)

    # Inference benchmark (batch)
    batch = X_test
    # warm-up
    _ = model.predict_proba(batch[:min(32,len(batch))]) if hasattr(model, 'predict_proba') else model.predict(batch[:min(32,len(batch))])
    start_mem = proc.memory_info().rss
    t0 = time.perf_counter()
    if hasattr(model, 'predict_proba'):
        preds_proba = model.predict_proba(batch)
        y_pred = (preds_proba[:,1] >= 0.5).astype(int)
    else:
        y_pred = model.predict(batch)
    t1 = time.perf_counter()
    end_mem = proc.memory_info().rss
    infer_time_total = t1 - t0
    infer_latency_ms = (infer_time_total / len(batch)) * 1000
    mem_delta_mb = (end_mem - start_mem) / (1024**2)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    results.append({
        'model': name,
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1': f1,
        'train_time_s': train_time,
        'peak_mem_mb_during_fit': peak_mem_mb,
        'inference_latency_ms_per_flow': infer_latency_ms,
        'inference_mem_delta_mb': mem_delta_mb,
        'confusion_matrix': cm.tolist()
    })

# Save results
out_df = pd.DataFrame(results)
out_path = os.path.join(RESULT_DIR, 'benchmark_results.csv')
out_df.to_csv(out_path, index=False)
print('Saved benchmark results to', out_path)

# Save confusion matrices separately as .npy
for r in results:
    cm_path = os.path.join(RESULT_DIR, f"cm_{r['model']}.npy")
    np.save(cm_path, np.array(r['confusion_matrix']))
print('Saved confusion matrices to', RESULT_DIR)

# If improved/unenc datasets exist, run matched experiment (train on unencrypted mirai + benign sample, test on encrypted if present)
if os.path.exists(UNENC_PATH):
    print('\nRunning matched-distribution improved PCAP experiment...')
    df_unenc = pd.read_csv(UNENC_PATH)
    # ensure df_unenc has labels; if missing, assume these are malicious C2 flows
    if 'label' not in df_unenc.columns and 'label_bin' not in df_unenc.columns:
        df_unenc['label_bin'] = 1
    elif 'label' in df_unenc.columns:
        df_unenc['label_bin'] = df_unenc['label'].map({'Benign':0, 'C&C':1, 'C2':1, 'Malicious':1}).fillna(1).astype(int)

    # create benign sample from main dataset
    benign = df[df['label_bin'] == 0]
    n = len(df_unenc)
    if n == 0:
        print('No unencrypted flows found in', UNENC_PATH)
    else:
        benign_sample = benign.sample(n=min(n, len(benign)), random_state=42)
        df_match = pd.concat([benign_sample.reset_index(drop=True), df_unenc.reset_index(drop=True)], ignore_index=True)
        # ensure label_bin exists
        if 'label_bin' not in df_match.columns:
            df_match['label_bin'] = np.where(df_match.index < len(benign_sample), 0, 1)
        Xm = df_match.select_dtypes(include=[np.number]).drop(columns=[c for c in ['label_bin','label'] if c in df_match.columns], errors='ignore').fillna(0)
        ym = df_match['label_bin'].astype(int)
        # if any NaNs present in ym, drop those rows
        mask_valid = ~pd.isna(ym)
        Xm = Xm.loc[mask_valid]
        ym = ym.loc[mask_valid]
        if len(ym.unique()) < 2:
            print('Matched dataset does not contain two classes after labeling; skipping matched experiment')
        else:
            Xtr, Xte, ytr, yte = train_test_split(Xm, ym, test_size=0.20, random_state=42, stratify=ym)
        matched_results = []
        for name, model in models.items():
            print('Matched experiment:', name)
            t0 = time.perf_counter()
            model.fit(Xtr, ytr)
            t1 = time.perf_counter()
            train_time = t1 - t0
            # inference
            t0 = time.perf_counter()
            if hasattr(model, 'predict_proba'):
                yp = (model.predict_proba(Xte)[:,1] >= 0.5).astype(int)
            else:
                yp = model.predict(Xte)
            t1 = time.perf_counter()
            acc = accuracy_score(yte, yp)
            prec = precision_score(yte, yp, zero_division=0)
            rec = recall_score(yte, yp, zero_division=0)
            f1s = f1_score(yte, yp, zero_division=0)
            cm = confusion_matrix(yte, yp)
            matched_results.append({'model': name, 'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1s, 'train_time_s': train_time, 'confusion_matrix': cm.tolist()})
        pd.DataFrame(matched_results).to_csv(os.path.join(RESULT_DIR, 'benchmark_matched_results.csv'), index=False)
        for r in matched_results:
            np.save(os.path.join(RESULT_DIR, f"cm_matched_{r['model']}.npy"), np.array(r['confusion_matrix']))
        print('Saved matched-distribution results to', RESULT_DIR)

print('Benchmark runner finished.')
