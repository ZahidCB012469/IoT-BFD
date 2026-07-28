# IoT Botnet Flow Dataset (IoT-BFD)

**IoT-BFD** is a balanced, flow-level dataset designed for the behavioral detection of encrypted IoT botnet Command-and-Control (C2) communication. 

This repository contains the verified dataset, the extraction methodology scripts, and the Jupyter notebooks used for model training and evaluation.

## Why IoT-BFD?
IoT-BFD is **not a simple relabeling of the IoT-23 dataset**. While raw PCAPs are sourced from IoT-23, the contribution extends substantially beyond label reassignment — encompassing:
1. **Packet-to-flow conversion** via 3-tuple bidirectional aggregation with a 120-second idle timeout.
2. **C2-phase isolation** from mixed malicious categories (separating C2 beaconing from DDoS and scanning traffic).
3. A novel **four-stage cascade label mapping pipeline** to transfer packet-level MCFP ground truth to aggregated flow records with majority voting.
4. Bespoke engineering of **15 encryption-agnostic features**.
5. Rigorous quality filtering and **class balancing** via under-sampling.

The resulting dataset is a fundamentally different resource, purpose-built for flow-level behavioral C2 detection in encrypted traffic scenarios without requiring payload inspection.

## Repository Structure

```text
.
├── dataset/
│   └── fair_balanced_cascade_verified_dataset.csv  # The final verified 2,796-flow dataset
├── scripts/
│   ├── apply_cascade_labeling.py                   # 4-stage cascade label mapping logic
│   ├── extract_unencrypted_mirai_features.py       # Flow extraction logic (malware)
│   ├── extract_benign_features_120s.py             # Flow extraction logic (benign)
│   └── benchmark_runner.py                         # Automated multi-classifier benchmarking
└── notebooks/
    ├── train_fair_balanced_rf.ipynb                # Random Forest model training and evaluation
    └── dataset_evaluation.ipynb                    # SHAP analysis, t-SNE, and feature distributions
```

## The Dataset
The final dataset (`dataset/fair_balanced_cascade_verified_dataset.csv`) contains **2,796 flows** (1,398 Benign, 1,398 C&C).

It contains the following 15 encryption-agnostic behavioral features:
* **Temporal:** `flow_duration`, `iat_mean`, `iat_min`, `iat_max`, `iat_std`, `flow_periodicity`
* **Volume:** `packet_count_fwd`, `packet_count_bwd`, `byte_count_fwd`, `byte_count_bwd`
* **Packet Size:** `packet_size_mean`, `packet_size_min`, `packet_size_max`, `packet_size_std`
* **Directional:** `directionality_ratio`

*(Note: `unique_endpoints`, `tcp_window_size_mean`, and `ip_ttl_mean` are also included in the CSV but were not used in the final timing-only cross-encryption benchmark).*

## Usage
To load the dataset and train a model using pandas and scikit-learn:

```python
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Load dataset
df = pd.read_csv('dataset/fair_balanced_cascade_verified_dataset.csv')

# Prepare features and labels
X = df.drop(columns=['src_ip', 'dst_ip', 'dst_port', 'protocol', 'label'])
y = df['label'].map({'Benign': 0, 'C&C': 1})

# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Model
clf = RandomForestClassifier(n_estimators=200, class_weight='balanced')
clf.fit(X_train, y_train)

print(f"Accuracy: {clf.score(X_test, y_test)}")
```


