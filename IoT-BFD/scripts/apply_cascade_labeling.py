#!/usr/bin/env python3
"""
Apply Cascade Label Mapping to unencrypted_mirai_features.csv

This script applies the four-stage cascade label mapping described in the paper
to verify C2 labels against MCFP ground truth, rather than hard-coding all
flows from malware PCAPs as C&C.

Cascade stages:
  1. Forward 4-tuple match (src_ip, dst_ip, dst_port, protocol)
  2. Reverse 4-tuple match (swap src/dst IP)  
  3. Forward 3-tuple fallback (remove port)
  4. Reverse 3-tuple fallback

Majority voting resolves conflicts when multiple MCFP records match one key.
"""

import os
import re
import pandas as pd
import numpy as np
from collections import Counter
from tqdm import tqdm

# ─── Paths ───────────────────────────────────────────────────────────────────
FEATURES_PATH = "/home/ioht22/contiki-ng/FYP/pcaps/finalcsv/unencrypted_mirai_features.csv"
BENIGN_PATH   = "/home/ioht22/contiki-ng/FYP/pcaps/finalcsv/timed_benign_features_expanded.csv"
MCFP_DIR      = "/home/ioht22/contiki-ng/FYP/pcaps/mcfp_labels"
OUTPUT_DIR     = "/home/ioht22/contiki-ng/FYP/pcaps/finalcsv"

# MCFP label files matching the PCAPs used in extract_unencrypted_mirai_features.py
MCFP_FILES = {
    'mirai1':     os.path.join(MCFP_DIR, 'mirai1_conn.log.labeled'),
    'mirai34':    os.path.join(MCFP_DIR, 'mirai34_conn.log.labeled'),
    'torii1':     os.path.join(MCFP_DIR, 'torii1_conn.log.labeled'),
    'torii2':     os.path.join(MCFP_DIR, 'torii2_conn.log.labeled'),
    'linuxmirai': os.path.join(MCFP_DIR, 'linuxmirai_conn.log.labeled'),
}

def build_lookup_dicts(mcfp_path):
    """
    Parse an MCFP conn.log.labeled file and build 4 lookup dictionaries.
    Only keeps entries labeled as Benign or Malicious+C&C/Heartbeat.
    Uses majority voting (Counter.most_common) for duplicate keys.
    """
    raw_4tuple_fwd = {}  # key -> list of labels
    raw_4tuple_rev = {}
    raw_3tuple_fwd = {}
    raw_3tuple_rev = {}
    
    benign_count = 0
    cc_count = 0
    other_malicious = 0
    skipped = 0
    
    with open(mcfp_path, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue
            
            parts = line.strip().split('\t')
            if len(parts) < 20:
                skipped += 1
                continue
            
            src_ip    = parts[2]
            src_port  = parts[3]
            dst_ip    = parts[4]
            dst_port  = parts[5]
            proto     = parts[6].upper()
            
            # Parse label from last columns
            # Format: ... \t MainLabel \t DetailLabel
            last_part = parts[-1] if len(parts) == 23 else '\t'.join(parts[20:])
            last_parts = re.split(r'\s{2,}|\t', last_part.strip())
            
            # Try to get main_label and det_label
            if len(parts) >= 23:
                main_label = parts[21].lower().strip()
                det_label = parts[22].lower().strip() if len(parts) > 22 else '-'
            elif len(last_parts) >= 2:
                main_label = last_parts[-2].lower().strip()
                det_label = last_parts[-1].lower().strip()
            else:
                lower_part = last_part.lower()
                if 'benign' in lower_part:
                    main_label = 'benign'
                    det_label = '-'
                elif 'malicious' in lower_part:
                    main_label = 'malicious'
                    det_label = 'c&c' if 'c&c' in lower_part else '-'
                else:
                    skipped += 1
                    continue
            
            # Determine final label (only keep Benign and C&C)
            if 'benign' in main_label:
                final_label = 'Benign'
                benign_count += 1
            elif 'malicious' in main_label and ('c&c' in det_label or 'heartbeat' in det_label):
                final_label = 'C&C'
                cc_count += 1
            elif 'malicious' in main_label:
                other_malicious += 1
                continue  # Skip DDoS, scanning, etc.
            else:
                skipped += 1
                continue
            
            # Build keys
            key_4_fwd = f"{src_ip}|{dst_ip}|{dst_port}|{proto}"
            key_4_rev = f"{dst_ip}|{src_ip}|{src_port}|{proto}"
            key_3_fwd = f"{src_ip}|{dst_ip}|{proto}"
            key_3_rev = f"{dst_ip}|{src_ip}|{proto}"
            
            # Collect labels for majority voting
            raw_4tuple_fwd.setdefault(key_4_fwd, []).append(final_label)
            raw_4tuple_rev.setdefault(key_4_rev, []).append(final_label)
            raw_3tuple_fwd.setdefault(key_3_fwd, []).append(final_label)
            raw_3tuple_rev.setdefault(key_3_rev, []).append(final_label)
    
    # Apply majority voting
    def majority_vote(raw_dict):
        return {k: Counter(v).most_common(1)[0][0] for k, v in raw_dict.items()}
    
    lookup_4_fwd = majority_vote(raw_4tuple_fwd)
    lookup_4_rev = majority_vote(raw_4tuple_rev)
    lookup_3_fwd = majority_vote(raw_3tuple_fwd)
    lookup_3_rev = majority_vote(raw_3tuple_rev)
    
    return lookup_4_fwd, lookup_4_rev, lookup_3_fwd, lookup_3_rev, {
        'benign': benign_count,
        'cc': cc_count,
        'other_malicious': other_malicious,
        'skipped': skipped
    }


def apply_cascade(df, lookup_4_fwd, lookup_4_rev, lookup_3_fwd, lookup_3_rev):
    """
    Apply 4-stage cascade label mapping to a DataFrame of flows.
    Returns the DataFrame with a 'cascade_label' column and stage tracking.
    """
    df = df.copy()
    
    # Build matching keys
    df['dst_port_first'] = df['dst_port'].astype(str).str.split(',').str[0]
    df['key_4'] = df['src_ip'] + '|' + df['dst_ip'] + '|' + df['dst_port_first'] + '|' + df['protocol']
    df['key_3'] = df['src_ip'] + '|' + df['dst_ip'] + '|' + df['protocol']
    
    # Stage 1: Forward 4-tuple
    df['cascade_label'] = df['key_4'].map(lookup_4_fwd)
    df['match_stage'] = np.where(df['cascade_label'].notna(), 1, np.nan)
    stage1_matched = df['cascade_label'].notna().sum()
    
    # Stage 2: Reverse 4-tuple
    unmatched = df['cascade_label'].isna()
    df.loc[unmatched, 'cascade_label'] = df.loc[unmatched, 'key_4'].map(lookup_4_rev)
    df.loc[unmatched & df['cascade_label'].notna(), 'match_stage'] = 2
    stage2_matched = df['cascade_label'].notna().sum() - stage1_matched
    
    # Stage 3: Forward 3-tuple fallback
    unmatched = df['cascade_label'].isna()
    df.loc[unmatched, 'cascade_label'] = df.loc[unmatched, 'key_3'].map(lookup_3_fwd)
    df.loc[unmatched & df['cascade_label'].notna(), 'match_stage'] = 3
    stage3_matched = df['cascade_label'].notna().sum() - stage1_matched - stage2_matched
    
    # Stage 4: Reverse 3-tuple fallback
    unmatched = df['cascade_label'].isna()
    df.loc[unmatched, 'cascade_label'] = df.loc[unmatched, 'key_3'].map(lookup_3_rev)
    df.loc[unmatched & df['cascade_label'].notna(), 'match_stage'] = 4
    stage4_matched = df['cascade_label'].notna().sum() - stage1_matched - stage2_matched - stage3_matched
    
    still_unmatched = df['cascade_label'].isna().sum()
    
    # Clean up
    df = df.drop(columns=['dst_port_first', 'key_4', 'key_3'])
    
    return df, {
        'stage1': stage1_matched,
        'stage2': stage2_matched,
        'stage3': stage3_matched,
        'stage4': stage4_matched,
        'unmatched': still_unmatched,
        'total': len(df)
    }


def main():
    print("=" * 70)
    print("CASCADE LABEL MAPPING FOR IoT-BFD")
    print("=" * 70)
    
    # ─── Step 1: Load the C2 features (currently all hard-coded as C&C) ──────
    print("\n[1/5] Loading unencrypted C2 features...")
    df_c2 = pd.read_csv(FEATURES_PATH)
    print(f"  Loaded: {len(df_c2)} flows (all currently labeled as '{df_c2['label'].iloc[0]}')")
    
    # ─── Step 2: Build lookup dictionaries from ALL MCFP files ───────────────
    print("\n[2/5] Building cascade lookup dictionaries from MCFP ground truth...")
    
    all_lookup_4_fwd = {}
    all_lookup_4_rev = {}
    all_lookup_3_fwd = {}
    all_lookup_3_rev = {}
    
    for name, path in MCFP_FILES.items():
        if not os.path.exists(path):
            print(f"  ⚠ {name}: file not found, skipping")
            continue
        
        print(f"  Processing {name}...", end=" ", flush=True)
        l4f, l4r, l3f, l3r, stats = build_lookup_dicts(path)
        
        # Merge into combined lookups
        all_lookup_4_fwd.update(l4f)
        all_lookup_4_rev.update(l4r)
        all_lookup_3_fwd.update(l3f)
        all_lookup_3_rev.update(l3r)
        
        print(f"C&C={stats['cc']:,}, Benign={stats['benign']:,}, "
              f"Other Malicious={stats['other_malicious']:,} (DDoS/scan/etc)")
    
    print(f"\n  Combined lookup sizes:")
    print(f"    4-tuple forward: {len(all_lookup_4_fwd):,} entries")
    print(f"    4-tuple reverse: {len(all_lookup_4_rev):,} entries")
    print(f"    3-tuple forward: {len(all_lookup_3_fwd):,} entries")
    print(f"    3-tuple reverse: {len(all_lookup_3_rev):,} entries")
    
    # ─── Step 3: Apply cascade to C2 flows ────────────────────────────────────
    print("\n[3/5] Applying 4-stage cascade label mapping...")
    df_labeled, stage_stats = apply_cascade(
        df_c2, all_lookup_4_fwd, all_lookup_4_rev, all_lookup_3_fwd, all_lookup_3_rev
    )
    
    print(f"\n  CASCADE MAPPING RESULTS:")
    print(f"  {'Stage':<30} {'Matched':>8}")
    print(f"  {'-'*40}")
    print(f"  {'Stage 1: Forward 4-tuple':<30} {stage_stats['stage1']:>8}")
    print(f"  {'Stage 2: Reverse 4-tuple':<30} {stage_stats['stage2']:>8}")
    print(f"  {'Stage 3: Forward 3-tuple':<30} {stage_stats['stage3']:>8}")
    print(f"  {'Stage 4: Reverse 3-tuple':<30} {stage_stats['stage4']:>8}")
    print(f"  {'-'*40}")
    total_matched = stage_stats['stage1'] + stage_stats['stage2'] + stage_stats['stage3'] + stage_stats['stage4']
    print(f"  {'Total matched':<30} {total_matched:>8}")
    print(f"  {'Unmatched (discarded)':<30} {stage_stats['unmatched']:>8}")
    
    # Show label distribution after cascade
    print(f"\n  LABEL DISTRIBUTION AFTER CASCADE:")
    matched = df_labeled[df_labeled['cascade_label'].notna()]
    print(matched['cascade_label'].value_counts().to_string(header=False))
    
    # ─── Step 4: Filter to keep only verified C&C flows ──────────────────────
    print("\n[4/5] Filtering to keep only verified C&C flows...")
    df_verified_cc = df_labeled[df_labeled['cascade_label'] == 'C&C'].copy()
    df_verified_cc['label'] = 'C&C'  # Keep original label column
    df_verified_cc = df_verified_cc.drop(columns=['cascade_label', 'match_stage'])
    
    print(f"  Verified C&C flows: {len(df_verified_cc)}")
    print(f"  Removed (Benign background / unmatched): {len(df_c2) - len(df_verified_cc)}")
    
    # Save verified C2 features
    verified_c2_path = os.path.join(OUTPUT_DIR, "unencrypted_mirai_features_cascade_verified.csv")
    df_verified_cc.to_csv(verified_c2_path, index=False)
    print(f"  Saved verified C2 features: {verified_c2_path}")
    
    # ─── Step 5: Create new balanced dataset ─────────────────────────────────
    print("\n[5/5] Creating new balanced dataset...")
    
    # Load benign features
    df_benign = pd.read_csv(BENIGN_PATH)
    print(f"  Benign flows available: {len(df_benign)}")
    print(f"  Verified C&C flows available: {len(df_verified_cc)}")
    
    # Balance: undersample to min of both
    target = min(len(df_benign), len(df_verified_cc))
    print(f"  Target per class: {target}")
    
    common_cols = [
        'src_ip', 'dst_ip', 'dst_port', 'protocol',
        'flow_duration', 'packet_count_fwd', 'packet_count_bwd',
        'byte_count_fwd', 'byte_count_bwd', 'iat_mean', 'iat_std',
        'iat_max', 'iat_min', 'packet_size_mean', 'packet_size_std',
        'packet_size_max', 'packet_size_min', 'flow_periodicity',
        'directionality_ratio', 'label'
    ]
    
    df_benign_sampled = df_benign.sample(n=target, random_state=42)
    df_cc_sampled = df_verified_cc.sample(n=target, random_state=42)
    
    # Ensure common columns exist
    available_cols = [c for c in common_cols if c in df_benign_sampled.columns and c in df_cc_sampled.columns]
    
    df_final = pd.concat([
        df_benign_sampled[available_cols],
        df_cc_sampled[available_cols]
    ], ignore_index=True)
    
    # Shuffle
    df_final = df_final.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save
    output_path = os.path.join(OUTPUT_DIR, "fair_balanced_cascade_verified_dataset.csv")
    df_final.to_csv(output_path, index=False)
    
    print(f"\n{'=' * 70}")
    print(f"FINAL RESULTS")
    print(f"{'=' * 70}")
    print(f"  New balanced dataset: {output_path}")
    print(f"  Total flows: {len(df_final)}")
    print(f"  Per class: {target}")
    print(df_final['label'].value_counts().to_string())
    print(f"\n  COMPARISON:")
    print(f"    Old dataset (hard-coded):    2,724 flows (1,362 + 1,362)")
    print(f"    New dataset (cascade-verified): {len(df_final)} flows ({target} + {target})")
    print(f"    Difference: {2724 - len(df_final)} fewer flows")


if __name__ == "__main__":
    main()
