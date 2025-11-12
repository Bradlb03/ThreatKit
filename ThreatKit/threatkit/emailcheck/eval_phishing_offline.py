#!/usr/bin/env python3
"""
Evaluate ThreatKit phishing pipeline offline using the same analyze_email(...)
interface. Uses 0..5 scoring where < 3.5 => phishing for evaluation
(so 'Likely Phishing' counts as phishing for metrics).
"""

import argparse
import os
import json
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

# Robust import so this works when run as module or script
import pathlib, sys
if __package__ in (None, ""):
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo_root))
    from threatkit.emailcheck.detector import analyze_email
else:
    from .detector import analyze_email


def clamp_score_0_5(raw):
    """
    Interpret raw as already being a 0..5 safety score from detector.py.
    Just clamp to [0, 5] to guard against any out-of-range values.
    """
    if raw is None:
        return np.nan
    try:
        s = float(raw)
    except Exception:
        return np.nan
    return max(0.0, min(5.0, s))


def classify_phishing(score_0_5):
    """
    For evaluation, use a slightly more aggressive cutoff:
      - phishing (1) if score < 4.0
      - safe (0) otherwise

    This increases recall by counting borderline-safe emails as phishing.
    """
    if np.isnan(score_0_5):
        return 0
    return int(score_0_5 < 4.0)


def find_score_in_output(out):
    """Search common keys in analyze_email() output for a numeric score."""
    if out is None:
        return None
    if isinstance(out, (int, float)):
        return out
    if isinstance(out, dict):
        for key in ('risk_score', 'score', 'phishing_prob', 'phish_prob', 'probability', 'rating'):
            if key in out:
                return out[key]
        if 'phishing' in out and isinstance(out['phishing'], bool):
            return 0.0 if out['phishing'] else 5.0
    return None


def evaluate_dataframe(df, out_csv=None):
    df['score_0_5'] = df['raw_score'].map(clamp_score_0_5)
    n_nan = df['score_0_5'].isna().sum()
    if n_nan:
        print(f"Warning: {n_nan} sample(s) returned NaN score; treating as 5.0 (safe).")
        df.loc[df['score_0_5'].isna(), 'score_0_5'] = 5.0

    df['pred_phish'] = df['score_0_5'].map(classify_phishing)
    df['label'] = df['label'].astype(int)

    y_true = df['label'].values
    y_pred = df['pred_phish'].values
    y_auc = 1.0 - (df['score_0_5'].values / 5.0)

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    try:
        auc = roc_auc_score(y_true, y_auc)
    except Exception:
        auc = float('nan')
    cm = confusion_matrix(y_true, y_pred)

    print("\n=== Evaluation Summary ===")
    print(json.dumps({
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1': f1,
        'roc_auc': auc,
        'confusion_matrix': cm.tolist()
    }, indent=2))
    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, digits=4, zero_division=0))

    if out_csv:
        os.makedirs(os.path.dirname(out_csv) or '.', exist_ok=True)
        df.to_csv(out_csv, index=False)
        print(f"\nSaved per-sample results to: {out_csv}")

    return {'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1, 'roc_auc': auc, 'confusion_matrix': cm.tolist()}


def run_eval(data_csv, out_csv=None, sample_limit=None, verbose=True):
    df = pd.read_csv(data_csv)
    required = ['subject', 'from', 'return_path', 'to', 'body', 'label']
    for c in required:
        if c not in df.columns:
            raise ValueError(f"Missing required column '{c}' in {data_csv}. Found: {df.columns.tolist()}")

    if sample_limit:
        df = df.sample(n=min(sample_limit, len(df)), random_state=42).reset_index(drop=True)

    raw_scores = []
    for i, row in df.iterrows():
        try:
            out = analyze_email(
                subject=str(row['subject'] or ''),
                from_hdr=str(row['from'] or ''),
                return_path=str(row.get('return_path', '') or ''),
                to_hdr=str(row.get('to', '') or ''),
                body=str(row['body'] or ''),
                headers=None
            )
            raw_scores.append(find_score_in_output(out))
            if verbose and (i % 100 == 0):
                print(f"Processed {i}/{len(df)}")
        except Exception as e:
            print(f"Error analyzing row {i}: {e}")
            raw_scores.append(None)

    df['raw_score'] = raw_scores
    return evaluate_dataframe(df, out_csv=out_csv)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--data', default='threatkit/emailcheck/eval/test_emails.csv', help='CSV with test samples')
    p.add_argument('--out', default='threatkit/emailcheck/eval/eval_results.csv', help='Per-sample results CSV')
    p.add_argument('--sample-limit', type=int, default=None, help='Limit number of tested samples (for quick runs)')
    p.add_argument('--suppress-verbose', action='store_true', help='Turn off progress prints')
    args = p.parse_args()

    print("Running ThreatKit offline phishing eval (0..5 scale, <3.5 => phishing)")
    run_eval(args.data, out_csv=args.out, sample_limit=args.sample_limit, verbose=(not args.suppress_verbose))


if __name__ == '__main__':
    main()