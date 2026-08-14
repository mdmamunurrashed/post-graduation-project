# ============================================================
# WebSentinel ML — Random Forest Training Script (v2)
# Extracts our own 30 features from dataset URLs
# This ensures perfect alignment between training and prediction
# Usage: python train_rf.py
# ============================================================

import pandas as pd
import numpy as np
import joblib
import json
import os
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report,
    roc_auc_score
)
from sklearn.preprocessing import StandardScaler
from features import extract_features, get_feature_names

print("=" * 60)
print("  WebSentinel ML — Random Forest Training v2")
print("  (Using our own 30 features for perfect alignment)")
print("=" * 60)

# Step 1: Load Dataset
print("\n[1/7] Loading dataset...")
DATA_DIR  = 'data'
csv_files = [f for f in os.listdir(DATA_DIR) if f.endswith('.csv')]
if not csv_files:
    print("No CSV found in data/ folder!")
    exit(1)
csv_path = os.path.join(DATA_DIR, csv_files[0])
df = pd.read_csv(csv_path)
print(f"   Loaded {len(df)} rows, {len(df.columns)} columns")

# Step 2: Find URL and Label columns
print("\n[2/7] Identifying columns...")
url_col   = None
label_col = None
for col in df.columns:
    if col.lower() in ['url', 'urls', 'website', 'link']:
        url_col = col
    if col.lower() in ['label', 'status', 'type', 'class', 'phishing', 'result']:
        label_col = col
if url_col is None:   url_col   = df.columns[0]
if label_col is None: label_col = df.columns[-1]
df = df.dropna(subset=[url_col, label_col])
print(f"   URL: '{url_col}', Label: '{label_col}', Rows: {len(df)}")

# Step 3: Extract Our 30 Features from URLs
print(f"\n[3/7] Extracting 30 features from {len(df)} URLs...")
X = []
y_raw = []
failed = 0
for i, (_, row) in enumerate(df.iterrows()):
    if i % 2000 == 0 and i > 0:
        print(f"   Progress: {i}/{len(df)}...")
    url = str(row[url_col]).strip()
    if not url or url == 'nan' or '.' not in url:
        continue
    try:
        feats = extract_features(url)
        if len(feats) == 30:
            X.append(feats)
            y_raw.append(row[label_col])
    except:
        failed += 1

print(f"   Done: {len(X)} URLs, {failed} failed")
X = np.array(X, dtype=float)

# Step 4: Prepare Labels
print("\n[4/7] Preparing labels...")
unique_labels = set(y_raw)
label_map = {}
for label in unique_labels:
    ls = str(label).lower().strip()
    label_map[label] = 1 if ls in ['phishing','phishy','1','1.0','bad','malicious','yes','positive'] else 0
y = np.array([label_map.get(l, 0) for l in y_raw])
print(f"   Phishing: {sum(y==1):,} | Legitimate: {sum(y==0):,}")
os.makedirs('models', exist_ok=True)
with open('models/label_map.json', 'w') as f:
    json.dump({str(k): v for k, v in label_map.items()}, f)

# Step 5: Split
print("\n[5/7] Splitting dataset (80/20)...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"   Train: {len(X_train):,} | Test: {len(X_test):,}")

# Step 6: Train
print("\n[6/7] Training models...")
scaler         = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

# Random Forest
print("   Training Random Forest (200 trees)...")
rf_model = RandomForestClassifier(n_estimators=200, max_depth=25, min_samples_split=4,
    min_samples_leaf=2, max_features='sqrt', random_state=42, n_jobs=-1, class_weight='balanced')
rf_model.fit(X_train_scaled, y_train)
rf_pred = rf_model.predict(X_test_scaled)
rf_prob = rf_model.predict_proba(X_test_scaled)[:, 1]
rf_acc  = accuracy_score(y_test, rf_pred)
rf_auc  = roc_auc_score(y_test, rf_prob)
print(f"   RF — Accuracy: {rf_acc*100:.2f}% | AUC: {rf_auc:.4f}")

# Gradient Boosting
print("   Training Gradient Boosting...")
gb_model = GradientBoostingClassifier(n_estimators=150, learning_rate=0.1, max_depth=6, random_state=42)
gb_model.fit(X_train_scaled, y_train)
gb_pred = gb_model.predict(X_test_scaled)
gb_prob = gb_model.predict_proba(X_test_scaled)[:, 1]
gb_acc  = accuracy_score(y_test, gb_pred)
gb_auc  = roc_auc_score(y_test, gb_prob)
print(f"   GB — Accuracy: {gb_acc*100:.2f}% | AUC: {gb_auc:.4f}")

# Ensemble
ensemble_prob = (rf_prob * 0.6) + (gb_prob * 0.4)
ensemble_pred = (ensemble_prob >= 0.5).astype(int)
ens_acc = accuracy_score(y_test, ensemble_pred)
ens_auc = roc_auc_score(y_test, ensemble_prob)
print(f"   Ensemble (RF60+GB40) — Accuracy: {ens_acc*100:.2f}% | AUC: {ens_auc:.4f}")

# Step 7: Evaluate
print("\n[7/7] Full evaluation...")
print(f"\n   {'='*50}")
for name, pred, prob, acc, auc in [
    ('Random Forest',     rf_pred, rf_prob, rf_acc, rf_auc),
    ('Gradient Boosting', gb_pred, gb_prob, gb_acc, gb_auc),
    ('Ensemble',          ensemble_pred, ensemble_prob, ens_acc, ens_auc),
]:
    p  = precision_score(y_test, pred)
    r  = recall_score(y_test, pred)
    f1 = f1_score(y_test, pred)
    cm = confusion_matrix(y_test, pred)
    print(f"\n   {name}:")
    print(f"     Accuracy: {acc*100:.2f}% | Precision: {p*100:.2f}% | Recall: {r*100:.2f}% | F1: {f1*100:.2f}% | AUC: {auc:.4f}")
    print(f"     TN={cm[0][0]:,}  FP={cm[0][1]:,}  FN={cm[1][0]:,}  TP={cm[1][1]:,}")

# Cross validation
print("\n   5-fold Cross Validation (Random Forest)...")
cv  = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cvs = cross_val_score(rf_model, X_train_scaled, y_train, cv=cv, scoring='accuracy')
print(f"   CV Accuracy: {cvs.mean()*100:.2f}% (+/- {cvs.std()*100:.2f}%)")

# Feature importance
print("\n   Top 10 Most Important Features:")
feat_names  = get_feature_names()
importances = rf_model.feature_importances_
feat_imp    = sorted(zip(feat_names, importances), key=lambda x: x[1], reverse=True)
for fname, imp in feat_imp[:10]:
    bar = '█' * int(imp * 60)
    print(f"   {fname:<28} {imp:.4f}  {bar}")

# Save models
print("\n   Saving models...")
joblib.dump(rf_model, 'models/random_forest.pkl')
joblib.dump(gb_model, 'models/gradient_boosting.pkl')
joblib.dump(scaler,   'models/scaler_rf.pkl')
with open('models/feature_names.json', 'w') as f:
    json.dump(feat_names, f)
with open('models/dataset_feature_cols.json', 'w') as f:
    json.dump(feat_names, f)

metrics = {
    'random_forest':     {'accuracy': round(rf_acc,4),  'precision': round(precision_score(y_test,rf_pred),4),  'recall': round(recall_score(y_test,rf_pred),4),  'f1': round(f1_score(y_test,rf_pred),4),  'auc': round(rf_auc,4),  'cv_mean': round(cvs.mean(),4), 'cv_std': round(cvs.std(),4)},
    'gradient_boosting': {'accuracy': round(gb_acc,4),  'precision': round(precision_score(y_test,gb_pred),4),  'recall': round(recall_score(y_test,gb_pred),4),  'f1': round(f1_score(y_test,gb_pred),4),  'auc': round(gb_auc,4)},
    'ensemble':          {'accuracy': round(ens_acc,4), 'precision': round(precision_score(y_test,ensemble_pred),4), 'recall': round(recall_score(y_test,ensemble_pred),4), 'f1': round(f1_score(y_test,ensemble_pred),4), 'auc': round(ens_auc,4)},
    'train_samples': len(X_train), 'test_samples': len(X_test), 'total_features': 30
}
with open('models/rf_metrics.json', 'w') as f:
    json.dump(metrics, f, indent=2)

print("\n" + "=" * 60)
print("  Training Complete!")
print(f"  Random Forest:     {rf_acc*100:.2f}%")
print(f"  Gradient Boosting: {gb_acc*100:.2f}%")
print(f"  Ensemble:          {ens_acc*100:.2f}%")
print("=" * 60)
print("  Next: python train_lstm.py")
