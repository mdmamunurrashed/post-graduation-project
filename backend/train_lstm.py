# ============================================================
# WebSentinel ML — LSTM Training Script
# Trains an LSTM neural network on raw URL characters
# LSTM learns sequential patterns in URL character sequences
# Run after train_rf.py
# Usage: python train_lstm.py
# ============================================================

import numpy as np
import pandas as pd
import os
import json
import joblib
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import (
    Embedding, LSTM, Dense, Dropout, Bidirectional
)
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

print("=" * 60)
print("  WebSentinel ML — LSTM Training")
print("=" * 60)

# ── Configuration ────────────────────────────────────────────
MAX_URL_LENGTH = 200    # max characters per URL
VOCAB_SIZE     = 100    # character vocabulary size
EMBEDDING_DIM  = 32     # embedding dimensions
LSTM_UNITS     = 64     # LSTM units
BATCH_SIZE     = 64
EPOCHS         = 20     # max epochs (early stopping will kick in)

# ── Step 1: Load Dataset ─────────────────────────────────────
print("\n[1/6] Loading dataset...")

DATA_DIR  = 'data'
csv_files = [f for f in os.listdir(DATA_DIR) if f.endswith('.csv')]
csv_path  = os.path.join(DATA_DIR, csv_files[0])

df = pd.read_csv(csv_path)
print(f"   Loaded {len(df)} rows")

# ── Step 2: Find URL and Label columns ──────────────────────
print("\n[2/6] Identifying columns...")

url_col   = None
label_col = None

for col in df.columns:
    if col.lower() in ['url', 'urls', 'website', 'link']:
        url_col = col
    if col.lower() in ['label', 'status', 'type', 'class', 'phishing', 'result']:
        label_col = col

if url_col is None:
    url_col = df.columns[0]
if label_col is None:
    label_col = df.columns[-1]

print(f"   URL column:   '{url_col}'")
print(f"   Label column: '{label_col}'")

# ── Step 3: Prepare URL sequences ───────────────────────────
print("\n[3/6] Preparing URL character sequences...")

urls = df[url_col].astype(str).tolist()

# Tokenize at character level
# LSTM reads URLs character by character — learns patterns like "paypal-login"
tokenizer = Tokenizer(num_words=VOCAB_SIZE, char_level=True, oov_token='<OOV>')
tokenizer.fit_on_texts(urls)

sequences = tokenizer.texts_to_sequences(urls)
X = pad_sequences(sequences, maxlen=MAX_URL_LENGTH, padding='post', truncating='post')

print(f"   URLs processed: {len(X)}")
print(f"   Sequence shape: {X.shape}")
print(f"   Vocabulary size: {len(tokenizer.word_index)} characters")

# ── Step 4: Prepare Labels ───────────────────────────────────
print("\n[4/6] Preparing labels...")

y = df[label_col].values
unique_labels = set(y)

# Convert to 0/1
label_map = {}
for label in unique_labels:
    label_str = str(label).lower()
    if label_str in ['phishing', 'phishy', '1', 'bad', 'malicious', 'yes']:
        label_map[label] = 1
    else:
        label_map[label] = 0

y = np.array([label_map.get(label, 0) for label in y])

print(f"   Phishing:    {sum(y==1)} samples")
print(f"   Legitimate:  {sum(y==0)} samples")

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"   Training: {len(X_train)}, Testing: {len(X_test)}")

# ── Step 5: Build LSTM Model ─────────────────────────────────
print("\n[5/6] Building LSTM model...")

model = Sequential([
    # Embedding layer — converts character IDs to vectors
    Embedding(
        input_dim=VOCAB_SIZE,
        output_dim=EMBEDDING_DIM,
        input_length=MAX_URL_LENGTH
    ),

    # Bidirectional LSTM — reads URL forwards AND backwards
    Bidirectional(LSTM(
        LSTM_UNITS,
        return_sequences=True,
        dropout=0.2,
        recurrent_dropout=0.2
    )),

    # Second LSTM layer for deeper pattern learning
    Bidirectional(LSTM(
        32,
        dropout=0.2,
        recurrent_dropout=0.2
    )),

    # Dense layers for final classification
    Dense(64, activation='relu'),
    Dropout(0.3),
    Dense(32, activation='relu'),
    Dropout(0.2),

    # Output: single neuron, sigmoid = probability 0-1
    Dense(1, activation='sigmoid')
])

model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy']
)

model.summary()

# ── Step 6: Train Model ──────────────────────────────────────
print("\n[6/6] Training LSTM model...")
print("   Early stopping enabled — will stop if no improvement after 3 epochs")

os.makedirs('models', exist_ok=True)

callbacks = [
    # Stop training if validation loss doesn't improve
    EarlyStopping(
        monitor='val_loss',
        patience=3,
        restore_best_weights=True,
        verbose=1
    ),
    # Save best model automatically
    ModelCheckpoint(
        'models/lstm_best.keras',
        monitor='val_accuracy',
        save_best_only=True,
        verbose=1
    )
]

history = model.fit(
    X_train, y_train,
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    validation_split=0.15,
    callbacks=callbacks,
    verbose=1
)

# ── Evaluate ─────────────────────────────────────────────────
print("\n   Evaluating on test set...")

y_prob = model.predict(X_test, verbose=0).flatten()
y_pred = (y_prob >= 0.5).astype(int)

accuracy = accuracy_score(y_test, y_pred)

print(f"\n   📊 LSTM MODEL PERFORMANCE")
print(f"   {'─' * 35}")
print(f"   Test Accuracy: {accuracy*100:.2f}%")
print(f"\n{classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'])}")

# ── Save Model & Tokenizer ───────────────────────────────────
print("   Saving model and tokenizer...")

model.save('models/lstm_model.keras')
joblib.dump(tokenizer, 'models/lstm_tokenizer.pkl')

# Save config for Flask API
lstm_config = {
    'max_url_length': MAX_URL_LENGTH,
    'vocab_size':     VOCAB_SIZE,
    'accuracy':       round(accuracy, 4)
}
with open('models/lstm_config.json', 'w') as f:
    json.dump(lstm_config, f, indent=2)

# Save training history for dissertation graphs
history_data = {
    'accuracy':     history.history.get('accuracy', []),
    'val_accuracy': history.history.get('val_accuracy', []),
    'loss':         history.history.get('loss', []),
    'val_loss':     history.history.get('val_loss', [])
}
with open('models/lstm_history.json', 'w') as f:
    json.dump(history_data, f, indent=2)

print("\n" + "=" * 60)
print("  ✅ LSTM Training Complete!")
print("=" * 60)
print(f"  Model saved to:     models/lstm_model.keras")
print(f"  Tokenizer saved to: models/lstm_tokenizer.pkl")
print(f"  Config saved to:    models/lstm_config.json")
print(f"\n  Final Accuracy: {accuracy*100:.2f}%")
print("=" * 60)
print("\n  Next step: Run python api.py")
