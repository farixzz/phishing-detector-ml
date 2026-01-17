import os
import pandas as pd
import joblib
import lightgbm as lgb
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve

def train_the_definitive_model():
    """
    Trains a production-grade model, automatically calculates the optimal
    security-focused threshold, and saves the model and metadata together.
    """
    data_path = os.path.join("data", "master_url_dataset.csv")
    print(f"Loading dataset from: {data_path}")
    df = pd.read_csv(data_path)
    df.dropna(inplace=True)
    X = df["url"]
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    print("Building TF-IDF + Optimized LightGBM pipeline...")
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2, max_features=300_000)),
        ("classifier", lgb.LGBMClassifier(
            objective="binary", random_state=42, n_jobs=-1, is_unbalance=True,
            n_estimators=300, learning_rate=0.05))
    ])

    print("Training production-grade model...")
    pipeline.fit(X_train, y_train)
    print("Training complete.")

    print("\n--- Production Model Evaluation ---")
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    # --- [NEW] Auto Threshold Retraining (Your Recommendation) ---
    print("\n--- Auto Threshold Selection (ROC-based) ---")
    TARGET_RECALL = 0.95  # Security-first target
    fpr, tpr, thresholds = roc_curve(y_test, y_proba)

    # Find the first (lowest) threshold that meets our recall target
    valid_indices = np.where(tpr >= TARGET_RECALL)[0]
    
    if len(valid_indices) > 0:
        # The first index corresponds to the lowest threshold that meets the target
        auto_threshold = thresholds[valid_indices[0]]
        print(f"Target Recall ({TARGET_RECALL}) met. Selecting recall-first threshold.")
    else:
        # Fallback: If target is unreachable, use Youden's J for a balanced choice
        j_scores = tpr - fpr
        auto_threshold = thresholds[np.argmax(j_scores)]
        print(f"Warning: Target Recall ({TARGET_RECALL}) not met. Falling back to Youden's J threshold.")
    
    roc_auc = roc_auc_score(y_test, y_proba)
    print(f"Selected Threshold: {auto_threshold:.4f}")
    print(f"ROC-AUC Score: {roc_auc:.4f}")
    # -----------------------------------------------------------------

    # --- [NEW] Save Model and Auto-Tuned Threshold (Your Recommendation) ---
    os.makedirs("models", exist_ok=True)
    model_path = os.path.join("models", "phishing_pipeline.joblib")
    
    model_bundle = {
        "model": pipeline,
        "threshold": float(auto_threshold),
        "roc_auc": float(roc_auc),
        "target_recall": TARGET_RECALL
    }

    joblib.dump(model_bundle, model_path)
    print(f"\n✅ Model bundle (pipeline + threshold={auto_threshold:.4f}) saved to {model_path}")

if __name__ == "__main__":
    train_the_definitive_model()