import pandas as pd
import os
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix
import joblib

def train_the_definitive_model():
    data_path = os.path.join('data', 'master_url_dataset.csv')
    print(f"Loading the definitive NORMALIZED dataset from {data_path}...")
    df = pd.read_csv(data_path)
    df.dropna(inplace=True)

    X = df['url'] # The URLs are now pre-normalized
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("Creating the definitive TF-IDF pipeline...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(analyzer='char', ngram_range=(3, 5))),
        ('classifier', LogisticRegression(random_state=42, n_jobs=-1, solver='saga', class_weight='balanced', max_iter=1000))
    ])

    print("Training the definitive pipeline on normalized data...")
    pipeline.fit(X_train, y_train)
    print("Pipeline training complete.")

    print("\n--- Definitive Model Evaluation ---")
    predictions = pipeline.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=['Legitimate (0)', 'Phishing (1)']))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    model_path = os.path.join('models', 'phishing_pipeline.joblib')
    print(f"\nSaving the final, correct pipeline to {model_path}...")
    joblib.dump(pipeline, model_path)
    print("✅✅✅ The final, correct model has been saved. The tool is ready. ✅✅✅")

if __name__ == "__main__":
    train_the_definitive_model()
