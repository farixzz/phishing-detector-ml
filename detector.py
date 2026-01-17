import joblib
import os
from api_checker import check_virustotal, check_google_safe_browsing
from url_normalizer import normalize_url # <-- IMPORT THE FIX

# --- Load the Model Pipeline ---
MODEL_PATH = os.path.join('models', 'phishing_pipeline.joblib')
try:
    pipeline = joblib.load(MODEL_PATH)
except FileNotFoundError:
    print("FATAL ERROR: Model pipeline not found. Please run train_model.py first.")
    pipeline = None

def analyze_url(url):
    """
    This is the core analysis function.
    It takes a URL string and returns a dictionary with the full analysis results.
    """
    if pipeline is None:
        return {"error": "Model not loaded."}

    # --- THE CRITICAL FIX ---
    # Normalize the URL for the machine learning model.
    normalized_url_for_ml = normalize_url(url)
    # -----------------------

    # --- 1. Machine Learning Analysis ---
    # Use the normalized URL for ML prediction
    prediction = pipeline.predict([normalized_url_for_ml])[0]
    probabilities = pipeline.predict_proba([normalized_url_for_ml])[0]
    
    ml_verdict = "Phishing" if prediction == 1 else "Legitimate"
    confidence = probabilities[prediction] * 100

    # --- 2. API Analysis ---
    # Use the ORIGINAL, full URL for API checks
    vt_status, vt_reason = check_virustotal(url)
    gsb_status, gsb_reason = check_google_safe_browsing(url)

    # --- 3. Final Verdict ---
    final_verdict = "LEGITIMATE"
    if ml_verdict == "Phishing" or vt_status == "MALICIOUS" or gsb_status == "MALICIOUS":
        final_verdict = "PHISHING DETECTED"

    # --- 4. Return a structured dictionary ---
    return {
        "url": url,
        "ml_verdict": ml_verdict,
        "confidence": confidence,
        "virustotal_status": vt_status,
        "virustotal_reason": vt_reason,
        "google_safe_browsing_status": gsb_status,
        "google_safe_browsing_reason": gsb_reason,
        "final_verdict": final_verdict
    }
