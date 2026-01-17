import joblib
import os
from url_normalizer import normalize_url
from api_checker import check_virustotal, check_google_safe_browsing

# --- This is the clean, correct way to load the model ---
# It is loaded only ONCE when the application starts.
MODEL_PATH = os.path.join('models', 'phishing_pipeline.joblib')
BUNDLE = None
PIPELINE = None
PHISHING_THRESHOLD = 0.5 # Default fallback

try:
    BUNDLE = joblib.load(MODEL_PATH)
    PIPELINE = BUNDLE["model"]
    PHISHING_THRESHOLD = BUNDLE["threshold"]
    print(f"✅ Model bundle loaded. Using auto-tuned threshold: {PHISHING_THRESHOLD:.4f}")
except Exception as e:
    print(f"❌ FATAL ERROR: Could not load model bundle from {MODEL_PATH}. Error: {e}")
# --------------------------------------------------------

def analyze_url(url):
    """
    This is the core analysis function. It is now pure backend logic
    with no knowledge of the frontend.
    """
    if PIPELINE is None:
        return {"error": "Model not loaded."}

    normalized_url_for_ml = normalize_url(url)

    probabilities = PIPELINE.predict_proba([normalized_url_for_ml])[0]
    phishing_probability = probabilities[1]

    if phishing_probability >= PHISHING_THRESHOLD:
        ml_verdict = "Phishing"
        confidence_in_verdict = phishing_probability * 100
    else:
        ml_verdict = "Legitimate"
        confidence_in_verdict = (1 - phishing_probability) * 100

    vt_status, vt_reason = check_virustotal(url)
    gsb_status, gsb_reason = check_google_safe_browsing(url)
    
    final_verdict = "LEGITIMATE"
    if ml_verdict == "Phishing" or vt_status == "MALICIOUS" or gsb_status == "MALICIOUS":
        final_verdict = "PHISHING DETECTED"

    return {
        "url": url,
        "ml_verdict": ml_verdict,
        "confidence": confidence_in_verdict,
        "phishing_probability": phishing_probability * 100,
        "threshold": PHISHING_THRESHOLD * 100,
        "target_recall": BUNDLE.get("target_recall", 0.95) * 100,
        "virustotal_status": vt_status,
        "virustotal_reason": vt_reason,
        "google_safe_browsing_status": gsb_status,
        "google_safe_browsing_reason": gsb_reason,
        "final_verdict": final_verdict
    }