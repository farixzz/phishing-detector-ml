import streamlit as st
from detector import analyze_url

# --- Page Configuration ---
# This should be the first Streamlit command in your script
st.set_page_config(page_title="Phishing Detector", page_icon="🎣", layout="wide")

# --- [NEW] Redesigned Sidebar ---
st.sidebar.title("About This Tool")
st.sidebar.markdown("""
This application is a powerful phishing detection tool that leverages a hybrid approach to security.

**Features:**
- **🧠 Machine Learning Core:** A sophisticated TF-IDF pipeline trained on over 500,000 URLs to identify suspicious textual patterns.
- **📡 Real-time API Checks:** Verifies URLs against live databases from VirusTotal and Google Safe Browsing for up-to-the-minute threat intelligence.
- **🛡️ Multi-Interface Design:** Fully accessible via this user-friendly GUI and a powerful, scriptable command-line interface.
""")

# --- [NEW] Creator Badge ---
st.sidebar.title("Creator")
st.sidebar.markdown(
    """
    <div style="
        background-color: #3b4b33;
        border-radius: 10px;
        padding: 12px;
        text-align: center;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    ">
        <span style="
            font-size: 1.1em;
            font-weight: bold;
            color: #61cf5a;
        ">
            farixzz
        </span>
    </div>
    """,
    unsafe_allow_html=True
)

# --- Main Page Content ---
st.title("🎣 Machine Learning Phishing Detector")
st.write(
    "Enter a URL below to analyze it using the machine learning model and real-time "
    "API checks."
)

# --- URL Input Form ---
with st.form(key='url_form'):
    url_input = st.text_input(
        "Enter the URL to analyze:", 
        placeholder="e.g., https://www.google.com"
    )
    submit_button = st.form_submit_button(label='Analyze URL')

# --- Analysis Section ---
if submit_button and url_input:
    with st.spinner(f"Analyzing {url_input}... Please wait."):
        results = analyze_url(url_input)

        st.write("---")
        st.header("Analysis Results")

        # --- Display Final Verdict ---
        if results['final_verdict'] == "PHISHING DETECTED":
            st.error(f"🚨 **Final Verdict: PHISHING DETECTED**")
        else:
            st.success(f"✅ **Final Verdict: LEGITIMATE**")

        # --- Display Detailed Results in Columns ---
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("🔬 Machine Learning Analysis")
            if results['ml_verdict'] == "Phishing":
                st.markdown(f"**Verdict:** <span style='color:red;'>{results['ml_verdict']}</span>", unsafe_allow_html=True)
            else:
                st.markdown(f"**Verdict:** <span style='color:green;'>{results['ml_verdict']}</span>", unsafe_allow_html=True)
            st.write(f"**Confidence:** {results['confidence']:.2f}%")

        with col2:
            st.subheader("📡 External API Checks")
            # VirusTotal
            if results['virustotal_status'] == "MALICIOUS":
                st.markdown(f"**VirusTotal:** <span style='color:red;'>{results['virustotal_reason']}</span>", unsafe_allow_html=True)
            else:
                st.markdown(f"**VirusTotal:** <span style='color:green;'>{results['virustotal_reason']}</span>", unsafe_allow_html=True)
            
            # Google Safe Browsing
            if results['google_safe_browsing_status'] == "API_ERROR":
                 st.markdown(f"**Google Safe Browsing:** <span style='color:grey;'>SKIPPED</span>", unsafe_allow_html=True)
            elif results['google_safe_browsing_status'] == "MALICIOUS":
                 st.markdown(f"**Google Safe Browsing:** <span style='color:red;'>{results['google_safe_browsing_reason']}</span>", unsafe_allow_html=True)
            else:
                 st.markdown(f"**Google Safe Browsing:** <span style='color:green;'>{results['google_safe_browsing_reason']}</span>", unsafe_allow_html=True)
