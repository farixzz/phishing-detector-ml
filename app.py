import streamlit as st
import pandas as pd
import folium
from streamlit_folium import st_folium
from detector import analyze_url
from geo_utils import get_geo_from_url
from ui_helpers import get_red_flags # <-- THIS IS THE MISSING LINE THAT FIXES THE ERROR

# --- Page Config & Sidebar (Unchanged) ---
st.set_page_config(page_title="Phishing Detector", page_icon="🎣", layout="wide", initial_sidebar_state="collapsed")

st.sidebar.title("About This Tool")
st.sidebar.markdown("""
This application is a powerful, real-time phishing detection system built on a hybrid security model. It is designed for accuracy, speed, and transparency.

**Core Components:**
- **🧠 Machine Learning Engine:**  
  A sophisticated pipeline using a TF-IDF vectorizer and a fine-tuned LightGBM classifier. It's trained on a massive dataset of over 500,000 verified URLs to recognize the subtle patterns of malicious links.

- **📡 Live Threat Intelligence:**  
  Every analysis is cross-referenced with **VirusTotal's** live database, leveraging insights from over 70 security vendors for up-to-the-minute threat detection.

- **🛡️ Data-Driven Thresholding:**  
  The detection threshold is not a fixed number. It is automatically calculated using ROC curve analysis during each training cycle to optimize for a security-first posture (maximizing the catch rate of phishing attempts).
""")
st.sidebar.title("Creator")
st.sidebar.markdown(
    """
    <a href="https://farixzz.github.io" target="_blank" style="text-decoration: none;">
        <div style="background-color: #3b4b33; border-radius: 10px; padding: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); transition: background-color 0.3s ease;">
            <span style="font-size: 1.1em; font-weight: bold; color: #61cf5a;">farixzz</span>
        </div>
    </a>
    <style>a:hover div {background-color: #4a5e42 !important;}</style>
    """, unsafe_allow_html=True
)

# --- Main App ---
st.title("🎣 Machine Learning Phishing Detector")
st.caption("Analyze single URLs or upload a CSV for batch analysis and threat mapping.")
st.markdown("---")

# --- Single URL Analysis ---
st.markdown("## 🔍 Analyze a Single URL")
single_analysis_results = None
with st.container():
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("url_form_single"):
            url_input = st.text_input("", placeholder="Enter a full URL (e.g., http://example.com)", label_visibility="collapsed")
            submit_button = st.form_submit_button("Analyze URL 🔎")

# --- Single URL Result ---
if submit_button and url_input:
    if '.' not in url_input or ' ' in url_input:
        st.warning("⚠️ Please enter a valid URL.")
    else:
        with st.spinner("Analyzing URL… Please wait"):
            single_analysis_results = analyze_url(url_input)

if single_analysis_results:
    st.markdown("---")
    st.header("📊 Analysis Results for Single URL")
    if single_analysis_results["final_verdict"] == "PHISHING DETECTED":
        st.error("🚨 FINAL VERDICT: PHISHING DETECTED")
        red_flags = get_red_flags(single_analysis_results["url"])
        if red_flags:
            st.subheader("🚩 Potential Red Flags Found")
            for flag in red_flags: st.markdown(f"- {flag}")
    else:
        st.success("✅ FINAL VERDICT: LEGITIMATE")

    risk_score = int(single_analysis_results["phishing_probability"])
    st.subheader("⚠️ Risk Score")
    st.caption(f"Based on a detection threshold of {single_analysis_results['threshold']:.2f}% (optimized for >{int(single_analysis_results['target_recall'])}% recall)")
    st.progress(risk_score)
    if risk_score >= 75:
        st.error(f"High Risk ({risk_score}%) 🚨")
    elif risk_score >= 40:
        st.warning(f"Medium Risk ({risk_score}%) ⚠️")
    else:
        st.success(f"Low Risk ({risk_score}%) ✅")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("🧠 Machine Learning")
        st.metric(label="ML Confidence in Verdict", value=f"{single_analysis_results['confidence']:.2f}%")
        st.write(f"**Verdict:** {single_analysis_results['ml_verdict']}")
    with col2:
        st.subheader("📡 External Checks")
        st.write(f"**VirusTotal:** {single_analysis_results['virustotal_reason']}")
        st.write(f"**Google Safe Browsing:** {single_analysis_results['google_safe_browsing_reason']}")
    with st.expander("🔎 View Technical Details"):
        st.json(single_analysis_results)

# --- Batch URL Upload ---
st.markdown("---")
st.header("📂 Batch URL Analysis")
uploaded_file = st.file_uploader("Upload a CSV file with a column named 'url'", type=["csv"])
batch_results = []
if uploaded_file:
    try:
        df = pd.read_csv(uploaded_file)
        if "url" not in df.columns:
            st.error("CSV file must contain a column named 'url'")
        else:
            st.info(f"Processing {len(df)} URLs... Please wait.")
            progress_bar = st.progress(0)
            status_text = st.empty()
            for i, row in df.iterrows():
                url = row["url"]
                try: batch_results.append(analyze_url(url))
                except Exception: batch_results.append({"url": url, "final_verdict": "ANALYSIS_ERROR"})
                progress_bar.progress((i + 1) / len(df))
                status_text.text(f"Analyzed {i+1} of {len(df)} URLs.")
            status_text.success("Batch analysis complete! ✅")
            results_df = pd.DataFrame(batch_results)
            st.dataframe(results_df[['url', 'final_verdict', 'ml_verdict', 'phishing_probability']], use_container_width=True)
            csv = results_df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download Full Results as CSV", csv, "phishing_analysis_results.csv", "text/csv", key='download-csv')
    except Exception as e:
        st.error(f"An error occurred while processing the file: {e}")

# --- Global Threat Map ---
st.markdown("---")
st.header("🌍 Global Threat Map")
urls_to_map = []
if single_analysis_results and single_analysis_results['final_verdict'] == 'PHISHING DETECTED':
    urls_to_map.append(single_analysis_results['url'])
elif batch_results:
    urls_to_map = [res['url'] for res in batch_results if res.get('final_verdict') == 'PHISHING DETECTED']
if not urls_to_map:
    st.info("No phishing URLs detected in the latest analysis to display on the map.")
else:
    st.write(f"Visualizing the locations of **{len(urls_to_map)}** detected phishing domains...")
    threat_map = folium.Map(location=[20, 0], zoom_start=2)
    locations_added = 0
    with st.spinner("Resolving domain locations..."):
        for url in urls_to_map:
            geo_info = get_geo_from_url(url)
            if geo_info:
                lat, lon, country, domain = geo_info
                folium.CircleMarker(location=[lat, lon], radius=6, color="red", fill=True, fill_color="red", fill_opacity=0.6, popup=f"<b>Domain:</b> {domain}<br><b>Country:</b> {country}").add_to(threat_map)
                locations_added += 1
    if locations_added > 0:
        st_folium(threat_map, use_container_width=True, height=500)
    else:
        st.warning("Could not resolve geographic locations for the detected phishing domains.")

# --- Footer ---
st.markdown("---")
st.markdown("""<p align="center">View the full source code on <a href="https://github.com/farixzz/phishing-detector-ml" target="_blank">GitHub</a></p>""", unsafe_allow_html=True)