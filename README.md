# 🎣 Phishing Detector ML Tool

_Created by rizz_

This project is a powerful, multi-interface phishing detection tool that uses a hybrid machine learning model and real-time API checks to identify malicious URLs.

## ✨ Features

- **Hybrid Machine Learning Model:** Combines TF-IDF text analysis with engineered features (URL length, dot count, etc.) for robust detection.
- **Real-time Intelligence:** Validates URLs against live databases from VirusTotal and (optionally) Google Safe Browsing.
- **SIEM Integration:** Can send alerts in the standard Common Event Format (CEF) for integration into a Security Operations Center (SOC).
- **Dual Interface:**
  - **Streamlit GUI:** A user-friendly web interface for easy, interactive analysis.
  - **Advanced CLI:** A powerful command-line tool with support for batch processing from files and structured JSON/CSV output.
- **Standalone Executable:** Can be packaged with PyInstaller into a single, portable application.

## 🚀 Setup and Installation

Follow these steps to get the project running on your local machine.
