# CampusShield IDS 🛡️
**Cryptographically Secured Intrusion Detection & Subnet Monitor**

Developed by **Vedant Manoj Kengale**  
*Final Year B.Tech Information Technology, Pimpri Chinchwad College of Engineering (PCCOE), Pune*

## 📖 Overview
CampusShield IDS is a comprehensive Network Intrusion Detection System designed to monitor, detect, and mitigate real-time cyber threats in a campus network environment. It combines multi-layer threat detection (Layer 4 Port Scanning, Layer 7 Brute Force, and Machine Learning-based Anomaly Detection) with a cryptographically secured audit logging system (HMAC-SHA256) to ensure tamper-evident network security monitoring.

## ✨ Key Features
- **Interactive Topology Map**: Real-time, Canvas-based visualization of campus subnets, active devices, and animated packet flows.
- **Multi-Layer Threat Detection**:
  - **Layer 4 (Transport)**: Sliding window detection for TCP Port Scanning.
  - **Layer 7 (Application)**: Velocity-based detection for SSH Brute Force attacks.
  - **Machine Learning**: Isolation Forest algorithm to detect zero-day netflow anomalies and data exfiltration.
- **Cryptographic Audit Logging (CNS Unit 3)**: Every security alert is signed with HMAC-SHA256, allowing for cryptographic verification to detect any tampering of log files.
- **Auto-Purge Engine**: A background 10-second sweep that automatically isolates and blocks devices exceeding the threat score threshold.
- **Live Analytics Dashboard**: Real-time Chart.js metrics for packet velocity and threat vector breakdown.

## 🛠️ Tech Stack
- **Frontend**: HTML5, Tailwind CSS, Vanilla JavaScript, Chart.js, HTML5 Canvas API
- **Backend**: Python, FastAPI, WebSockets, Scikit-Learn (Isolation Forest), NumPy, Pydantic
- **Security**: HMAC-SHA256 Cryptographic Signing

## 🚀 Getting Started

### 1. Backend Setup
Navigate to the `backend` directory and install the required Python dependencies:
```bash
cd backend
pip install -r requirements.txt
