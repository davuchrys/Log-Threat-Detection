# Log Threat Detection Analysis

A comprehensive security analysis system for detecting and visualizing threats in web server logs using Machine Learning and statistical methods.

## Features

- **Real-time threat detection** - SQL injection, XSS, path traversal attacks
- **ML-powered anomaly detection** - Isolation Forest algorithm
- **Interactive web dashboard** - Built with Streamlit
- **Comprehensive analysis notebooks** - Three detailed Jupyter notebooks
- **Threat classification & risk scoring** - Multi-level severity assessment

## Project Structure

```
analisis data log/
├── log_threat_detection/     # Core Python package
│   ├── __init__.py
│   ├── config.py             # Threat detection patterns
│   ├── dataset.py            # Data loading utilities
│   └── models.py             # ThreatDetector & AnomalyDetector
├── notebooks/                # Analysis notebooks
│   ├── 1.01-eda-and-threat-detection.ipynb
│   ├── 2.01-anomaly-detection-analysis.ipynb
│   └── 3.01-security-threat-classification.ipynb
├── results/                  # Analysis output files
├── access_log.csv            # Access log data
├── error_log_parsed.csv      # Error log data
├── security_dashboard.py     # Streamlit dashboard
├── run_dashboard.bat         # Windows launcher
└── requirements.txt          # Python dependencies
```

## Analysis Branches

### Branch 1: Exploratory Data Analysis & Threat Detection
**Notebook:** `1.01-eda-and-threat-detection.ipynb`

**Features:**
- Data exploration and statistical overview
- Basic threat detection (SQL injection, XSS, path traversal)
- Traffic pattern analysis by hour/day
- HTTP status code distribution
- Geographic IP analysis
- Error log correlation

**Key Outputs:**
- Threat summary statistics
- Visualizations of attack patterns
- Hourly traffic trends
- Top threat sources by IP

### Branch 2: Anomaly Detection Analysis
**Notebook:** `2.01-anomaly-detection-analysis.ipynb`

**Features:**
- Statistical anomaly detection using Z-scores
- ML-based anomaly detection with Isolation Forest
- IP behavior profiling
- Traffic volume anomalies
- Error spike detection
- Comprehensive visualization dashboard

**Key Outputs:**
- Anomalous IP addresses
- Request volume anomalies
- Error rate patterns
- ML model predictions

### Branch 3: Security Threat Classification
**Notebook:** `3.01-security-threat-classification.ipynb`

**Features:**
- Advanced threat categorization
- Multi-dimensional severity scoring (CRITICAL/HIGH/MEDIUM/LOW)
- IP risk assessment framework
- Attack pattern analysis
- Success rate tracking
- Actionable security recommendations

**Key Outputs:**
- Threat actor profiles
- Risk-scored IP addresses
- Attack success metrics
- Prioritized remediation plan

## Quick Start

### Prerequisites

- Python 3.8 or higher
- Git (for cloning the repository)
- Web browser (for viewing the dashboard)

### Installation

1. **Clone the repository:**
```bash
git clone <your-repo-url>
cd "analisis data log"
```

2. **Create and activate virtual environment (recommended):**
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/Mac
python -m venv .venv
source .venv/bin/activate
```

3. **Install dependencies:**
```bash
pip install pandas numpy matplotlib seaborn scikit-learn scipy streamlit plotly
```

## How to Run

### Option 1: Interactive Dashboard (Recommended)

Run the Streamlit web dashboard for real-time threat monitoring:

```bash
streamlit run security_dashboard.py
```

Then open your browser to: **http://localhost:8501**

**Dashboard Features:**
- Security overview with key metrics
- ML anomaly detection visualization
- Threat classification analysis
- Threat actor profiles
- Actionable security recommendations
- Export reports to CSV

**Alternative (Windows):**
```bash
run_dashboard.bat
```

### Option 2: Jupyter Notebooks

For detailed analysis and exploration:

```bash
jupyter notebook
```

Then navigate to the `notebooks/` folder and open:

1. **1.01-eda-and-threat-detection.ipynb** - Start here for basic analysis
2. **2.01-anomaly-detection-analysis.ipynb** - ML-based anomaly detection
3. **3.01-security-threat-classification.ipynb** - Advanced threat classification

**Running notebooks:**
- Execute cells sequentially from top to bottom
- Results are saved automatically to `results/` folder
- Visualizations appear inline

### Option 3: Python Scripts

Use the core detection modules programmatically:

```python
from log_threat_detection.dataset import LogDataset
from log_threat_detection.models import ThreatDetector, AnomalyDetector

# Load data
dataset = LogDataset()
access_df, error_df = dataset.load_all()
access_df = dataset.preprocess_access_log(access_df)

# Detect threats
detector = ThreatDetector()
access_df = detector.analyze_threats(access_df)
summary = detector.get_threat_summary(access_df)

# Run anomaly detection
anomaly_detector = AnomalyDetector()
ip_anomalies = anomaly_detector.detect_ip_anomalies(access_df)

print(f"Threats detected: {summary['total_threats']}")
print(f"Anomalous IPs: {(ip_anomalies['anomaly_score'] == -1).sum()}")
```

## Output Files

Analysis results are saved to the `results/` directory:

- `threat_actors.csv` - IP addresses ranked by threat score
- `critical_threats.csv` - All critical severity threats
- `high_risk_ips.csv` - IPs classified as CRITICAL or HIGH risk
- `anomalous_ips.csv` - ML-detected anomalous behavior

## Threat Types Detected

| Threat Type | Description | Severity Weight |
|------------|-------------|----------------|
| **SQL Injection** | Database manipulation attempts | 10 |
| **XSS Attack** | Cross-site scripting vectors | 8 |
| **Path Traversal** | Directory navigation attacks | 9 |
| **Suspicious Status** | Unusual HTTP response codes | 5 |
| **ML Anomalies** | Behavioral outliers | Variable |

## Detection Methods

1. **Pattern-Based Detection** - Regex patterns for known attack signatures
2. **Statistical Analysis** - Z-score based outlier detection
3. **Machine Learning** - Isolation Forest algorithm for anomaly detection
4. **Behavioral Profiling** - IP-based threat actor identification

## Example Results

```
COMPREHENSIVE THREAT ANALYSIS
================================================================================
Total Requests: 233,930
Threats Detected: 15,847
Threat Rate: 6.77%

THREAT BREAKDOWN:
- SQL Injection Attempts: 1,234
- XSS Attacks: 892
- Path Traversal: 456
- Suspicious Status Codes: 13,265

SEVERITY DISTRIBUTION:
- CRITICAL: 89 threats
- HIGH: 567 threats
- MEDIUM: 3,421 threats
- LOW: 11,770 threats

ML ANOMALY DETECTION:
- Total IPs Analyzed: 5,659
- Anomalous IPs: 283 (5%)
- Top Threat Actor: 192.168.1.105 (Score: 247)
```

## Troubleshooting

### Common Issues

**Issue:** `ModuleNotFoundError: No module named 'sklearn'`
```bash
pip install scikit-learn
```

**Issue:** `streamlit: command not found`
```bash
pip install streamlit
# Or use full path: .venv/Scripts/streamlit run security_dashboard.py
```

**Issue:** Jupyter notebook kernel not found
```bash
pip install ipykernel
python -m ipykernel install --user
```

**Issue:** Column name errors in notebooks
- Make sure all cells are run in order from top to bottom
- Restart kernel and run all cells if needed

## Requirements

```txt
pandas>=2.0.0
numpy>=1.24.0
matplotlib>=3.7.0
seaborn>=0.12.0
scikit-learn>=1.3.0
scipy>=1.11.0
streamlit>=1.30.0
plotly>=5.18.0
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new detection pattern'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

## License

This project is open source and available for educational purposes.

## Author

Security Analysis Team - Log Threat Detection Project

## Acknowledgments

- Threat detection patterns based on OWASP Top 10
- ML anomaly detection using scikit-learn Isolation Forest
- Dashboard powered by Streamlit
- Data visualization with Plotly and Matplotlib

---

**Last Updated:** January 2026  
**Version:** 1.0.0  
**Status:** Active Development

For questions or issues, please open an issue on GitHub.
