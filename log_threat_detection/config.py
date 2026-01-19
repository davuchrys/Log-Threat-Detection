"""
Configuration file for log analysis project
"""

import os
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
INTERIM_DATA_DIR = DATA_DIR / "interim"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
NOTEBOOKS_DIR = PROJECT_ROOT / "notebooks"

# Data files
ACCESS_LOG_FILE = PROJECT_ROOT / "access_log.csv"
ERROR_LOG_FILE = PROJECT_ROOT / "error_log_parsed.csv"

# Threat detection parameters
SUSPICIOUS_STATUS_CODES = [400, 401, 403, 404, 500, 503]
HIGH_REQUEST_THRESHOLD = 100  # requests per IP per hour
SQL_INJECTION_PATTERNS = [
    'union', 'select', 'insert', 'update', 'delete', 'drop',
    'create', 'alter', '--', ';--', 'or 1=1', "or '1'='1"
]
XSS_PATTERNS = [
    '<script', 'javascript:', 'onerror=', 'onload=', '<iframe',
    'alert(', 'eval(', 'document.cookie'
]
PATH_TRAVERSAL_PATTERNS = [
    '../', '..\\', '..%2f', '..%5c', '%2e%2e%2f', '%2e%2e%5c', '%2e%2e/',
    'etc/passwd', 'etc%2fpasswd', 'windows/system32', 'windows%2fsystem32',
    'boot.ini', 'win.ini'
]

# Analysis settings
DATETIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
ERROR_DATETIME_FORMAT = "%a %b %d %H:%M:%S.%f %Y"
