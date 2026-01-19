"""
Threat detection models and analysis functions
"""

import pandas as pd
import numpy as np
import re
from typing import List, Dict, Tuple
from .config import *


class ThreatDetector:
    """Main class for detecting security threats in logs"""
    
    def __init__(self):
        """Initialize threat detector"""
        self.sql_patterns = SQL_INJECTION_PATTERNS
        self.xss_patterns = XSS_PATTERNS
        self.path_traversal_patterns = PATH_TRAVERSAL_PATTERNS
        self.suspicious_status_codes = SUSPICIOUS_STATUS_CODES
    
    def _detect_sql_injection_string(self, url: str) -> bool:
        """Detect potential SQL injection attempts in a single URL"""
        if pd.isna(url):
            return False
        url_lower = str(url).lower()
        return any(pattern in url_lower for pattern in self.sql_patterns)
    
    def _detect_xss_string(self, url: str) -> bool:
        """Detect potential XSS attempts in a single URL"""
        if pd.isna(url):
            return False
        url_lower = str(url).lower()
        return any(pattern in url_lower for pattern in self.xss_patterns)
    
    def _detect_path_traversal_string(self, url: str) -> bool:
        """Detect potential path traversal attempts in a single URL"""
        if pd.isna(url):
            return False
        url_lower = str(url).lower()
        return any(pattern in url_lower for pattern in self.path_traversal_patterns)
    
    def detect_sql_injection(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect SQL injection attempts in access log DataFrame"""
        sql_threats = df[df['url'].apply(self._detect_sql_injection_string)].copy()
        return sql_threats
    
    def detect_xss(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect XSS attempts in access log DataFrame"""
        xss_threats = df[df['url'].apply(self._detect_xss_string)].copy()
        return xss_threats
    
    def detect_path_traversal(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect path traversal attempts in access log DataFrame"""
        path_threats = df[df['url'].apply(self._detect_path_traversal_string)].copy()
        return path_threats
    
    def detect_brute_force(self, df: pd.DataFrame, threshold: int = HIGH_REQUEST_THRESHOLD) -> pd.DataFrame:
        """Detect potential brute force attacks (high request rate from single IP)"""
        ip_counts = df.groupby(['ip', 'date']).size().reset_index(name='request_count')
        suspicious_ips = ip_counts[ip_counts['request_count'] > threshold]
        return suspicious_ips
    
    def detect_suspicious_status_codes(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect requests with suspicious status codes"""
        return df[df['status'].isin(self.suspicious_status_codes)]
    
    def analyze_threats(self, df: pd.DataFrame) -> pd.DataFrame:
        """Comprehensive threat analysis on access log"""
        df = df.copy()
        
        # Apply threat detection
        df['sql_injection'] = df['url'].apply(self._detect_sql_injection_string)
        df['xss_attack'] = df['url'].apply(self._detect_xss_string)
        df['path_traversal'] = df['url'].apply(self._detect_path_traversal_string)
        df['suspicious_status'] = df['status'].isin(self.suspicious_status_codes)
        
        # Overall threat flag
        df['threat_detected'] = (
            df['sql_injection'] | 
            df['xss_attack'] | 
            df['path_traversal'] | 
            df['suspicious_status']
        )
        
        return df
    
    def get_threat_summary(self, df: pd.DataFrame) -> Dict:
        """Get summary of detected threats"""
        summary = {
            'total_requests': len(df),
            'sql_injection_attempts': df['sql_injection'].sum(),
            'xss_attempts': df['xss_attack'].sum(),
            'path_traversal_attempts': df['path_traversal'].sum(),
            'suspicious_status_codes': df['suspicious_status'].sum(),
            'total_threats': df['threat_detected'].sum(),
            'threat_percentage': (df['threat_detected'].sum() / len(df) * 100) if len(df) > 0 else 0
        }
        return summary


class AnomalyDetector:
    """Class for detecting anomalies in log data"""
    
    def __init__(self):
        """Initialize anomaly detector"""
        pass
    
    def detect_traffic_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect unusual traffic patterns"""
        from scipy import stats
        
        # Resample by time periods (e.g., hourly)
        df_sorted = df.copy()
        
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df_sorted['timestamp']):
            df_sorted['timestamp'] = pd.to_datetime(df_sorted['timestamp'], errors='coerce')
        
        df_sorted = df_sorted.sort_values('timestamp').dropna(subset=['timestamp'])
        
        # Group by 1-hour windows
        df_sorted = df_sorted.set_index('timestamp')
        traffic_by_hour = df_sorted.resample('1H').size().reset_index(name='request_count')
        traffic_by_hour.columns = ['timestamp', 'request_count']
        
        # Calculate z-scores
        mean = traffic_by_hour['request_count'].mean()
        std = traffic_by_hour['request_count'].std()
        
        if std > 0:
            traffic_by_hour['z_score'] = (traffic_by_hour['request_count'] - mean) / std
            traffic_by_hour['is_anomaly'] = abs(traffic_by_hour['z_score']) > 2
        else:
            traffic_by_hour['z_score'] = 0
            traffic_by_hour['is_anomaly'] = False
        
        return traffic_by_hour
    
    def detect_ip_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect IPs with anomalous behavior using Isolation Forest"""
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        
        # Determine which column to use for path/url
        path_col = 'url' if 'url' in df.columns else 'path'
        
        # Aggregate IP statistics
        ip_stats = df.groupby('ip').agg({
            path_col: 'count',  # Total requests
            'status': lambda x: (x >= 400).sum() / len(x) if len(x) > 0 else 0,  # Error rate
            'bytes': 'mean'  # Average bytes
        }).reset_index()
        
        ip_stats.columns = ['ip', 'request_count', 'error_rate', 'avg_bytes']
        
        # Add unique paths count
        unique_paths = df.groupby('ip')[path_col].nunique().reset_index(name='unique_paths')
        ip_stats = ip_stats.merge(unique_paths, on='ip')
        
        # Handle missing values
        ip_stats = ip_stats.fillna(0)
        
        # Prepare features for ML
        features = ip_stats[['request_count', 'unique_paths', 'error_rate', 'avg_bytes']].values
        
        # Standardize features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        # Apply Isolation Forest
        iso_forest = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
        ip_stats['anomaly_score'] = iso_forest.fit_predict(features_scaled)
        
        return ip_stats
    
    def detect_error_spikes(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect spikes in error occurrences"""
        if df.empty:
            return pd.DataFrame(columns=['timestamp', 'error_count', 'z_score', 'is_spike'])
        
        # Determine timestamp column name
        timestamp_col = 'timestamp' if 'timestamp' in df.columns else 'datetime'
        
        if timestamp_col not in df.columns:
            return pd.DataFrame(columns=['timestamp', 'error_count', 'z_score', 'is_spike'])
        
        # Resample by time periods
        df_sorted = df.copy()
        
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df_sorted[timestamp_col]):
            df_sorted[timestamp_col] = pd.to_datetime(df_sorted[timestamp_col], errors='coerce')
        
        df_sorted = df_sorted.sort_values(timestamp_col).dropna(subset=[timestamp_col])
        
        # Group by 1-hour windows
        df_sorted = df_sorted.set_index(timestamp_col)
        errors_by_hour = df_sorted.resample('1H').size().reset_index(name='error_count')
        errors_by_hour.columns = ['timestamp', 'error_count']
        
        # Calculate z-scores
        mean = errors_by_hour['error_count'].mean()
        std = errors_by_hour['error_count'].std()
        
        if std > 0:
            errors_by_hour['z_score'] = (errors_by_hour['error_count'] - mean) / std
            errors_by_hour['is_spike'] = errors_by_hour['z_score'] > 2
        else:
            errors_by_hour['z_score'] = 0
            errors_by_hour['is_spike'] = False
        
        return errors_by_hour
