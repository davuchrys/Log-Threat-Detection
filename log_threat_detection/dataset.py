"""
Dataset loading and preprocessing utilities
"""

import pandas as pd
import numpy as np
from datetime import datetime
from typing import Tuple
from .config import *


class LogDataset:
    """Class for loading and preprocessing log data"""
    
    def __init__(self, access_log_path=None, error_log_path=None):
        """Initialize dataset loader"""
        self.access_log_path = access_log_path or ACCESS_LOG_FILE
        self.error_log_path = error_log_path or ERROR_LOG_FILE
        self.access_df = None
        self.error_df = None
    
    def load_access_log(self) -> pd.DataFrame:
        """Load and parse access log data"""
        try:
            self.access_df = pd.read_csv(self.access_log_path)
            print(f"Loaded {len(self.access_df)} access log entries")
            return self.access_df
        except Exception as e:
            print(f"Error loading access log: {e}")
            return None
    
    def load_error_log(self) -> pd.DataFrame:
        """Load and parse error log data"""
        try:
            self.error_df = pd.read_csv(self.error_log_path)
            print(f"Loaded {len(self.error_df)} error log entries")
            return self.error_df
        except Exception as e:
            print(f"Error loading error log: {e}")
            return None
    
    def load_all(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Load both access and error logs"""
        access = self.load_access_log()
        error = self.load_error_log()
        return access, error
    
    def preprocess_access_log(self, df: pd.DataFrame) -> pd.DataFrame:
        """Preprocess access log data"""
        df = df.copy()
        
        # Parse timestamp - handle multiple formats
        if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            try:
                # Try Apache log format first: 28/Feb/2025:00:00:02 +0530
                df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
            except:
                try:
                    # Try without timezone
                    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S', errors='coerce')
                except:
                    # Let pandas infer the format
                    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
        # Extract time features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['date'] = df['timestamp'].dt.date
        
        # Add 'path' alias for 'url' column for backward compatibility
        if 'url' in df.columns and 'path' not in df.columns:
            df['path'] = df['url']
        
        # Convert status to numeric
        df['status'] = pd.to_numeric(df['status'], errors='coerce')
        df['bytes'] = pd.to_numeric(df['bytes'], errors='coerce')
        
        return df
    
    def preprocess_error_log(self, df: pd.DataFrame) -> pd.DataFrame:
        """Preprocess error log data"""
        df = df.copy()
        
        # Parse datetime - handle if already datetime
        if not pd.api.types.is_datetime64_any_dtype(df['datetime']):
            df['datetime'] = pd.to_datetime(df['datetime'], errors='coerce')
        
        # Rename to timestamp for consistency
        df['timestamp'] = df['datetime']
        
        # Extract time features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['date'] = df['timestamp'].dt.date
        
        return df
