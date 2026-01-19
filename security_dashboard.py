import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import sys
sys.path.append('.')

from log_threat_detection.dataset import LogDataset
from log_threat_detection.models import ThreatDetector, AnomalyDetector
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

# Page configuration
st.set_page_config(
    page_title="Security Threat Analysis Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .big-font {
        font-size:30px !important;
        font-weight: bold;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #ff4b4b;
    }
    </style>
    """, unsafe_allow_html=True)

# Cache data loading
@st.cache_data
def load_and_process_data():
    """Load and process log data"""
    dataset = LogDataset()
    access_df, error_df = dataset.load_all()
    access_df = dataset.preprocess_access_log(access_df)
    error_df = dataset.preprocess_error_log(error_df)
    return access_df, error_df

@st.cache_data
def run_threat_detection(access_df):
    """Run threat detection analysis"""
    detector = ThreatDetector()
    access_df = detector.analyze_threats(access_df)
    summary = detector.get_threat_summary(access_df)
    return access_df, summary

@st.cache_data
def classify_threats(access_df):
    """Classify threat severity"""
    def classify_severity(row):
        severity_score = 0
        threat_type = []
        
        if row['sql_injection']:
            severity_score += 10
            threat_type.append('SQL_INJECTION')
        if row['xss_attack']:
            severity_score += 8
            threat_type.append('XSS')
        if row['path_traversal']:
            severity_score += 9
            threat_type.append('PATH_TRAVERSAL')
        if row['suspicious_status']:
            severity_score += 5
            threat_type.append('SUSPICIOUS_STATUS')
        
        if severity_score >= 15:
            severity = 'CRITICAL'
        elif severity_score >= 10:
            severity = 'HIGH'
        elif severity_score >= 5:
            severity = 'MEDIUM'
        elif severity_score > 0:
            severity = 'LOW'
        else:
            severity = 'NONE'
        
        return pd.Series({
            'threat_severity': severity,
            'threat_score': severity_score,
            'threat_types': ','.join(threat_type) if threat_type else 'NONE'
        })
    
    access_df[['threat_severity', 'threat_score', 'threat_types']] = access_df.apply(classify_severity, axis=1)
    return access_df

@st.cache_data
def run_ml_anomaly_detection(access_df):
    """Run ML-based anomaly detection"""
    # Use AnomalyDetector class
    detector = AnomalyDetector()
    ip_features = detector.detect_ip_anomalies(access_df)
    
    # Add anomaly boolean flag
    ip_features['anomaly'] = ip_features['anomaly_score'] == -1
    
    # Add additional computed columns for compatibility
    ip_features['total_requests'] = ip_features['request_count']
    ip_features['unique_urls'] = ip_features['unique_paths']
    ip_features['error_count'] = (ip_features['error_rate'] * ip_features['request_count']).astype(int)
    ip_features['post_rate'] = 0.0  # Not available in original method
    
    return ip_features

# Main app
def main():
    # Header
    st.markdown('<p class="big-font">🛡️ Security Threat Analysis Dashboard</p>', unsafe_allow_html=True)
    st.markdown("**Real-time threat detection and anomaly analysis powered by Machine Learning**")
    st.markdown("---")
    
    # Sidebar
    st.sidebar.header("⚙️ Dashboard Controls")
    
    # Load data button
    if st.sidebar.button("🔄 Refresh Data", type="primary"):
        st.cache_data.clear()
        st.rerun()
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📊 Analysis Modules")
    show_overview = st.sidebar.checkbox("Overview", value=True)
    show_ml = st.sidebar.checkbox("ML Anomaly Detection", value=True)
    show_threats = st.sidebar.checkbox("Threat Classification", value=True)
    show_actors = st.sidebar.checkbox("Threat Actors", value=True)
    show_recommendations = st.sidebar.checkbox("Recommendations", value=True)
    
    # Load and process data
    with st.spinner("Loading data..."):
        access_df, error_df = load_and_process_data()
        access_df, summary = run_threat_detection(access_df)
        access_df = classify_threats(access_df)
        ip_features = run_ml_anomaly_detection(access_df)
    
    # Overview Section
    if show_overview:
        st.header("📈 Security Overview")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label="Total Requests",
                value=f"{len(access_df):,}",
                delta="Last 24h"
            )
        
        with col2:
            threat_pct = summary['threat_percentage']
            st.metric(
                label="Threats Detected",
                value=f"{summary['total_threats']:,}",
                delta=f"{threat_pct:.2f}%",
                delta_color="inverse"
            )
        
        with col3:
            anomalous_count = ip_features['anomaly'].sum()
            st.metric(
                label="Anomalous IPs",
                value=f"{anomalous_count}",
                delta="ML Detected",
                delta_color="inverse"
            )
        
        with col4:
            critical_count = (access_df['threat_severity'] == 'CRITICAL').sum()
            high_count = (access_df['threat_severity'] == 'HIGH').sum()
            st.metric(
                label="Critical/High Threats",
                value=f"{critical_count + high_count:,}",
                delta="Needs attention",
                delta_color="inverse"
            )
        
        st.markdown("---")
        
        # Threat breakdown
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🎯 Threat Type Distribution")
            threat_data = pd.DataFrame({
                'Type': ['SQL Injection', 'XSS Attack', 'Path Traversal', 'Suspicious Status'],
                'Count': [
                    summary['sql_injection_attempts'],
                    summary['xss_attempts'],
                    summary['path_traversal_attempts'],
                    summary['suspicious_status_codes']
                ]
            })
            fig = px.bar(threat_data, x='Type', y='Count', 
                        color='Count',
                        color_continuous_scale='Reds',
                        title="Detected Threat Types")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("⚠️ Severity Distribution")
            severity_data = access_df['threat_severity'].value_counts()
            colors = {'CRITICAL': '#8B0000', 'HIGH': '#FF0000', 'MEDIUM': '#FFA500', 'LOW': '#FFFF00', 'NONE': '#90EE90'}
            fig = px.pie(values=severity_data.values, names=severity_data.index,
                        title="Threat Severity Levels",
                        color=severity_data.index,
                        color_discrete_map=colors)
            st.plotly_chart(fig, use_container_width=True)
    
    # ML Anomaly Detection
    if show_ml:
        st.header("🤖 Machine Learning Anomaly Detection")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("Anomaly Detection Visualization")
            
            # Create scatter plot
            fig = go.Figure()
            
            # Normal IPs
            normal = ip_features[~ip_features['anomaly']]
            fig.add_trace(go.Scatter(
                x=normal['total_requests'],
                y=normal['error_rate'],
                mode='markers',
                name='Normal IPs',
                marker=dict(size=8, color='blue', opacity=0.5)
            ))
            
            # Anomalous IPs
            anomalous = ip_features[ip_features['anomaly']]
            fig.add_trace(go.Scatter(
                x=anomalous['total_requests'],
                y=anomalous['error_rate'],
                mode='markers',
                name='Anomalous IPs',
                marker=dict(size=15, color='red', symbol='triangle-up', 
                           line=dict(color='black', width=2))
            ))
            
            fig.update_layout(
                title="IP Behavior: Request Volume vs Error Rate",
                xaxis_title="Total Requests",
                yaxis_title="Error Rate",
                hovermode='closest'
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("📊 ML Detection Stats")
            
            total_ips = len(ip_features)
            anomalous_ips = ip_features['anomaly'].sum()
            
            st.metric("Total IPs Analyzed", f"{total_ips:,}")
            st.metric("Anomalous IPs Detected", f"{anomalous_ips}", 
                     delta=f"{(anomalous_ips/total_ips*100):.1f}%",
                     delta_color="inverse")
            
            st.markdown("**Algorithm:** Isolation Forest")
            st.markdown("**Contamination:** 5%")
            st.markdown("**Features Used:**")
            st.markdown("- Request volume")
            st.markdown("- Error rate")
            st.markdown("- Unique paths/URLs")
            st.markdown("- Average bytes")
        
        # Top anomalous IPs
        st.subheader("🚨 Top 20 Anomalous IPs (ML Detected)")
        top_anomalous = ip_features[ip_features['anomaly']].sort_values('request_count', ascending=False).head(20)
        
        if len(top_anomalous) > 0:
            st.dataframe(
                top_anomalous[['request_count', 'error_rate', 'unique_paths', 'avg_bytes']].style.background_gradient(cmap='Reds'),
                use_container_width=True
            )
        else:
            st.info("No anomalous IPs detected by ML model.")
    
    # Threat Classification
    if show_threats:
        st.header("🎯 Threat Classification Analysis")
        
        # Threat by IP
        threat_by_ip = access_df[access_df['threat_detected']].groupby('ip').agg({
            'threat_detected': 'count',
            'sql_injection': 'sum',
            'xss_attack': 'sum',
            'path_traversal': 'sum',
            'threat_score': 'sum',
            'threat_severity': lambda x: (x.isin(['CRITICAL', 'HIGH'])).sum()
        }).rename(columns={
            'threat_detected': 'total_threats',
            'threat_severity': 'high_severity_threats'
        }).sort_values('threat_score', ascending=False)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Top 15 Threat Sources")
            top15 = threat_by_ip.head(15)
            fig = px.bar(
                x=top15['total_threats'].values,
                y=top15.index,
                orientation='h',
                title="IPs by Threat Count",
                labels={'x': 'Number of Threats', 'y': 'IP Address'},
                color=top15['threat_score'].values,
                color_continuous_scale='Reds'
            )
            fig.update_layout(yaxis={'categoryorder':'total ascending'})
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Threat Timeline")
            hourly_threats = access_df[access_df['threat_detected']].groupby('hour').size()
            fig = px.line(
                x=hourly_threats.index,
                y=hourly_threats.values,
                title="Threat Activity by Hour",
                labels={'x': 'Hour of Day', 'y': 'Number of Threats'},
                markers=True
            )
            fig.update_traces(line_color='red', line_width=3)
            st.plotly_chart(fig, use_container_width=True)
    
    # Threat Actors
    if show_actors:
        st.header("👤 Threat Actor Analysis")
        
        threat_by_ip = access_df[access_df['threat_detected']].groupby('ip').agg({
            'threat_detected': 'count',
            'sql_injection': 'sum',
            'xss_attack': 'sum',
            'path_traversal': 'sum',
            'threat_score': 'sum',
            'threat_severity': lambda x: (x.isin(['CRITICAL', 'HIGH'])).sum()
        }).rename(columns={
            'threat_detected': 'total_threats',
            'threat_severity': 'high_severity_threats'
        }).sort_values('threat_score', ascending=False).head(20)
        
        # Create risk assessment
        risk_levels = []
        for ip, data in threat_by_ip.iterrows():
            if data['threat_score'] >= 100 and data['high_severity_threats'] >= 5:
                risk = 'CRITICAL'
            elif data['threat_score'] >= 50 and data['high_severity_threats'] >= 2:
                risk = 'HIGH'
            elif data['threat_score'] >= 20:
                risk = 'MEDIUM'
            else:
                risk = 'LOW'
            risk_levels.append(risk)
        
        threat_by_ip['risk_level'] = risk_levels
        
        st.subheader("🎯 Top 20 Threat Actors with Risk Assessment")
        
        # Color coding
        def color_risk(val):
            if val == 'CRITICAL':
                return 'background-color: #8B0000; color: white'
            elif val == 'HIGH':
                return 'background-color: #FF0000; color: white'
            elif val == 'MEDIUM':
                return 'background-color: #FFA500; color: black'
            else:
                return 'background-color: #FFFF00; color: black'
        
        styled_df = threat_by_ip.style.applymap(color_risk, subset=['risk_level'])
        st.dataframe(styled_df, use_container_width=True)
        
        # Download button
        csv = threat_by_ip.to_csv()
        st.download_button(
            label="📥 Download Threat Actors Report",
            data=csv,
            file_name=f"threat_actors_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv"
        )
    
    # Recommendations
    if show_recommendations:
        st.header("💡 Security Recommendations")
        
        critical_ips = threat_by_ip[threat_by_ip['risk_level'] == 'CRITICAL'].index.tolist() if 'risk_level' in threat_by_ip.columns else []
        high_ips = threat_by_ip[threat_by_ip['risk_level'] == 'HIGH'].index.tolist() if 'risk_level' in threat_by_ip.columns else []
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🚨 Immediate Actions")
            
            if critical_ips:
                st.error(f"**CRITICAL:** Block {len(critical_ips)} IPs immediately")
                with st.expander("View IPs to block"):
                    for ip in critical_ips[:10]:
                        st.code(ip)
            
            if high_ips:
                st.warning(f"**HIGH:** Implement rate limiting for {len(high_ips)} IPs")
            
            if summary['sql_injection_attempts'] > 0:
                st.warning(f"**HIGH:** Strengthen input validation - {summary['sql_injection_attempts']} SQL injection attempts")
            
            if summary['xss_attempts'] > 0:
                st.warning(f"**HIGH:** Implement output encoding - {summary['xss_attempts']} XSS attempts")
        
        with col2:
            st.subheader("🛠️ Medium-Term Actions")
            
            st.info("**MEDIUM:** Deploy Web Application Firewall (WAF)")
            st.info("**MEDIUM:** Implement real-time threat monitoring")
            st.info("**MEDIUM:** Set up automated blocking rules")
            st.info("**LOW:** Cross-reference with threat intelligence databases")
        
        st.markdown("---")
        st.subheader("📋 Detailed Action Plan")
        
        recommendations = pd.DataFrame([
            {'Priority': 'CRITICAL', 'Action': f'Block {len(critical_ips)} critical IPs', 'Timeline': 'Immediate'},
            {'Priority': 'HIGH', 'Action': 'Implement WAF rules', 'Timeline': '24 hours'},
            {'Priority': 'HIGH', 'Action': 'Strengthen input validation', 'Timeline': '48 hours'},
            {'Priority': 'MEDIUM', 'Action': 'Deploy monitoring system', 'Timeline': '1 week'},
            {'Priority': 'MEDIUM', 'Action': 'Security audit of vulnerable endpoints', 'Timeline': '1 week'},
            {'Priority': 'LOW', 'Action': 'Threat intelligence integration', 'Timeline': '2 weeks'}
        ])
        
        st.table(recommendations)
    
    # Footer
    st.markdown("---")
    st.markdown(f"**Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | **Total Logs Analyzed:** {len(access_df):,} access logs, {len(error_df):,} error logs")

if __name__ == "__main__":
    main()
