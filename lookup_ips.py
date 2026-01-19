import requests
import pandas as pd
import time

# Top 20 suspicious IPs from the analysis
ips = [
    "203.115.97.42",
    "157.35.64.200",
    "117.233.210.143",
    "103.168.223.4",
    "106.221.41.32",
    "152.59.146.58",
    "157.42.7.14",
    "103.155.3.139",
    "106.195.95.229",
    "106.219.174.37",
    "49.47.130.161",
    "152.59.143.215",
    "183.82.33.14",
    "150.240.161.195",
    "152.56.154.103",
    "182.72.100.186",
    "152.56.153.194",
    "223.226.166.132",
    "152.59.135.189",
    "223.182.93.39"
]

results = []

print("Looking up IP locations...\n")

for ip in ips:
    try:
        # Using ip-api.com (free, no key required)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                results.append({
                    'IP': ip,
                    'Country': data.get('country', 'Unknown'),
                    'Region': data.get('regionName', 'Unknown'),
                    'City': data.get('city', 'Unknown'),
                    'ISP': data.get('isp', 'Unknown'),
                    'Organization': data.get('org', 'Unknown')
                })
                print(f"✓ {ip} - {data.get('country')} ({data.get('city')})")
            else:
                results.append({'IP': ip, 'Country': 'Lookup Failed', 'Region': '', 'City': '', 'ISP': '', 'Organization': ''})
        else:
            results.append({'IP': ip, 'Country': 'API Error', 'Region': '', 'City': '', 'ISP': '', 'Organization': ''})
        
        # Rate limiting (free tier allows 45 requests/minute)
        time.sleep(1.5)
        
    except Exception as e:
        print(f"✗ {ip} - Error: {str(e)}")
        results.append({'IP': ip, 'Country': 'Error', 'Region': '', 'City': '', 'ISP': '', 'Organization': ''})

# Create DataFrame
df = pd.DataFrame(results)

# Save to CSV
df.to_csv('data/processed/suspicious_ips_geolocation.csv', index=False)
print(f"\n✓ Results saved to: data/processed/suspicious_ips_geolocation.csv")

# Display results
print("\n" + "="*100)
print("SUSPICIOUS IP GEOLOCATION RESULTS")
print("="*100)
print(df.to_string(index=False))

# Summary by country
print("\n" + "="*100)
print("THREAT ORIGIN SUMMARY")
print("="*100)
country_counts = df['Country'].value_counts()
print(country_counts)
