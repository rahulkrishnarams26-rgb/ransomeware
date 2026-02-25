import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import math
import random
import tldextract

def calculate_entropy(url):
    if not url:
        return 0
    prob = [float(url.count(c)) / len(url) for c in set(url)]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def extract_features(url):
    try:
        extracted = tldextract.extract(url)
        domain = extracted.domain
        suffix = extracted.suffix
        subdomain = extracted.subdomain
    except:
        domain = ""
        suffix = ""
        subdomain = ""
    
    url_length = len(url)
    dot_count = url.count('.')
    
    has_ip = 0
    if len(url.split('/')) > 2:
        host = url.split('/')[2]
        if any(char.isdigit() for char in host) and any(c.isalpha() not in host for c in host):
            has_ip = 1
    
    if url.startswith('https://'):
        has_https = 1
    else:
        has_https = 0
    
    suspicious_keywords = ['encrypt', 'decrypt', 'secure', 'update', 'verify', 'account', 'login', 'free', 'download', 'wallet', 'crypto', 'bitcoin', 'password', 'banking', 'invoice', 'payment']
    keyword_count = sum(1 for kw in suspicious_keywords if kw.lower() in url.lower())
    
    suspicious_tlds = ['ru', 'cn', 'tk', 'xyz', 'top', 'pw', 'cc', 'ws', 'info', 'work', 'click', 'link', 'loan', 'date', 'racing']
    tld_risk_score = 1.0 if suffix.lower() in suspicious_tlds else 0.0
    
    subdomain_count = subdomain.count('.') + 1 if subdomain else 0
    
    entropy = calculate_entropy(url)
    
    return {
        'url_length': url_length,
        'dot_count': dot_count,
        'has_ip': has_ip,
        'has_https': has_https,
        'suspicious_keywords': keyword_count,
        'tld_risk_score': tld_risk_score,
        'subdomain_count': subdomain_count,
        'entropy': entropy
    }

def generate_synthetic_dataset(n_samples=2000):
    data = []
    labels = []
    
    for _ in range(n_samples):
        is_malicious = random.random() < 0.4
        
        if is_malicious:
            url_length = random.randint(60, 200)
            dot_count = random.randint(3, 10)
            has_ip = random.choice([0, 1, 1])
            has_https = random.choice([0, 1])
            keyword_count = random.randint(1, 5)
            tld_risk_score = random.choice([0, 0, 1])
            subdomain_count = random.randint(2, 8)
            entropy = random.uniform(4.0, 6.5)
        else:
            url_length = random.randint(20, 80)
            dot_count = random.randint(1, 3)
            has_ip = 0
            has_https = random.choice([0, 1])
            keyword_count = random.randint(0, 1)
            tld_risk_score = 0
            subdomain_count = random.randint(0, 2)
            entropy = random.uniform(2.0, 4.5)
        
        data.append([
            url_length, dot_count, has_ip, has_https,
            keyword_count, tld_risk_score, subdomain_count, entropy
        ])
        labels.append(1 if is_malicious else 0)
    
    return np.array(data), np.array(labels)

def train_model():
    X, y = generate_synthetic_dataset(2000)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X_train, y_train)
    
    accuracy = model.score(X_test, y_test)
    print(f"Model trained with accuracy: {accuracy:.4f}")
    
    joblib.dump(model, 'url_threat_model.joblib')
    print("Model saved to url_threat_model.joblib")
    
    return model

if __name__ == "__main__":
    train_model()
