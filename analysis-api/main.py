import os
import math
import json
import uuid
import tldextract
import requests
import joblib
import numpy as np
from datetime import datetime
from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import firebase_admin
from firebase_admin import credentials, firestore

app = FastAPI(title="Ransomware Early Warning System API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

try:
    import google.cloud.firestore
    from google.cloud import firestore as gc_firestore
    firestore_client = None
    use_emulator = os.environ.get("FIRESTORE_EMULATOR_HOST", "")
    
    if use_emulator:
        firestore_client = gc_firestore.Client()
        print(f"Using Firestore emulator: {use_emulator}")
    else:
        cred = credentials.Certificate("firebase-config.json")
        firebase_admin.initialize_app(cred)
        firestore_client = firestore.client()
except Exception as e:
    print(f"Firestore initialization: {e}")
    firestore_client = None

try:
    model = joblib.load('url_threat_model.joblib')
    print("ML model loaded successfully")
except:
    print("ML model not found, will generate synthetic predictions")
    model = None

def calculate_entropy(url: str) -> float:
    if not url:
        return 0
    prob = [float(url.count(c)) / len(url) for c in set(url)]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def extract_features(url: str) -> Dict[str, float]:
    try:
        extracted = tldextract.extract(url)
        domain = extracted.domain or ""
        suffix = extracted.suffix or ""
        subdomain = extracted.subdomain or ""
    except:
        domain = ""
        suffix = ""
        subdomain = ""
    
    url_length = len(url)
    dot_count = url.count('.')
    
    has_ip = 0
    try:
        if '/' in url:
            host_part = url.split('/')[2] if len(url.split('/')) > 2 else url.split('/')[0]
            parts = host_part.replace('.', '').replace(':', '')
            if parts.isdigit() and len(parts) >= 7:
                has_ip = 1
    except:
        pass
    
    has_https = 1 if url.startswith('https://') else 0
    
    suspicious_keywords_list = ['encrypt', 'decrypt', 'secure', 'update', 'verify', 'account', 'login', 'free', 'download', 'wallet', 'crypto', 'bitcoin', 'password', 'banking', 'invoice', 'payment', 'support', 'confirm', 'unlock']
    keyword_count = sum(1 for kw in suspicious_keywords_list if kw.lower() in url.lower())
    
    suspicious_tlds = ['ru', 'cn', 'tk', 'xyz', 'top', 'pw', 'cc', 'ws', 'info', 'work', 'click', 'link', 'loan', 'date', 'racing', 'gq', 'ml', 'ga', 'cf']
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

def predict_threat(features: Dict[str, float]) -> tuple:
    if model is not None:
        feature_array = np.array([[
            features['url_length'],
            features['dot_count'],
            features['has_ip'],
            features['has_https'],
            features['suspicious_keywords'],
            features['tld_risk_score'],
            features['subdomain_count'],
            features['entropy']
        ]])
        prob = model.predict_proba(feature_array)[0]
        threat_score = float(prob[1])
        confidence = "High" if abs(prob[0] - prob[1]) > 0.4 else "Medium" if abs(prob[0] - prob[1]) > 0.2 else "Low"
    else:
        threat_score = 0.0
        indicators = []
        
        if features['url_length'] > 80:
            threat_score += 0.15
            indicators.append("Unusually long URL")
        
        if features['dot_count'] > 4:
            threat_score += 0.1
            indicators.append("Excessive subdomains")
        
        if features['has_ip']:
            threat_score += 0.25
            indicators.append("IP address in URL")
        
        if features['has_https'] == 0:
            threat_score += 0.1
            indicators.append("No HTTPS encryption")
        
        if features['suspicious_keywords'] > 0:
            threat_score += features['suspicious_keywords'] * 0.1
            indicators.append(f"Suspicious keywords detected ({features['suspicious_keywords']} found)")
        
        if features['tld_risk_score'] > 0:
            threat_score += 0.2
            indicators.append("High-risk TLD detected")
        
        if features['subdomain_count'] > 3:
            threat_score += 0.1
            indicators.append("Excessive subdomain depth")
        
        if features['entropy'] > 5.0:
            threat_score += 0.15
            indicators.append("High URL entropy (obfuscation indicator)")
        
        threat_score = min(threat_score, 1.0)
        confidence = "Medium"
    
    return threat_score, confidence

def get_google_safe_browsing(url: str) -> Dict[str, Any]:
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {"enabled": False, "result": "API key not configured"}
    
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {
                "clientId": "ransomware-early-warning",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(api_url, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {"enabled": True, "matches": data.get("matches", [])}
    except Exception as e:
        return {"enabled": False, "error": str(e)}
    
    return {"enabled": False, "result": "clean"}

def get_virustotal_analysis(url: str) -> Dict[str, Any]:
    if not VIRUSTOTAL_API_KEY:
        return {"enabled": False, "result": "API key not configured"}
    
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls", 
                              params={"url": url}, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {"enabled": True, "data": data}
    except Exception as e:
        return {"enabled": False, "error": str(e)}
    
    return {"enabled": False, "result": "clean"}

def analyze_url(url: str) -> Dict[str, Any]:
    features = extract_features(url)
    threat_score, confidence = predict_threat(features)
    
    indicators = []
    
    if features['url_length'] > 80:
        indicators.append("Unusually long URL")
    if features['dot_count'] > 4:
        indicators.append("Excessive subdomains/dots")
    if features['has_ip']:
        indicators.append("IP address detected instead of domain")
    if features['has_https'] == 0:
        indicators.append("No HTTPS encryption")
    if features['suspicious_keywords'] > 0:
        indicators.append(f"Suspicious keywords detected ({features['suspicious_keywords']} found)")
    if features['tld_risk_score'] > 0:
        indicators.append("High-risk TLD detected")
    if features['subdomain_count'] > 3:
        indicators.append("Excessive subdomain depth")
    if features['entropy'] > 5.0:
        indicators.append("High URL entropy (obfuscation indicator)")
    
    gsb_result = get_google_safe_browsing(url)
    if gsb_result.get("enabled") and gsb_result.get("matches"):
        threat_score = min(threat_score + 0.3, 1.0)
        indicators.append("Flagged by Google Safe Browsing")
        confidence = "High"
    
    vt_result = get_virustotal_analysis(url)
    if vt_result.get("enabled"):
        indicators.append("Analyzed by VirusTotal")
    
    if threat_score <= 0.3:
        threat_level = "Safe"
        recommendation = "This URL appears to be safe. Exercise normal caution."
        safe_to_visit = True
    elif threat_score <= 0.6:
        threat_level = "Suspicious"
        recommendation = "This URL shows some suspicious characteristics. Proceed with caution."
        safe_to_visit = False
    else:
        threat_level = "High Risk"
        recommendation = "This URL shows multiple high-risk indicators. Do not visit this URL."
        safe_to_visit = False
    
    if not indicators:
        indicators = ["No specific threat indicators detected"]
    
    return {
        "url": url,
        "threatScore": round(threat_score, 2),
        "threatLevel": threat_level,
        "confidence": confidence,
        "isMalicious": threat_score > 0.5,
        "indicators": indicators,
        "recommendation": recommendation,
        "actionRequired": threat_score > 0.3,
        "safeToVisit": safe_to_visit,
        "features": features,
        "googleSafeBrowsing": gsb_result,
        "virusTotal": vt_result
    }

class URLRequest(BaseModel):
    url: str

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "Ransomware Early Warning System"}

@app.post("/analyze-url")
def analyze_url_endpoint(request: URLRequest):
    try:
        result = analyze_url(request.url)
        
        scan_data = {
            "scanId": str(uuid.uuid4()),
            "url": result["url"],
            "threatScore": result["threatScore"],
            "threatLevel": result["threatLevel"],
            "confidence": result["confidence"],
            "indicators": result["indicators"],
            "recommendation": result["recommendation"],
            "safeToVisit": result["safeToVisit"],
            "createdAt": datetime.utcnow().isoformat()
        }
        
        if firestore_client:
            try:
                firestore_client.collection("url_scans").document(scan_data["scanId"]).set(scan_data)
                print(f"Scan saved to Firestore: {scan_data['scanId']}")
            except Exception as e:
                print(f"Firestore save error: {e}")
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analytics")
def get_analytics():
    if not firestore_client:
        return {
            "totalScans": 0,
            "safeCount": 0,
            "suspiciousCount": 0,
            "highRiskCount": 0
        }
    
    try:
        scans = list(firestore_client.collection("url_scans").stream())
        
        total = len(scans)
        safe = sum(1 for s in scans if s.to_dict().get("threatLevel") == "Safe")
        suspicious = sum(1 for s in scans if s.to_dict().get("threatLevel") == "Suspicious")
        high_risk = sum(1 for s in scans if s.to_dict().get("threatLevel") == "High Risk")
        
        return {
            "totalScans": total,
            "safeCount": safe,
            "suspiciousCount": suspicious,
            "highRiskCount": high_risk
        }
    except Exception as e:
        print(f"Analytics error: {e}")
        return {
            "totalScans": 0,
            "safeCount": 0,
            "suspiciousCount": 0,
            "highRiskCount": 0
        }

@app.get("/scan-history")
def get_scan_history(limit: int = 50):
    if not firestore_client:
        return []
    
    try:
        scans = firestore_client.collection("url_scans") \
            .order_by("createdAt", direction=firestore.Query.DESCENDING) \
            .limit(limit) \
            .stream()
        
        return [s.to_dict() for s in scans]
    except Exception as e:
        print(f"Scan history error: {e}")
        return []

@app.delete("/scan-history/{scan_id}")
def delete_scan(scan_id: str):
    if not firestore_client:
        raise HTTPException(status_code=500, detail="Firestore not available")
    
    try:
        firestore_client.collection("url_scans").document(scan_id).delete()
        return {"status": "deleted", "scanId": scan_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
