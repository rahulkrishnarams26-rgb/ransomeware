# Ransomware Early Warning System

A professional full-stack web application for detecting ransomware-related malicious URLs using machine learning and threat intelligence.

## Features

- **URL Analysis**: Analyzes URLs for multiple threat indicators
- **Machine Learning**: RandomForest-based threat prediction
- **Threat Intelligence**: Google Safe Browsing & VirusTotal integration (optional)
- **Dashboard**: Real-time threat statistics and visualizations
- **Scan History**: Complete history of all URL scans
- **Analytics**: Comprehensive threat trend analysis

## Tech Stack

### Frontend
- React 19 (Vite)
- TailwindCSS
- Recharts
- Firebase SDK

### Backend
- Python
- FastAPI
- scikit-learn
- Firebase Firestore

## Project Structure

```
ransomware-warning/
├── analysis-api/          # Python FastAPI backend
│   ├── main.py           # Main API application
│   ├── train_model.py    # ML model training script
│   ├── requirements.txt  # Python dependencies
│   └── firebase-config.json
└── frontend/             # React frontend
    ├── src/
    │   ├── components/   # Reusable components
    │   ├── pages/        # Page components
    │   ├── api.js        # API client
    │   └── App.jsx       # Main app
    └── package.json
```

## Setup Instructions

### Prerequisites

- Node.js 18+
- Python 3.8+
- Firebase project (optional for production)

### Backend Setup

```bash
cd analysis-api

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Train ML model (optional - creates url_threat_model.joblib)
python train_model.py

# Configure Firebase (optional)
# Add your firebase-config.json and API keys

# Run backend
uvicorn main:app --reload --port 8000
```

### Environment Variables

```bash
# For Google Safe Browsing API (optional)
export GOOGLE_SAFE_BROWSING_API_KEY="your-api-key"

# For VirusTotal API (optional)
export VIRUSTOTAL_API_KEY="your-api-key"

# For Firestore emulator (development)
export FIRESTORE_EMULATOR_HOST="localhost:8080"
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

The frontend will be available at `http://localhost:5173`

### Running with Firestore Emulator

1. Install Java (required for Firestore emulator)
2. Start Firestore emulator:
```bash
firebase emulators:start --only firestore
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/analyze-url` | POST | Analyze a URL |
| `/analytics` | GET | Get threat statistics |
| `/scan-history` | GET | Get all scan history |

## Example Usage

### Analyze a URL

```bash
curl -X POST http://localhost:8000/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/login"}'
```

### Response

```json
{
  "url": "https://example.com/login",
  "threatScore": 0.25,
  "threatLevel": "Safe",
  "confidence": "Medium",
  "isMalicious": false,
  "indicators": ["No specific threat indicators detected"],
  "recommendation": "This URL appears to be safe.",
  "actionRequired": false,
  "safeToVisit": true
}
```

## Threat Indicators Analyzed

- URL length
- Number of dots
- IP address detection
- Suspicious keywords
- Domain age (simulated)
- Suspicious TLDs
- HTTPS usage
- Subdomain count
- URL entropy

## Security Note

This is an academic/educational project for detecting ransomware-related URLs. It uses simulated threat intelligence and should not be used as the sole method for security decisions in production environments.

## License

MIT
