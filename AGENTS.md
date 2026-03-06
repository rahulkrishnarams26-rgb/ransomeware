# AGENTS.md - Agentic Coding Guidelines

This document provides guidelines for agents working on this codebase.

## Project Overview

This is a full-stack Ransomware Early Warning System:
- **Frontend**: React 19 + Vite + Tailwind CSS v4
- **Backend**: Python FastAPI with scikit-learn ML model

## Build / Lint / Test Commands

### Frontend (React)

```bash
cd frontend

# Install dependencies
npm install

# Development server
npm run dev

# Production build
npm run build

# Lint code (ESLint)
npm run lint

# Preview production build
npm run preview
```

**Running a single test**: This project does not have test files configured. If adding tests, use:
```bash
npm run test -- --run  # or vitest
npm run test -- --run src/pages/Login.test.jsx  # specific file
```

### Backend (Python)

```bash
cd analysis-api

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Run development server
uvicorn main:app --reload --port 8000

# Run with specific Python file
python main.py
```

**Running a single test**: No formal test framework configured. If adding tests with pytest:
```bash
pytest                           # all tests
pytest test_main.py::test_func   # specific test
pytest -k "test_name"           # by pattern
```

---

## Code Style Guidelines

### JavaScript / React (Frontend)

#### General Rules
- Use functional components with hooks
- Use `.jsx` extension for React components
- Always use `import` statements (ES modules)
- Prefer named exports for utilities, default for components
- Component files should be `PascalCase` (e.g., `Dashboard.jsx`)

#### Naming Conventions
- Components: `PascalCase` (e.g., `URLScanner`)
- Variables/functions: `camelCase` (e.g., `analyzeUrl`, `scanData`)
- Constants: `SCREAMING_SNAKE_CASE` (e.g., `API_BASE`)
- File names: `camelCase.jsx` for components, `camelCase.js` for utilities

#### Imports
```javascript
// React core
import { useState, useEffect } from 'react'

// Router
import { BrowserRouter, Routes, Route } from 'react-router-dom'

// Firebase
import { auth } from './firebase'
import { onAuthStateChanged } from 'firebase/auth'

// Local - components
import Layout from './components/Layout'

// Local - pages
import Dashboard from './pages/Dashboard'
```

#### Formatting
- Use 2 spaces for indentation
- Use single quotes for strings in JSX, double quotes in regular JS
- Add trailing commas
- Use semicolons
- Max line length: 100 characters

#### Tailwind CSS
- Use utility classes in JSX
- Common patterns: `className="flex items-center justify-center"`
- Use `bg-slate-50`, `text-blue-500`, etc.

#### Error Handling
```javascript
try {
  const response = await fetch(url)
  if (!response.ok) throw new Error('Analysis failed')
  return response.json()
} catch (error) {
  console.error('Error:', error)
  throw error
}
```

---

### Python (Backend)

#### General Rules
- Follow PEP 8 style guide
- Use type hints for function signatures
- Use Pydantic models for request/response validation
- Use FastAPI decorators for routes

#### Naming Conventions
- Functions/variables: `snake_case` (e.g., `analyze_url`, `threat_score`)
- Classes: `PascalCase` (e.g., `URLRequest`, `FastAPI`)
- Constants: `SCREAMING_SNAKE_CASE` (e.g., `GOOGLE_SAFE_BROWSING_API_KEY`)
- File names: `snake_case.py` (e.g., `main.py`, `train_model.py`)

#### Type Hints
```python
from typing import List, Dict, Any

def extract_features(url: str) -> Dict[str, float]:
    ...

def predict_threat(features: Dict[str, float]) -> tuple:
    ...
```

#### Pydantic Models
```python
from pydantic import BaseModel

class URLRequest(BaseModel):
    url: str
```

#### FastAPI Routes
```python
from fastapi import FastAPI, HTTPException

app = FastAPI(title="API Title")

@app.get("/endpoint")
def endpoint_handler():
    return {"key": "value"}

@app.post("/endpoint")
def post_handler(request: Model):
    try:
        result = process(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

#### Error Handling
- Use try/except blocks for external calls (Firestore, APIs)
- Log errors with `print(f"Error: {e}")`
- Return appropriate HTTP status codes
- Use `HTTPException` for API errors

#### Imports
```python
# Standard library
import os
import json
import uuid
from datetime import datetime
from typing import List, Dict, Any

# Third-party
import requests
import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Firebase
import firebase_admin
from firebase_admin import credentials, firestore
```

---

## Project Structure

```
ransomeware/
├── analysis-api/           # Python FastAPI backend
│   ├── main.py            # Main API application
│   ├── train_model.py     # ML model training
│   ├── requirements.txt   # Python dependencies
│   └── firebase-config.json
└── frontend/              # React frontend
    ├── src/
    │   ├── components/    # Reusable components (Layout.jsx)
    │   ├── pages/        # Page components (Dashboard.jsx, etc.)
    │   ├── api.js        # API client functions
    │   ├── firebase.js   # Firebase config
    │   ├── index.css    # Tailwind imports
    │   ├── main.jsx     # Entry point
    │   └── App.jsx      # Main app with routing
    ├── package.json
    ├── vite.config.js
    └── eslint.config.js
```

---

## Environment Variables

### Frontend
- None required (uses Firebase SDK)

### Backend
```bash
GOOGLE_SAFE_BROWSING_API_KEY=...
VIRUSTOTAL_API_KEY=...
FIRESTORE_EMULATOR_HOST=localhost:8080  # for dev
```

---

## Important Notes

1. **Firebase**: Requires `firebase-config.json` in `analysis-api/` for production; uses emulator for dev
2. **ML Model**: `url_threat_model.joblib` is optional; falls back to heuristic scoring if missing
3. **CORS**: Backend allows all origins (`allow_origins=["*"]`) - restrict in production
4. **API Proxy**: Frontend proxies `/api` requests to `http://localhost:8000`
