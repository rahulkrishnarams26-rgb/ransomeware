import { useState } from 'react';
import { db } from '../firebase';
import { collection, addDoc } from 'firebase/firestore';
import { analyzeUrl } from '../api';

const ThreatIndicator = ({ score, level }) => {
  const colors = {
    'Safe': { bg: 'from-green-50 to-green-100', border: 'border-green-200', text: 'text-green-600', bar: 'bg-green-500' },
    'Suspicious': { bg: 'from-yellow-50 to-yellow-100', border: 'border-yellow-200', text: 'text-yellow-600', bar: 'bg-yellow-500' },
    'High Risk': { bg: 'from-red-50 to-red-100', border: 'border-red-200', text: 'text-red-600', bar: 'bg-red-500' }
  };
  const style = colors[level] || colors['Safe'];

  return (
    <div className={`bg-gradient-to-br ${style.bg} border ${style.border} rounded-xl p-6`}>
      <div className="flex items-center justify-between mb-4">
        <div>
          <p className="text-slate-500 text-sm">Threat Level</p>
          <p className={`text-2xl font-bold ${style.text}`}>{level}</p>
        </div>
        <div className={`w-16 h-16 rounded-full border-4 ${style.border} flex items-center justify-center`}>
          <span className={`text-2xl font-bold ${style.text}`}>{(score * 100).toFixed(0)}%</span>
        </div>
      </div>
      <div className="w-full bg-slate-200 rounded-full h-3 overflow-hidden">
        <div 
          className={`h-full ${style.bar} transition-all duration-1000 ease-out rounded-full`} 
          style={{ width: `${score * 100}%` }}
        />
      </div>
    </div>
  );
};

const IndicatorBadge = ({ text, isWarning }) => (
  <div className={`flex items-center gap-2 px-3 py-2 rounded-lg ${isWarning ? 'bg-red-50 text-red-600' : 'bg-slate-100 text-slate-600'}`}>
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      {isWarning ? (
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      ) : (
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      )}
    </svg>
    <span className="text-sm">{text}</span>
  </div>
);

export default function URLScanner() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const analysisResult = await analyzeUrl(url);
      setResult(analysisResult);
      
      console.log('Saving to Firestore...');
      const docRef = await addDoc(collection(db, 'url_scans'), {
        url: analysisResult.url,
        threatScore: analysisResult.threatScore,
        threatLevel: analysisResult.threatLevel,
        confidence: analysisResult.confidence,
        indicators: analysisResult.indicators,
        recommendation: analysisResult.recommendation,
        safeToVisit: analysisResult.safeToVisit,
        createdAt: new Date().toISOString()
      });
      console.log('Saved to Firestore with ID:', docRef.id);
    } catch (err) {
      console.error('Error saving to Firestore:', err);
      setError('Failed to analyze URL. Please check if the backend is running. ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-slide-up">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-slate-800">URL Threat Scanner</h2>
        <p className="text-slate-500 mt-1">Analyze URLs for ransomware and malware indicators</p>
      </div>

      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
              <svg className="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to analyze (e.g., https://example.com/login)"
              className="w-full pl-12 pr-4 py-4 bg-slate-50 border border-slate-200 rounded-xl text-slate-800 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="w-full py-4 bg-blue-500 hover:bg-blue-600 disabled:bg-slate-300 text-white font-semibold rounded-xl transition-all flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                Analyzing URL...
              </>
            ) : (
              <>
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Analyze URL
              </>
            )}
          </button>
        </form>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex items-center gap-3">
          <svg className="w-5 h-5 text-red-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-red-600">{error}</p>
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <ThreatIndicator score={result.threatScore} level={result.threatLevel} />

          <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
            <div className="flex items-center gap-3 mb-4">
              <div className={`w-3 h-3 rounded-full ${
                result.safeToVisit ? 'bg-green-500' : 'bg-red-500'
              }`}></div>
              <span className={`font-semibold ${
                result.safeToVisit ? 'text-green-600' : 'text-red-600'
              }`}>
                {result.safeToVisit ? 'Safe to Visit' : 'Dangerous - Do Not Visit'}
              </span>
            </div>
            <p className="text-slate-600">{result.recommendation}</p>
            <div className="mt-4 text-sm text-slate-500">
              Confidence: <span className="text-blue-600 font-medium">{result.confidence}</span>
            </div>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
            <h3 className="text-lg font-semibold text-slate-800 mb-4">Threat Indicators</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {result.indicators.map((indicator, idx) => (
                <IndicatorBadge 
                  key={idx} 
                  text={indicator} 
                  isWarning={indicator.includes('IP') || indicator.includes('keyword') || indicator.includes('High-risk') || indicator.includes('entropy') || indicator.includes('Flagged')} 
                />
              ))}
            </div>
          </div>

          {result.features && (
            <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
              <h3 className="text-lg font-semibold text-slate-800 mb-4">URL Features Analysis</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-slate-50 rounded-lg p-3">
                  <p className="text-slate-500 text-xs">URL Length</p>
                  <p className="text-slate-800 font-semibold">{result.features.url_length}</p>
                </div>
                <div className="bg-slate-50 rounded-lg p-3">
                  <p className="text-slate-500 text-xs">Dot Count</p>
                  <p className="text-slate-800 font-semibold">{result.features.dot_count}</p>
                </div>
                <div className="bg-slate-50 rounded-lg p-3">
                  <p className="text-slate-500 text-xs">Has IP</p>
                  <p className="text-slate-800 font-semibold">{result.features.has_ip ? 'Yes' : 'No'}</p>
                </div>
                <div className="bg-slate-50 rounded-lg p-3">
                  <p className="text-slate-500 text-xs">HTTPS</p>
                  <p className="text-slate-800 font-semibold">{result.features.has_https ? 'Yes' : 'No'}</p>
                </div>
                <div className="bg-slate-50 rounded-lg p-3">
                  <p className="text-slate-500 text-xs">Suspicious Keywords</p>
                  <p className="text-slate-800 font-semibold">{result.features.suspicious_keywords}</p>
                </div>
                <div className="bg-slate-50 rounded-lg p-3">
                  <p className="text-slate-500 text-xs">TLD Risk</p>
                  <p className="text-slate-800 font-semibold">{result.features.tld_risk_score > 0 ? 'High' : 'Normal'}</p>
                </div>
                <div className="bg-slate-50 rounded-lg p-3">
                  <p className="text-slate-500 text-xs">Subdomains</p>
                  <p className="text-slate-800 font-semibold">{result.features.subdomain_count}</p>
                </div>
                <div className="bg-slate-50 rounded-lg p-3">
                  <p className="text-slate-500 text-xs">Entropy</p>
                  <p className="text-slate-800 font-semibold">{result.features.entropy.toFixed(2)}</p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      <div className="bg-slate-50 border border-slate-200 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-slate-500 mb-3">Sample URLs to Test</h3>
        <div className="flex flex-wrap gap-2">
          {[
            'https://google.com',
            'https://secure-bank.com/login',
            'http://192.168.1.1/pay',
            'https://update.microsoft.xyz/verify',
            'https://free-download.site/installer'
          ].map((sampleUrl, idx) => (
            <button
              key={idx}
              onClick={() => setUrl(sampleUrl)}
              className="px-3 py-1 bg-white hover:bg-slate-100 text-slate-600 text-sm rounded-lg border border-slate-200 transition-colors"
            >
              {sampleUrl.length > 40 ? sampleUrl.substring(0, 40) + '...' : sampleUrl}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
