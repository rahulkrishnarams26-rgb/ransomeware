const API_BASE = 'https://ransomeware-agjg.onrender.com';

export async function analyzeUrl(url) {
  const response = await fetch(`${API_BASE}/analyze-url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });
  if (!response.ok) throw new Error('Analysis failed');
  return response.json();
}

export async function checkHealth() {
  const response = await fetch(`${API_BASE}/health`);
  return response.json();
}
