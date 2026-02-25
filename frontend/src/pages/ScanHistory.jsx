import { useState, useEffect } from 'react';
import { db } from '../firebase';
import { collection, getDocs, query, orderBy, doc, deleteDoc } from 'firebase/firestore';

const ThreatLevelBadge = ({ level }) => {
  const styles = {
    'Safe': 'bg-green-100 text-green-700 border-green-200',
    'Suspicious': 'bg-yellow-100 text-yellow-700 border-yellow-200',
    'High Risk': 'bg-red-100 text-red-700 border-red-200'
  };
  return (
    <span className={`px-2 py-1 rounded-md text-xs font-medium border ${styles[level] || styles['Safe']}`}>
      {level}
    </span>
  );
};

export default function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState(null);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const q = query(collection(db, 'url_scans'), orderBy('createdAt', 'desc'));
        const snapshot = await getDocs(q);
        const history = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        setScans(history);
      } catch (error) {
        console.error('Failed to fetch scan history:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, []);

  const handleDelete = async (id) => {
    try {
      await deleteDoc(doc(db, 'url_scans', id));
      setScans(scans.filter(s => s.id !== id));
      if (selectedScan?.id === id) setSelectedScan(null);
    } catch (error) {
      console.error('Failed to delete scan:', error);
    }
  };

  const filteredScans = scans.filter(scan => {
    if (filter === 'all') return true;
    return scan.threatLevel === filter;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="text-slate-500">Loading scan history...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-slide-up">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Scan History</h2>
          <p className="text-slate-500 mt-1">View all URL threat analysis results</p>
        </div>
        <div className="flex items-center gap-2">
          {['all', 'Safe', 'Suspicious', 'High Risk'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                filter === f
                  ? 'bg-blue-50 text-blue-600 border border-blue-200'
                  : 'bg-white text-slate-600 border border-slate-200 hover:border-slate-300'
              }`}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50">
                  <th className="text-left py-4 px-4 text-slate-500 font-medium text-sm">URL</th>
                  <th className="text-left py-4 px-4 text-slate-500 font-medium text-sm">Threat Level</th>
                  <th className="text-left py-4 px-4 text-slate-500 font-medium text-sm">Score</th>
                  <th className="text-left py-4 px-4 text-slate-500 font-medium text-sm">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.length > 0 ? filteredScans.map((scan) => (
                  <tr 
                    key={scan.id}
                    onClick={() => setSelectedScan(scan)}
                    className={`border-b border-slate-100 hover:bg-slate-50 cursor-pointer transition-colors ${
                      selectedScan?.id === scan.id ? 'bg-blue-50' : ''
                    }`}
                  >
                    <td className="py-4 px-4">
                      <div className="max-w-xs truncate">
                        <span className="text-slate-600 font-mono text-sm">{scan.url}</span>
                      </div>
                    </td>
                    <td className="py-4 px-4">
                      <ThreatLevelBadge level={scan.threatLevel} />
                    </td>
                    <td className="py-4 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-slate-200 rounded-full h-2 overflow-hidden">
                          <div 
                            className={`h-full rounded-full ${
                              scan.threatLevel === 'Safe' ? 'bg-green-500' :
                              scan.threatLevel === 'Suspicious' ? 'bg-yellow-500' : 'bg-red-500'
                            }`}
                            style={{ width: `${scan.threatScore * 100}%` }}
                          />
                        </div>
                        <span className="text-slate-600 text-sm">{(scan.threatScore * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="py-4 px-4">
                      <button
                        onClick={(e) => { e.stopPropagation(); handleDelete(scan.id); }}
                        className="text-red-500 hover:text-red-700 text-sm"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                )) : (
                  <tr>
                    <td colSpan="4" className="py-12 text-center text-slate-400">
                      {scans.length === 0 ? 'No scans yet. Start scanning URLs!' : 'No matching scans found.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-slate-800 mb-4">Scan Details</h3>
          {selectedScan ? (
            <div className="space-y-4">
              <div>
                <p className="text-slate-500 text-xs mb-1">URL</p>
                <p className="text-slate-800 font-mono text-sm break-all">{selectedScan.url}</p>
              </div>
              <div>
                <p className="text-slate-500 text-xs mb-1">Threat Level</p>
                <ThreatLevelBadge level={selectedScan.threatLevel} />
              </div>
              <div>
                <p className="text-slate-500 text-xs mb-1">Threat Score</p>
                <p className="text-slate-800">{(selectedScan.threatScore * 100).toFixed(1)}%</p>
              </div>
              <div>
                <p className="text-slate-500 text-xs mb-1">Confidence</p>
                <p className="text-blue-600 font-medium">{selectedScan.confidence}</p>
              </div>
              <div>
                <p className="text-slate-500 text-xs mb-1">Scan Date</p>
                <p className="text-slate-800 text-sm">{new Date(selectedScan.createdAt).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-slate-500 text-xs mb-1">Recommendation</p>
                <p className="text-slate-600 text-sm">{selectedScan.recommendation}</p>
              </div>
              <div>
                <p className="text-slate-500 text-xs mb-2">Indicators</p>
                <div className="flex flex-wrap gap-1">
                  {selectedScan.indicators?.map((ind, idx) => (
                    <span key={idx} className="px-2 py-1 bg-slate-100 text-slate-600 text-xs rounded">
                      {ind}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center text-slate-400 py-8">
              <svg className="w-12 h-12 mx-auto mb-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
              </svg>
              <p>Click a scan to view details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
