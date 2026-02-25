import { useState, useEffect } from 'react';
import { auth } from '../firebase';
import { onAuthStateChanged } from 'firebase/auth';
import { db } from '../firebase';
import { collection, getDocs, query, orderBy, where } from 'firebase/firestore';
import { PieChart, Pie, Cell, LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const COLORS = {
  safe: '#22C55E',
  suspicious: '#F59E0B',
  highRisk: '#EF4444',
  blue: '#0EA5E9'
};

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

export default function Dashboard() {
  const [analytics, setAnalytics] = useState({ totalScans: 0, safeCount: 0, suspiciousCount: 0, highRiskCount: 0 });
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      const user = auth.currentUser;
      if (!user) return;
      
      try {
        const q = query(
          collection(db, 'url_scans'), 
          where('userId', '==', user.uid),
          orderBy('createdAt', 'desc')
        );
        const snapshot = await getDocs(q);
        const scans = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        
        const total = scans.length;
        const safe = scans.filter(s => s.threatLevel === 'Safe').length;
        const suspicious = scans.filter(s => s.threatLevel === 'Suspicious').length;
        const highRisk = scans.filter(s => s.threatLevel === 'High Risk').length;
        
        setAnalytics({ totalScans: total, safeCount: safe, suspiciousCount: suspicious, highRiskCount: highRisk });
        setRecentScans(scans.slice(0, 10));
      } catch (error) {
        console.error('Failed to fetch data:', error);
      } finally {
        setLoading(false);
      }
    };
    
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      if (user) fetchData();
    });
    
    return () => unsubscribe();
  }, []);

  const pieData = [
    { name: 'Safe', value: analytics.safeCount, color: COLORS.safe },
    { name: 'Suspicious', value: analytics.suspiciousCount, color: COLORS.suspicious },
    { name: 'High Risk', value: analytics.highRiskCount, color: COLORS.highRisk }
  ].filter(d => d.value > 0);

  const lineData = recentScans.length > 0 
    ? [...recentScans].reverse().map((scan) => ({
        name: new Date(scan.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        score: scan.threatScore * 100
      }))
    : [
        { name: '00:00', score: 0 },
        { name: '06:00', score: 0 },
        { name: '12:00', score: 0 },
        { name: '18:00', score: 0 },
        { name: 'Now', score: 0 }
      ];

  const barData = [
    { name: 'Safe', count: analytics.safeCount, fill: COLORS.safe },
    { name: 'Suspicious', count: analytics.suspiciousCount, fill: COLORS.suspicious },
    { name: 'High Risk', count: analytics.highRiskCount, fill: COLORS.highRisk }
  ];

  const StatCard = ({ title, value, color, icon }) => (
    <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm hover:shadow-md transition-shadow">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-slate-500 text-sm">{title}</p>
          <p className="text-3xl font-bold mt-1" style={{ color }}>{value}</p>
        </div>
        <div className={`w-12 h-12 rounded-xl flex items-center justify-center`} style={{ backgroundColor: `${color}15` }}>
          <svg className="w-6 h-6" style={{ color }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={icon} />
          </svg>
        </div>
      </div>
    </div>
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="text-slate-500">Loading threat intelligence...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-slide-up">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Threat Intelligence Dashboard</h2>
          <p className="text-slate-500 mt-1">Real-time ransomware detection and analysis</p>
        </div>
        <div className="flex items-center gap-2 px-4 py-2 bg-blue-50 rounded-lg border border-blue-100">
          <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></div>
          <span className="text-sm text-blue-600 font-medium">Live Monitoring</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard 
          title="Total URLs Scanned" 
          value={analytics.totalScans} 
          color={COLORS.blue}
          icon="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
        />
        <StatCard 
          title="Safe URLs" 
          value={analytics.safeCount} 
          color={COLORS.safe}
          icon="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
        />
        <StatCard 
          title="Suspicious URLs" 
          value={analytics.suspiciousCount} 
          color={COLORS.suspicious}
          icon="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
        />
        <StatCard 
          title="High Risk URLs" 
          value={analytics.highRiskCount} 
          color={COLORS.highRisk}
          icon="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-slate-800 mb-4">Threat Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={pieData.length > 0 ? pieData : [{ name: 'No Data', value: 1, color: '#e2e8f0' }]}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={90}
                paddingAngle={2}
                dataKey="value"
              >
                {(pieData.length > 0 ? pieData : [{ name: 'No Data', value: 1, color: '#e2e8f0' }]).map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ backgroundColor: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px' }}
                itemStyle={{ color: '#1e293b' }}
              />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-slate-800 mb-4">Threat Score Trend</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={lineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} domain={[0, 100]} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px' }}
                itemStyle={{ color: '#1e293b' }}
              />
              <Line type="monotone" dataKey="score" stroke={COLORS.blue} strokeWidth={2} dot={{ fill: COLORS.blue }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-slate-800 mb-4">Risk Level Breakdown</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={barData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis type="number" stroke="#64748b" fontSize={12} />
              <YAxis dataKey="name" type="category" stroke="#64748b" fontSize={12} width={80} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px' }}
                itemStyle={{ color: '#1e293b' }}
              />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {barData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
        <h3 className="text-lg font-semibold text-slate-800 mb-4">Recent Scans</h3>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-200">
                <th className="text-left py-3 px-4 text-slate-500 font-medium text-sm">URL</th>
                <th className="text-left py-3 px-4 text-slate-500 font-medium text-sm">Threat Level</th>
                <th className="text-left py-3 px-4 text-slate-500 font-medium text-sm">Score</th>
                <th className="text-left py-3 px-4 text-slate-500 font-medium text-sm">Date</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.length > 0 ? recentScans.map((scan, idx) => (
                <tr key={idx} className="border-b border-slate-100 hover:bg-slate-50">
                  <td className="py-3 px-4 text-slate-600 font-mono text-sm truncate max-w-xs">{scan.url}</td>
                  <td className="py-3 px-4"><ThreatLevelBadge level={scan.threatLevel} /></td>
                  <td className="py-3 px-4 text-slate-600">{(scan.threatScore * 100).toFixed(0)}%</td>
                  <td className="py-3 px-4 text-slate-500 text-sm">{new Date(scan.createdAt).toLocaleString()}</td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="4" className="py-8 text-center text-slate-400">No scans yet. Start scanning URLs!</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
