import { useState, useEffect } from 'react';
import { db } from '../firebase';
import { collection, getDocs, query, orderBy } from 'firebase/firestore';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, AreaChart, Area } from 'recharts';

const COLORS = {
  safe: '#22C55E',
  suspicious: '#F59E0B',
  highRisk: '#EF4444',
  blue: '#0EA5E9',
  purple: '#8B5CF6'
};

export default function Analytics() {
  const [analytics, setAnalytics] = useState({ totalScans: 0, safeCount: 0, suspiciousCount: 0, highRiskCount: 0 });
  const [scanHistory, setScanHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const q = query(collection(db, 'url_scans'), orderBy('createdAt', 'desc'));
        const snapshot = await getDocs(q);
        const scans = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        
        const total = scans.length;
        const safe = scans.filter(s => s.threatLevel === 'Safe').length;
        const suspicious = scans.filter(s => s.threatLevel === 'Suspicious').length;
        const highRisk = scans.filter(s => s.threatLevel === 'High Risk').length;
        
        setAnalytics({ totalScans: total, safeCount: safe, suspiciousCount: suspicious, highRiskCount: highRisk });
        setScanHistory(scans);
      } catch (error) {
        console.error('Failed to fetch analytics:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const threatDistribution = [
    { name: 'Safe', value: analytics.safeCount, color: COLORS.safe },
    { name: 'Suspicious', value: analytics.suspiciousCount, color: COLORS.suspicious },
    { name: 'High Risk', value: analytics.highRiskCount, color: COLORS.highRisk }
  ];

  const dailyStats = scanHistory.reduce((acc, scan) => {
    const date = new Date(scan.createdAt).toLocaleDateString();
    const existing = acc.find(d => d.date === date);
    if (existing) {
      existing.total += 1;
      if (scan.threatLevel === 'Safe') existing.safe += 1;
      else if (scan.threatLevel === 'Suspicious') existing.suspicious += 1;
      else if (scan.threatLevel === 'High Risk') existing.highRisk += 1;
    } else {
      acc.push({
        date,
        total: 1,
        safe: scan.threatLevel === 'Safe' ? 1 : 0,
        suspicious: scan.threatLevel === 'Suspicious' ? 1 : 0,
        highRisk: scan.threatLevel === 'High Risk' ? 1 : 0
      });
    }
    return acc;
  }, []);

  const hourlyStats = Array.from({ length: 24 }, (_, i) => {
    const hour = i.toString().padStart(2, '0');
    const scansInHour = scanHistory.filter(scan => {
      const scanHour = new Date(scan.createdAt).getHours();
      return scanHour === i;
    });
    return {
      hour: `${hour}:00`,
      scans: scansInHour.length,
      highRisk: scansInHour.filter(s => s.threatLevel === 'High Risk').length
    };
  });

  const riskMetrics = [
    { name: 'Average Threat Score', value: analytics.totalScans > 0 
      ? ((analytics.suspiciousCount * 0.5 + analytics.highRiskCount * 0.85) / analytics.totalScans * 100).toFixed(1) 
      : 0, color: COLORS.blue },
    { name: 'Detection Rate', value: analytics.totalScans > 0 
      ? ((analytics.suspiciousCount + analytics.highRiskCount) / analytics.totalScans * 100).toFixed(1) 
      : 0, color: COLORS.purple },
    { name: 'Safe Rate', value: analytics.totalScans > 0 
      ? ((analytics.safeCount) / analytics.totalScans * 100).toFixed(1) 
      : 0, color: COLORS.safe }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="text-slate-500">Loading analytics...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-slide-up">
      <div>
        <h2 className="text-2xl font-bold text-slate-800">Threat Analytics</h2>
        <p className="text-slate-500 mt-1">Comprehensive threat intelligence insights</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {riskMetrics.map((metric, idx) => (
          <div key={idx} className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
            <p className="text-slate-500 text-sm">{metric.name}</p>
            <p className="text-4xl font-bold mt-2" style={{ color: metric.color }}>{metric.value}%</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-slate-800 mb-4">Daily Scan Trends</h3>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={dailyStats.length > 0 ? dailyStats : [{ date: 'No Data', total: 0 }]}>
              <defs>
                <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={COLORS.blue} stopOpacity={0.3}/>
                  <stop offset="95%" stopColor={COLORS.blue} stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis dataKey="date" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} />
              <Tooltip contentStyle={{ backgroundColor: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px' }} />
              <Legend />
              <Area type="monotone" dataKey="total" stroke={COLORS.blue} fillOpacity={1} fill="url(#colorTotal)" name="Total Scans" />
              <Area type="monotone" dataKey="highRisk" stroke={COLORS.highRisk} fill="transparent" name="High Risk" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-slate-800 mb-4">Hourly Activity</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={hourlyStats}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis dataKey="hour" stroke="#64748b" fontSize={10} />
              <YAxis stroke="#64748b" fontSize={12} />
              <Tooltip contentStyle={{ backgroundColor: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px' }} />
              <Bar dataKey="scans" fill={COLORS.blue} name="Scans" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-slate-800 mb-4">Risk Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={threatDistribution.some(d => d.value > 0) ? threatDistribution : [{ name: 'No Data', value: 1, color: '#e2e8f0' }]}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={100}
                paddingAngle={2}
                dataKey="value"
              >
                {(threatDistribution.some(d => d.value > 0) ? threatDistribution : [{ name: 'No Data', value: 1, color: '#e2e8f0' }]).map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px' }} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-slate-800 mb-4">Threat Level Breakdown</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={threatDistribution} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis type="number" stroke="#64748b" fontSize={12} />
              <YAxis dataKey="name" type="category" stroke="#64748b" fontSize={12} width={80} />
              <Tooltip contentStyle={{ backgroundColor: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px' }} />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {threatDistribution.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
        <h3 className="text-lg font-semibold text-slate-800 mb-4">Threat Intelligence Summary</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-blue-50 rounded-lg p-4 text-center">
            <p className="text-3xl font-bold text-blue-600">{analytics.totalScans}</p>
            <p className="text-slate-500 text-sm mt-1">Total Scans</p>
          </div>
          <div className="bg-green-50 rounded-lg p-4 text-center">
            <p className="text-3xl font-bold text-green-600">{analytics.safeCount}</p>
            <p className="text-slate-500 text-sm mt-1">Safe URLs</p>
          </div>
          <div className="bg-yellow-50 rounded-lg p-4 text-center">
            <p className="text-3xl font-bold text-yellow-600">{analytics.suspiciousCount}</p>
            <p className="text-slate-500 text-sm mt-1">Suspicious</p>
          </div>
          <div className="bg-red-50 rounded-lg p-4 text-center">
            <p className="text-3xl font-bold text-red-600">{analytics.highRiskCount}</p>
            <p className="text-slate-500 text-sm mt-1">High Risk</p>
          </div>
        </div>
      </div>
    </div>
  );
}
