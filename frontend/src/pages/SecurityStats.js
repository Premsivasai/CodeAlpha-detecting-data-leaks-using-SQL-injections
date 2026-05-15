import React, { useState, useEffect } from 'react';
import api from '../services/api';
import { BarChart3, Shield, TrendingUp, Activity } from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  AreaChart,
  Area
} from 'recharts';

const SecurityStats = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await api.get('/security/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    } finally {
      setLoading(false);
    }
  };

  const mockWeeklyData = [
    { day: 'Mon', attacks: 45, blocked: 45 },
    { day: 'Tue', attacks: 52, blocked: 52 },
    { day: 'Wed', attacks: 38, blocked: 38 },
    { day: 'Thu', attacks: 67, blocked: 65 },
    { day: 'Fri', attacks: 42, blocked: 42 },
    { day: 'Sat', attacks: 28, blocked: 28 },
    { day: 'Sun', attacks: 21, blocked: 21 },
  ];

  const mockTrendData = [
    { hour: '00:00', score: 85 },
    { hour: '04:00', score: 92 },
    { hour: '08:00', score: 78 },
    { hour: '12:00', score: 65 },
    { hour: '16:00', score: 72 },
    { hour: '20:00', score: 88 },
    { hour: '24:00', score: 95 },
  ];

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <span className="loading-spinner" />
      </div>
    );
  }

  return (
    <div className="page-container">
      <h1 className="page-title">Security Analytics</h1>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.5rem', marginBottom: '2rem' }}>
        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-success)', marginBottom: '0.5rem' }}>
            <Shield size={24} />
            <span>Security Score</span>
          </div>
          <div className="stat-value" style={{ color: 'var(--accent-success)' }}>92%</div>
          <div className="stat-label">Excellent</div>
        </div>

        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-primary)', marginBottom: '0.5rem' }}>
            <TrendingUp size={24} />
            <span>Detection Rate</span>
          </div>
          <div className="stat-value">99.8%</div>
          <div className="stat-label">Last 30 days</div>
        </div>

        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-warning)', marginBottom: '0.5rem' }}>
            <Activity size={24} />
            <span>Active Alerts</span>
          </div>
          <div className="stat-value">{stats?.active_alerts || 0}</div>
          <div className="stat-label">Pending</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        <div className="card">
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <BarChart3 size={20} />
            Weekly Attack Summary
          </div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={mockWeeklyData}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                <XAxis dataKey="day" stroke="var(--text-secondary)" />
                <YAxis stroke="var(--text-secondary)" />
                <Tooltip 
                  contentStyle={{ 
                    background: 'var(--bg-secondary)', 
                    border: '1px solid var(--border-color)',
                    borderRadius: '0.5rem'
                  }} 
                />
                <Bar dataKey="attacks" fill="var(--accent-danger)" name="Attacks" />
                <Bar dataKey="blocked" fill="var(--accent-success)" name="Blocked" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={20} />
            Security Trend
          </div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={mockTrendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                <XAxis dataKey="hour" stroke="var(--text-secondary)" />
                <YAxis stroke="var(--text-secondary)" domain={[0, 100]} />
                <Tooltip 
                  contentStyle={{ 
                    background: 'var(--bg-secondary)', 
                    border: '1px solid var(--border-color)',
                    borderRadius: '0.5rem'
                  }} 
                />
                <Area 
                  type="monotone" 
                  dataKey="score" 
                  stroke="var(--accent-success)" 
                  fill="rgba(16, 185, 129, 0.2)"
                  name="Security Score"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: '1.5rem' }}>
        <div className="card-header">Top Attack Types</div>
        {stats?.top_attack_types?.length > 0 ? (
          <div style={{ display: 'grid', gap: '1rem' }}>
            {stats.top_attack_types.map((item, index) => (
              <div key={item.type} style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <span style={{ width: '150px', fontWeight: 600 }}>{item.type}</span>
                <div style={{ flex: 1, height: '24px', background: 'var(--bg-tertiary)', borderRadius: '4px', overflow: 'hidden' }}>
                  <div 
                    style={{ 
                      width: `${(item.count / Math.max(...stats.top_attack_types.map(t => t.count))) * 100}%`, 
                      height: '100%', 
                      background: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6'][index % 5],
                      transition: 'width 0.3s ease'
                    }} 
                  />
                </div>
                <span style={{ width: '60px', textAlign: 'right' }}>{item.count}</span>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            No attack data available
          </div>
        )}
      </div>
    </div>
  );
};

export default SecurityStats;