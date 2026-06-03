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
  LineChart,
  Line
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

  const weeklyData = stats?.timeseries?.map((point, index) => {
    const date = new Date(point.time);
    return {
      day: date.toLocaleDateString('en-US', { weekday: 'short', hour: '2-digit' }),
      attacks: point.attacks || 0,
      blocked: point.attacks || 0
    };
  }) || [];

  const trendData = stats?.timeseries?.map((point) => ({
    time: new Date(point.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    score: Math.max(0, 100 - (point.attacks * 2))
  })) || [];

  const securityScore = stats 
    ? Math.max(0, 100 - (stats.attacks_today * 2)) 
    : 100;
  
  const scoreLabel = securityScore > 70 ? 'Good' : securityScore > 40 ? 'Fair' : 'Poor';
  const scoreColor = securityScore > 70 ? 'var(--accent-success)' : securityScore > 40 ? 'var(--accent-warning)' : 'var(--accent-danger)';

  const detectionRate = stats?.total_attacks_blocked > 0 
    ? ((stats.total_attacks_blocked - stats.attacks_today) / stats.total_attacks_blocked * 100).toFixed(1)
    : '100';

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
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: scoreColor, marginBottom: '0.5rem' }}>
            <Shield size={24} />
            <span>Security Score</span>
          </div>
          <div className="stat-value" style={{ color: scoreColor }}>{securityScore}%</div>
          <div className="stat-label">{scoreLabel}</div>
        </div>

        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-primary)', marginBottom: '0.5rem' }}>
            <TrendingUp size={24} />
            <span>Detection Rate</span>
          </div>
          <div className="stat-value">{detectionRate}%</div>
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
            Attack Timeline
          </div>
          <div className="chart-container">
            {weeklyData.length > 0 ? (
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={weeklyData}>
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
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '250px', color: 'var(--text-secondary)' }}>
                No data available
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={20} />
            Security Trend
          </div>
          <div className="chart-container">
            {trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height={250}>
                <LineChart data={trendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                  <XAxis dataKey="time" stroke="var(--text-secondary)" />
                  <YAxis stroke="var(--text-secondary)" domain={[0, 100]} />
                  <Tooltip 
                    contentStyle={{ 
                      background: 'var(--bg-secondary)', 
                      border: '1px solid var(--border-color)',
                      borderRadius: '0.5rem'
                    }} 
                  />
                  <Line 
                    type="monotone" 
                    dataKey="score" 
                    stroke="var(--accent-success)" 
                    strokeWidth={2}
                    name="Security Score"
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '250px', color: 'var(--text-secondary)' }}>
                No data available
              </div>
            )}
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