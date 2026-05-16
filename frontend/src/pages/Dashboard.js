import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import { 
  Shield, 
  AlertTriangle, 
  Ban, 
  Brain, 
  Activity,
  TrendingUp,
  Clock
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts';

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [attacks, setAttacks] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    // Open WebSocket for real-time updates
    let ws;
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
      const host = window.location.hostname || 'localhost';
      ws = new WebSocket(`${protocol}://${host}:8000/api/v1/ws/attacks`);

      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          if (msg.type === 'attack') {
            // refresh data to include latest attack
            fetchData();
          }
        } catch (e) {
          console.error('WS parse error', e);
        }
      };
    } catch (e) {
      console.warn('WebSocket init failed', e);
    }
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const [statsRes, attacksRes] = await Promise.all([
        api.get('/security/stats'),
        api.get('/logs/attacks?limit=10')
      ]);
      setStats(statsRes.data);
      setAttacks(attacksRes.data);

      try {
        const incidentsRes = await api.get('/incidents?limit=5');
        setIncidents(incidentsRes.data || []);
      } catch (incidentError) {
        console.warn('Failed to fetch incidents:', incidentError);
        setIncidents([]);
      }
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const securityScore = stats ? Math.max(0, 100 - (stats.attacks_today * 2)) : 50;
  const scoreColor = securityScore > 70 ? 'high' : securityScore > 40 ? 'medium' : 'low';

  // Build chart data from live stats timeseries (hourly)
  const chartData = stats?.timeseries?.map((point) => ({
    time: new Date(point.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    attacks: point.attacks
  })) || [];

  const pieData = stats?.top_attack_types?.map((item, index) => ({
    name: item.type,
    value: item.count,
    color: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6'][index % 5]
  })) || [];

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <span className="loading-spinner" />
      </div>
    );
  }

  return (
    <div className="page-container">
      <h1 className="page-title">Security Dashboard</h1>
      
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-danger)', marginBottom: '0.5rem' }}>
            <Shield size={24} />
            <span>Total Attacks</span>
          </div>
          <div className="stat-value">{stats?.total_attacks_blocked || 0}</div>
          <div className="stat-label">Blocked</div>
        </div>
        
        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-warning)', marginBottom: '0.5rem' }}>
            <AlertTriangle size={24} />
            <span>Today's Attacks</span>
          </div>
          <div className="stat-value">{stats?.attacks_today || 0}</div>
          <div className="stat-label">Detected</div>
        </div>
        
        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-primary)', marginBottom: '0.5rem' }}>
            <Ban size={24} />
            <span>Blocked IPs</span>
          </div>
          <div className="stat-value">{stats?.active_blocked_ips || 0}</div>
          <div className="stat-label">Active</div>
        </div>
        
        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-success)', marginBottom: '0.5rem' }}>
            <Brain size={24} />
            <span>AI Predictions</span>
          </div>
          <div className="stat-value">{stats?.ai_predictions_today || 0}</div>
          <div className="stat-label">Today</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem', marginBottom: '2rem' }}>
        <div className="card">
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <TrendingUp size={20} />
            Attack Timeline
          </div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height={250}>
                <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                <XAxis dataKey="time" stroke="var(--text-secondary)" />
                <YAxis stroke="var(--text-secondary)" />
                <Tooltip 
                  contentStyle={{ 
                    background: 'var(--bg-secondary)', 
                    border: '1px solid var(--border-color)',
                    borderRadius: '0.5rem'
                  }} 
                />
                <Line 
                  type="monotone" 
                  dataKey="attacks" 
                  stroke="var(--accent-danger)" 
                  strokeWidth={2}
                  dot={{ fill: 'var(--accent-danger)' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={20} />
            Attack Types
          </div>
          <div className="chart-container">
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    dataKey="value"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ 
                      background: 'var(--bg-secondary)', 
                      border: '1px solid var(--border-color)',
                      borderRadius: '0.5rem'
                    }} 
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '200px', color: 'var(--text-secondary)' }}>
                No data available
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '2rem' }}>
        <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertTriangle size={20} />
          Recent Incidents
        </div>
        <div className="attack-feed">
          {incidents.length > 0 ? (
            incidents.map((incident) => (
              <Link key={incident.id} to={`/incidents/${incident.id}`} style={{ textDecoration: 'none', color: 'inherit' }}>
              <div className="attack-item" style={{ cursor: 'pointer' }}>
                <div>
                  <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>
                    {incident.title}
                  </div>
                  <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                    {incident.description || 'No description provided'}
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <span className={`badge badge-${incident.severity === 'critical' ? 'danger' : incident.severity === 'high' ? 'warning' : 'info'}`}>
                    {incident.severity}
                  </span>
                  <span className={`badge badge-${incident.status === 'open' ? 'warning' : 'success'}`}>
                    {incident.status}
                  </span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {new Date(incident.created_at).toLocaleString()}
                  </span>
                </div>
              </div>
              </Link>
            ))
          ) : (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
              No active incidents
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Clock size={20} />
            Recent Attack Feed
          </div>
          <div className="security-meter" style={{ width: '200px' }}>
            <div 
              className={`security-meter-fill ${scoreColor}`}
              style={{ width: `${securityScore}%` }}
            />
          </div>
        </div>
        
        <div className="attack-feed">
          {attacks.length > 0 ? (
            attacks.map((attack) => (
              <div key={attack.id} className="attack-item">
                <div>
                  <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>
                    {attack.attack_type}
                  </div>
                  <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                    {attack.payload?.substring(0, 80)}...
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <span className={`badge badge-${attack.severity === 'critical' ? 'danger' : attack.severity === 'high' ? 'warning' : 'info'}`}>
                    {attack.severity}
                  </span>
                  <span className="badge badge-success">Blocked</span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {new Date(attack.timestamp).toLocaleString()}
                  </span>
                </div>
              </div>
            ))
          ) : (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
              No recent attacks detected
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;