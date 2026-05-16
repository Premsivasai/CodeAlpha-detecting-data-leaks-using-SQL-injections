import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import { Bell, CheckCircle, AlertTriangle, XCircle } from 'lucide-react';

const Alerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAlerts();
  }, []);

  const fetchAlerts = async () => {
    try {
      const response = await api.get('/alerts');
      setAlerts(response.data);
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
    } finally {
      setLoading(false);
    }
  };

  const resolveAlert = async (alertId) => {
    try {
      await api.post(`/alerts/${alertId}/resolve`);
      fetchAlerts();
    } catch (error) {
      console.error('Failed to resolve alert:', error);
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
        return <XCircle size={20} color="var(--accent-danger)" />;
      case 'high':
        return <AlertTriangle size={20} color="var(--accent-warning)" />;
      default:
        return <Bell size={20} color="var(--accent-primary)" />;
    }
  };

  const getSeverityClass = (severity) => {
    switch (severity) {
      case 'critical':
        return 'badge-danger';
      case 'high':
        return 'badge-warning';
      default:
        return 'badge-info';
    }
  };

  return (
    <div className="page-container">
      <h1 className="page-title">Security Alerts</h1>

      <div className="card">
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '2rem' }}>
            <span className="loading-spinner" />
          </div>
        ) : alerts.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {alerts.map((alert) => (
              <div 
                key={alert.id} 
                style={{ 
                  padding: '1.5rem', 
                  background: 'var(--bg-tertiary)', 
                  borderRadius: '0.75rem',
                  borderLeft: `4px solid ${alert.severity === 'critical' ? 'var(--accent-danger)' : alert.severity === 'high' ? 'var(--accent-warning)' : 'var(--accent-primary)'}`
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    {getSeverityIcon(alert.severity)}
                    <span style={{ fontWeight: 600, fontSize: '1.125rem' }}>{alert.title}</span>
                  </div>
                  <span className={`badge ${getSeverityClass(alert.severity)}`}>
                    {alert.severity}
                  </span>
                </div>
                
                <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                  {alert.message}
                </p>

                {alert.metadata?.incident_id && (
                  <div style={{ marginBottom: '1rem' }}>
                    <Link to={`/incidents/${alert.metadata.incident_id}`} className="badge badge-info" style={{ textDecoration: 'none' }}>
                      View related incident #{alert.metadata.incident_id}
                    </Link>
                  </div>
                )}
                
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                    {new Date(alert.created_at).toLocaleString()}
                  </span>
                  
                  {!alert.is_resolved && (
                    <button 
                      onClick={() => resolveAlert(alert.id)}
                      className="btn btn-primary"
                      style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                    >
                      <CheckCircle size={16} />
                      Mark Resolved
                    </button>
                  )}
                  
                  {alert.is_resolved && (
                    <span className="badge badge-success">Resolved</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <Bell size={48} style={{ marginBottom: '1rem', opacity: 0.5 }} />
            <p>No active alerts</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Alerts;