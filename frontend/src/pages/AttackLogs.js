import React, { useState, useEffect, useCallback } from 'react';
import api from '../services/api';
import { ShieldAlert, Filter, RefreshCw } from 'lucide-react';

const AttackLogs = () => {
  const [attacks, setAttacks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({
    type: '',
    severity: '',
    query: '',
    blocked: '',
    startTime: '',
    endTime: ''
  });

  const fetchAttacks = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filter.type) params.append('attack_type', filter.type);
      if (filter.severity) params.append('severity', filter.severity);
      if (filter.query) params.append('query', filter.query);
      if (filter.blocked !== '') params.append('blocked', filter.blocked);
      if (filter.startTime) params.append('start_time', filter.startTime);
      if (filter.endTime) params.append('end_time', filter.endTime);
      
      const response = await api.get(`/logs/attacks?${params.toString()}`);
      setAttacks(response.data);
    } catch (error) {
      console.error('Failed to fetch attacks:', error);
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    fetchAttacks();
  }, [fetchAttacks]);

  return (
    <div className="page-container">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h1 className="page-title" style={{ marginBottom: 0 }}>Attack Logs</h1>
        <button onClick={fetchAttacks} className="btn btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <RefreshCw size={18} />
          Refresh
        </button>
      </div>

      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '1rem' }}>
          <Filter size={20} color="var(--text-secondary)" />
          <select 
            className="input" 
            style={{ width: 'auto' }}
            value={filter.type}
            onChange={(e) => setFilter({ ...filter, type: e.target.value })}
          >
            <option value="">All Types</option>
            <option value="sql_injection">SQL Injection</option>
            <option value="union_injection">Union Injection</option>
            <option value="boolean_blind">Boolean Blind</option>
            <option value="error_based">Error Based</option>
            <option value="time_based">Time Based</option>
            <option value="stacked_query">Stacked Query</option>
          </select>
          
          <select 
            className="input" 
            style={{ width: 'auto' }}
            value={filter.severity}
            onChange={(e) => setFilter({ ...filter, severity: e.target.value })}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            className="input"
            style={{ width: 'auto' }}
            value={filter.blocked}
            onChange={(e) => setFilter({ ...filter, blocked: e.target.value })}
          >
            <option value="">All Outcomes</option>
            <option value="true">Blocked</option>
            <option value="false">Allowed</option>
          </select>

          <input
            className="input"
            style={{ width: '220px' }}
            type="text"
            placeholder="Search IP, payload, or type"
            value={filter.query}
            onChange={(e) => setFilter({ ...filter, query: e.target.value })}
          />

          <input
            className="input"
            style={{ width: '190px' }}
            type="datetime-local"
            value={filter.startTime}
            onChange={(e) => setFilter({ ...filter, startTime: e.target.value })}
          />

          <input
            className="input"
            style={{ width: '190px' }}
            type="datetime-local"
            value={filter.endTime}
            onChange={(e) => setFilter({ ...filter, endTime: e.target.value })}
          />
        </div>
      </div>

      <div className="card">
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '2rem' }}>
            <span className="loading-spinner" />
          </div>
        ) : attacks.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Attack Type</th>
                <th>Severity</th>
                <th>Payload</th>
                <th>Detection Method</th>
                <th>IP Address</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {attacks.map((attack) => (
                <tr key={attack.id}>
                  <td>{attack.id}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <ShieldAlert size={16} color="var(--accent-danger)" />
                      {attack.attack_type}
                    </div>
                  </td>
                  <td>
                    <span className={`badge badge-${attack.severity === 'critical' ? 'danger' : attack.severity === 'high' ? 'warning' : 'info'}`}>
                      {attack.severity}
                    </span>
                  </td>
                  <td style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {attack.payload}
                  </td>
                  <td>{attack.detection_method}</td>
                  <td>{attack.ip_address}</td>
                  <td>{new Date(attack.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            No attacks found
          </div>
        )}
      </div>
    </div>
  );
};

export default AttackLogs;