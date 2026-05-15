import React, { useState, useEffect } from 'react';
import api from '../services/api';
import { Ban, Plus, Trash2, Globe } from 'lucide-react';

const IPBlocking = () => {
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newIP, setNewIP] = useState('');
  const [reason, setReason] = useState('');
  const [isPermanent, setIsPermanent] = useState(false);
  const [blocking, setBlocking] = useState(false);

  useEffect(() => {
    fetchBlockedIPs();
  }, []);

  const fetchBlockedIPs = async () => {
    try {
      const response = await api.get('/ip/blocked');
      setBlockedIPs(response.data);
    } catch (error) {
      console.error('Failed to fetch blocked IPs:', error);
    } finally {
      setLoading(false);
    }
  };

  const blockIP = async () => {
    if (!newIP.trim()) return;
    
    setBlocking(true);
    try {
      await api.post('/ip/block', {
        ip_address: newIP,
        reason: reason || 'Manual block',
        is_permanent: isPermanent
      });
      setNewIP('');
      setReason('');
      setIsPermanent(false);
      fetchBlockedIPs();
    } catch (error) {
      console.error('Failed to block IP:', error);
    } finally {
      setBlocking(false);
    }
  };

  const unblockIP = async (ipAddress) => {
    try {
      await api.post('/ip/unblock', null, {
        params: { ip_address: ipAddress }
      });
      fetchBlockedIPs();
    } catch (error) {
      console.error('Failed to unblock IP:', error);
    }
  };

  return (
    <div className="page-container">
      <h1 className="page-title">IP Blocking Management</h1>

      <div className="card" style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
          <Plus size={24} color="var(--accent-primary)" />
          <span style={{ fontWeight: 600 }}>Block New IP Address</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr auto', gap: '1rem', alignItems: 'end' }}>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">IP Address</label>
            <input
              type="text"
              className="input"
              value={newIP}
              onChange={(e) => setNewIP(e.target.value)}
              placeholder="192.168.1.100"
            />
          </div>
          
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Reason</label>
            <input
              type="text"
              className="input"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Suspicious activity"
            />
          </div>
          
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <input
                type="checkbox"
                checked={isPermanent}
                onChange={(e) => setIsPermanent(e.target.checked)}
              />
              Permanent Block
            </label>
          </div>
          
          <button
            onClick={blockIP}
            disabled={blocking || !newIP.trim()}
            className="btn btn-danger"
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <Ban size={18} />
            Block IP
          </button>
        </div>
      </div>

      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
          <Globe size={24} color="var(--accent-danger)" />
          <span style={{ fontWeight: 600 }}>Blocked IP Addresses ({blockedIPs.length})</span>
        </div>

        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '2rem' }}>
            <span className="loading-spinner" />
          </div>
        ) : blockedIPs.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Reason</th>
                <th>Blocked At</th>
                <th>Expires</th>
                <th>Type</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {blockedIPs.map((ip) => (
                <tr key={ip.ip_address}>
                  <td style={{ fontFamily: 'monospace' }}>{ip.ip_address}</td>
                  <td>{ip.reason || '-'}</td>
                  <td>{new Date(ip.blocked_at).toLocaleString()}</td>
                  <td>{ip.expires_at ? new Date(ip.expires_at).toLocaleString() : 'Never'}</td>
                  <td>
                    <span className={`badge ${ip.is_permanent ? 'badge-danger' : 'badge-warning'}`}>
                      {ip.is_permanent ? 'Permanent' : 'Temporary'}
                    </span>
                  </td>
                  <td>
                    <button
                      onClick={() => unblockIP(ip.ip_address)}
                      className="btn btn-secondary"
                      style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.25rem 0.5rem' }}
                    >
                      <Trash2 size={16} />
                      Unblock
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <Ban size={48} style={{ marginBottom: '1rem', opacity: 0.5 }} />
            <p>No blocked IP addresses</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default IPBlocking;