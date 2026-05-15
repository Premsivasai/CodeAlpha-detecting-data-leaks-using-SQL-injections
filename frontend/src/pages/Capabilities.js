import React, { useState, useEffect } from 'react';
import api from '../services/api';
import { Key, Plus, Copy, Check, Clock } from 'lucide-react';

const Capabilities = () => {
  const [capabilities, setCapabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [newCapability, setNewCapability] = useState({
    permissions: ['read:own'],
    resources: ['profile'],
    expiration_days: 7
  });
  const [copiedToken, setCopiedToken] = useState(null);

  useEffect(() => {
    fetchCapabilities();
  }, []);

  const fetchCapabilities = async () => {
    try {
      const response = await api.get('/capability/list');
      setCapabilities(response.data.capabilities || []);
    } catch (error) {
      console.error('Failed to fetch capabilities:', error);
    } finally {
      setLoading(false);
    }
  };

  const generateCapability = async () => {
    setGenerating(true);
    try {
      const response = await api.post('/capability/generate', newCapability);
      fetchCapabilities();
      setNewCapability({
        permissions: ['read:own'],
        resources: ['profile'],
        expiration_days: 7
      });
    } catch (error) {
      console.error('Failed to generate capability:', error);
    } finally {
      setGenerating(false);
    }
  };

  const copyToken = (token) => {
    navigator.clipboard.writeText(token);
    setCopiedToken(token);
    setTimeout(() => setCopiedToken(null), 2000);
  };

  const availablePermissions = [
    'read:own', 'write:own', 'read:all', 'write:all', 'delete:all',
    'profile:read', 'profile:write', 'logs:read', 'logs:write',
    'users:read', 'users:write', 'users:delete', 'analytics:read',
    'analytics:write', 'detection:read', 'detection:write', 'alerts:read',
    'alerts:write', 'reports:create', 'settings:read', 'settings:write'
  ];

  const availableResources = ['profile', 'data', 'users', 'logs', 'analytics', 'detection', 'alerts', 'reports', 'settings'];

  const togglePermission = (perm) => {
    setNewCapability(prev => ({
      ...prev,
      permissions: prev.permissions.includes(perm)
        ? prev.permissions.filter(p => p !== perm)
        : [...prev.permissions, perm]
    }));
  };

  const toggleResource = (res) => {
    setNewCapability(prev => ({
      ...prev,
      resources: prev.resources.includes(res)
        ? prev.resources.filter(r => r !== res)
        : [...prev.resources, res]
    }));
  };

  return (
    <div className="page-container">
      <h1 className="page-title">Capability Management</h1>

      <div className="card" style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
          <Plus size={24} color="var(--accent-primary)" />
          <span style={{ fontWeight: 600 }}>Generate New Capability Token</span>
        </div>

        <div style={{ marginBottom: '1.5rem' }}>
          <label className="form-label">Permissions</label>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {availablePermissions.map(perm => (
              <button
                key={perm}
                onClick={() => togglePermission(perm)}
                className={`btn ${newCapability.permissions.includes(perm) ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}
              >
                {perm}
              </button>
            ))}
          </div>
        </div>

        <div style={{ marginBottom: '1.5rem' }}>
          <label className="form-label">Resources</label>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {availableResources.map(res => (
              <button
                key={res}
                onClick={() => toggleResource(res)}
                className={`btn ${newCapability.resources.includes(res) ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}
              >
                {res}
              </button>
            ))}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end' }}>
          <div className="form-group" style={{ marginBottom: 0, width: '200px' }}>
            <label className="form-label">Expiration (days)</label>
            <input
              type="number"
              className="input"
              value={newCapability.expiration_days}
              onChange={(e) => setNewCapability(prev => ({ ...prev, expiration_days: parseInt(e.target.value) || 7 }))}
              min={1}
              max={365}
            />
          </div>
          
          <button
            onClick={generateCapability}
            disabled={generating || newCapability.permissions.length === 0 || newCapability.resources.length === 0}
            className="btn btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <Key size={18} />
            Generate Token
          </button>
        </div>
      </div>

      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
          <Key size={24} color="var(--accent-secondary)" />
          <span style={{ fontWeight: 600 }}>Active Capability Tokens ({capabilities.length})</span>
        </div>

        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '2rem' }}>
            <span className="loading-spinner" />
          </div>
        ) : capabilities.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {capabilities.map((cap, index) => (
              <div 
                key={index}
                style={{ 
                  padding: '1.5rem', 
                  background: 'var(--bg-tertiary)', 
                  borderRadius: '0.75rem' 
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-muted)' }}>
                    <Clock size={16} />
                    <span style={{ fontSize: '0.875rem' }}>Expires: {new Date(cap.expires_at).toLocaleString()}</span>
                  </div>
                  <button
                    onClick={() => copyToken(cap.token)}
                    className="btn btn-secondary"
                    style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.25rem 0.5rem' }}
                  >
                    {copiedToken === cap.token ? <Check size={16} color="var(--accent-success)" /> : <Copy size={16} />}
                    {copiedToken === cap.token ? 'Copied!' : 'Copy'}
                  </button>
                </div>
                
                <code style={{ 
                  display: 'block', 
                  padding: '0.75rem', 
                  background: 'var(--bg-primary)', 
                  borderRadius: '0.5rem',
                  fontSize: '0.75rem',
                  wordBreak: 'break-all',
                  marginBottom: '1rem'
                }}>
                  {cap.token}
                </code>
                
                <div style={{ display: 'flex', gap: '1.5rem' }}>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                      Permissions
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                      {cap.permissions.map((perm, i) => (
                        <span key={i} className="badge badge-info" style={{ fontSize: '0.625rem' }}>
                          {perm}
                        </span>
                      ))}
                    </div>
                  </div>
                  
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                      Resources
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                      {cap.resources.map((res, i) => (
                        <span key={i} className="badge badge-success" style={{ fontSize: '0.625rem' }}>
                          {res}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <Key size={48} style={{ marginBottom: '1rem', opacity: 0.5 }} />
            <p>No active capability tokens</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Capabilities;