import React, { useEffect, useState } from 'react';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

const AdminConfig = () => {
  const [items, setItems] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState(null);

  useEffect(() => {
    fetchConfig();
  }, []);

  const { user } = useAuth();
  if (!user || !(user.role === 'admin' || user.role === 'super_admin')) {
    return (
      <div className="page-container">
        <div className="card">You are not authorized to view this page.</div>
      </div>
    );
  }

  const fetchConfig = async () => {
    setLoading(true);
    try {
      const resp = await api.get('/admin/config');
      setItems(resp.data || {});
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to load config' });
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setMessage(null);
    try {
      const payload = Object.entries(items).filter(([k]) => k !== '__last_applied__').map(([k, v]) => ({ key: k, value: v.value || v, encrypted: !!v.encrypted }));
      await api.put('/admin/config', payload);
      setMessage({ type: 'success', text: 'Config saved' });
      await fetchConfig();
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to save' });
    } finally {
      setSaving(false);
    }
  };

  const handleApply = async () => {
    setMessage(null);
    try {
      const resp = await api.post('/admin/config/apply');
      setMessage({ type: 'success', text: `Applied. restart=${resp.data.restart}` });
    } catch (err) {
      const d = err?.response?.data?.detail || err.message;
      setMessage({ type: 'error', text: `Apply failed: ${d}` });
    }
  };

  const updateItem = (key, field, value) => {
    setItems(prev => ({ ...prev, [key]: { ...(prev[key] || {}), [field]: value } }));
  };

  if (loading) return <div className="page-container">Loading...</div>;

  return (
    <div className="page-container">
      <h1 className="page-title">Admin Configuration</h1>
      {message && (
        <div className={`alert ${message.type === 'success' ? 'alert-success' : 'alert-error'}`} style={{ marginBottom: '1rem' }}>
          {message.text}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="card">
          <h3>Config Keys</h3>
          <div style={{ display: 'grid', gap: '0.5rem', marginTop: '0.5rem' }}>
            {Object.keys(items).map(key => (
              <button key={key} className="btn" onClick={() => { /* noop */ }} style={{ textAlign: 'left' }}>{key}</button>
            ))}
          </div>
        </div>

        <div className="card">
          <h3>Editor</h3>
          {Object.keys(items).map(key => (
            <div key={key} style={{ marginBottom: '1rem' }}>
              <label className="form-label">{key}</label>
              <textarea className="input" rows={4} value={JSON.stringify(items[key].value || items[key], null, 2)} onChange={(e) => {
                try {
                  const parsed = JSON.parse(e.target.value);
                  updateItem(key, 'value', parsed);
                } catch {
                  updateItem(key, 'value', e.target.value);
                }
              }} />
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem', alignItems: 'center' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <input type="checkbox" checked={!!items[key].encrypted} onChange={(e) => updateItem(key, 'encrypted', e.target.checked)} /> Encrypted
                </label>
              </div>
            </div>
          ))}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem', marginTop: '1rem' }}>
            <button className="btn btn-secondary" onClick={handleSave} disabled={saving}>{saving ? 'Saving...' : 'Save'}</button>
            <button className="btn btn-primary" onClick={handleApply}>Apply & Restart</button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminConfig;
