import React, { useState, useEffect } from 'react';
import api from '../services/api';
import {
  Settings as SettingsIcon,
  Shield, Bell, Lock,
  Database, Save, RefreshCw,
  AlertTriangle, CheckCircle
} from 'lucide-react';

const Settings = () => {
  const [activeTab, setActiveTab] = useState('general');
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState(null);
  const [testResult, setTestResult] = useState(null);

  const [settings, setSettings] = useState({
    general: {
      autoRefresh: true,
      refreshInterval: 30,
      language: 'en'
    },
    security: {
      mfaEnabled: false,
      sessionTimeout: 30,
      ipWhitelist: false,
      allowedIPs: [],
      apiKeyRequired: true
    },
    notifications: {
      emailAlerts: true,
      slackWebhook: '',
      webhookUrl: '',
      alertOnCritical: true,
      alertOnHigh: true,
      alertOnMedium: false,
      alertOnLow: false
    },
    detection: {
      aiDetectionEnabled: true,
      threatScoreThreshold: 0.7,
      autoBlockEnabled: true,
      logAllQueries: false,
      maxQueryLength: 5000
    },
    database: {
      postgresHost: 'localhost',
      postgresPort: 5432,
      postgresDatabase: 'secureshield',
      redisHost: 'localhost',
      redisPort: 6379
    }
  });

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      const response = await api.get('/users/me/settings');
      if (response.data) {
        setSettings(prev => ({
          ...prev,
          ...response.data,
          general: { ...prev.general, ...(response.data.general || {}) },
          security: { ...prev.security, ...(response.data.security || {}) },
          notifications: { ...prev.notifications, ...(response.data.notifications || {}) },
          detection: { ...prev.detection, ...(response.data.detection || {}) },
          database: { ...prev.database, ...(response.data.database || {}) }
        }));
      }
    } catch (error) {
      console.error('Failed to fetch settings:', error);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setMessage(null);

    try {
      await api.put('/users/me/settings', settings);
      setMessage({ type: 'success', text: 'Settings saved successfully!' });
    } catch (error) {
      setMessage({ type: 'error', text: 'Failed to save settings' });
    } finally {
      setSaving(false);
      setTimeout(() => setMessage(null), 3000);
    }
  };

  const testConnection = async () => {
    setTestResult(null);
    try {
      const payload = {
        type: 'db',
        host: settings.database.postgresHost,
        port: settings.database.postgresPort,
        database: settings.database.postgresDatabase
      };

      const resp = await api.post('/admin/config/test', payload);
      setTestResult({ ok: resp.data.ok, details: resp.data.details });
    } catch (err) {
      const details = err?.response?.data?.detail || err.message || String(err);
      setTestResult({ ok: false, details });
    }
    setTimeout(() => setTestResult(null), 8000);
  };

  const updateSetting = (category, key, value) => {
    setSettings(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        [key]: value
      }
    }));
  };

  const tabs = [
    { id: 'general', label: 'General', icon: SettingsIcon },
    { id: 'security', label: 'Security', icon: Lock },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'detection', label: 'Detection', icon: Shield },
    { id: 'database', label: 'Database', icon: Database }
  ];

  return (
    <div className="page-container">
      <h1 className="page-title">Settings</h1>

      {message && (
        <div className={`alert ${message.type === 'success' ? 'alert-success' : 'alert-error'}`} style={{ marginBottom: '1.5rem' }}>
          {message.type === 'success' ? <CheckCircle size={20} /> : <AlertTriangle size={20} />}
          <span style={{ marginLeft: '0.5rem' }}>{message.text}</span>
        </div>
      )}

      <div style={{ display: 'flex', gap: '1.5rem' }}>
        <div className="card" style={{ width: '250px', padding: '1rem', height: 'fit-content' }}>
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                width: '100%',
                padding: '0.75rem 1rem',
                marginBottom: '0.5rem',
                background: activeTab === tab.id ? 'var(--bg-tertiary)' : 'transparent',
                border: 'none',
                borderRadius: '0.5rem',
                color: activeTab === tab.id ? 'var(--accent-primary)' : 'var(--text-secondary)',
                cursor: 'pointer',
                textAlign: 'left'
              }}
            >
              <tab.icon size={18} />
              <span>{tab.label}</span>
            </button>
          ))}
        </div>

        <div style={{ flex: 1 }}>
          {activeTab === 'general' && (
            <div className="card">
              <div className="card-header">
                <SettingsIcon size={20} style={{ marginRight: '0.5rem' }} />
                General Settings
              </div>

              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={settings.general.autoRefresh}
                    onChange={(e) => updateSetting('general', 'autoRefresh', e.target.checked)}
                  />
                  Auto-refresh dashboard
                </label>
              </div>

              <div className="form-group">
                <label className="form-label">Refresh Interval (seconds)</label>
                <input
                  type="number"
                  className="input"
                  value={settings.general.refreshInterval}
                  onChange={(e) => updateSetting('general', 'refreshInterval', parseInt(e.target.value))}
                  min={10}
                  max={300}
                />
              </div>

              <div className="form-group">
                <label className="form-label">Language</label>
                <select
                  className="input"
                  value={settings.general.language}
                  onChange={(e) => updateSetting('general', 'language', e.target.value)}
                >
                  <option value="en">English</option>
                  <option value="es">Spanish</option>
                  <option value="fr">French</option>
                  <option value="de">German</option>
                </select>
              </div>
            </div>
          )}

          {activeTab === 'security' && (
            <div className="card">
              <div className="card-header">
                <Lock size={20} style={{ marginRight: '0.5rem' }} />
                Security Settings
              </div>

              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={settings.security.mfaEnabled}
                    onChange={(e) => updateSetting('security', 'mfaEnabled', e.target.checked)}
                  />
                  Enable Two-Factor Authentication
                </label>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  Require TOTP code on login for additional security
                </p>
              </div>

              <div className="form-group">
                <label className="form-label">Session Timeout (minutes)</label>
                <input
                  type="number"
                  className="input"
                  value={settings.security.sessionTimeout}
                  onChange={(e) => updateSetting('security', 'sessionTimeout', parseInt(e.target.value))}
                  min={5}
                  max={1440}
                />
              </div>

              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={settings.security.ipWhitelist}
                    onChange={(e) => updateSetting('security', 'ipWhitelist', e.target.checked)}
                  />
                  Enable IP Whitelist
                </label>
              </div>

              {settings.security.ipWhitelist && (
                <div className="form-group">
                  <label className="form-label">Allowed IPs (one per line)</label>
                  <textarea
                    className="input"
                    rows={4}
                    placeholder="192.168.1.1&#10;10.0.0.0/24"
                    value={settings.security.allowedIPs.join('\n')}
                    onChange={(e) => updateSetting('security', 'allowedIPs', e.target.value.split('\n'))}
                  />
                </div>
              )}

              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={settings.security.apiKeyRequired}
                    onChange={(e) => updateSetting('security', 'apiKeyRequired', e.target.checked)}
                  />
                  Require API Key for External Access
                </label>
              </div>
            </div>
          )}

          {activeTab === 'notifications' && (
            <div className="card">
              <div className="card-header">
                <Bell size={20} style={{ marginRight: '0.5rem' }} />
                Notification Settings
              </div>

              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={settings.notifications.emailAlerts}
                    onChange={(e) => updateSetting('notifications', 'emailAlerts', e.target.checked)}
                  />
                  Email Alerts
                </label>
              </div>

              <div className="form-group">
                <label className="form-label">Webhook URL</label>
                <input
                  type="url"
                  className="input"
                  placeholder="https://your-webhook.com/notify"
                  value={settings.notifications.webhookUrl}
                  onChange={(e) => updateSetting('notifications', 'webhookUrl', e.target.value)}
                />
              </div>

              <div className="form-group">
                <label className="form-label">Slack Webhook</label>
                <input
                  type="url"
                  className="input"
                  placeholder="https://hooks.slack.com/services/..."
                  value={settings.notifications.slackWebhook}
                  onChange={(e) => updateSetting('notifications', 'slackWebhook', e.target.value)}
                />
              </div>

              <div style={{ marginTop: '1.5rem' }}>
                <h4 style={{ marginBottom: '1rem' }}>Alert Severity Settings</h4>
                
                <div className="form-group">
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={settings.notifications.alertOnCritical}
                      onChange={(e) => updateSetting('notifications', 'alertOnCritical', e.target.checked)}
                    />
                    <span className="badge badge-danger">Critical</span> alerts
                  </label>
                </div>

                <div className="form-group">
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={settings.notifications.alertOnHigh}
                      onChange={(e) => updateSetting('notifications', 'alertOnHigh', e.target.checked)}
                    />
                    <span className="badge badge-warning">High</span> alerts
                  </label>
                </div>

                <div className="form-group">
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={settings.notifications.alertOnMedium}
                      onChange={(e) => updateSetting('notifications', 'alertOnMedium', e.target.checked)}
                    />
                    <span className="badge badge-info">Medium</span> alerts
                  </label>
                </div>

                <div className="form-group">
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={settings.notifications.alertOnLow}
                      onChange={(e) => updateSetting('notifications', 'alertOnLow', e.target.checked)}
                    />
                    <span className="badge badge-success">Low</span> alerts
                  </label>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'detection' && (
            <div className="card">
              <div className="card-header">
                <Shield size={20} style={{ marginRight: '0.5rem' }} />
                Detection Settings
              </div>

              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={settings.detection.aiDetectionEnabled}
                    onChange={(e) => updateSetting('detection', 'aiDetectionEnabled', e.target.checked)}
                  />
                  Enable AI-Powered Detection
                </label>
              </div>

              <div className="form-group">
                <label className="form-label">Threat Score Threshold</label>
                <input
                  type="range"
                  min="0"
                  max="100"
                  value={settings.detection.threatScoreThreshold * 100}
                  onChange={(e) => updateSetting('detection', 'threatScoreThreshold', parseInt(e.target.value) / 100)}
                  style={{ width: '100%' }}
                />
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  <span>More permissive</span>
                  <span>{Math.round(settings.detection.threatScoreThreshold * 100)}%</span>
                  <span>Stricter</span>
                </div>
              </div>

              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={settings.detection.autoBlockEnabled}
                    onChange={(e) => updateSetting('detection', 'autoBlockEnabled', e.target.checked)}
                  />
                  Automatically Block High-Risk Attacks
                </label>
              </div>

              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={settings.detection.logAllQueries}
                    onChange={(e) => updateSetting('detection', 'logAllQueries', e.target.checked)}
                  />
                  Log All Database Queries (not just attacks)
                </label>
              </div>

              <div className="form-group">
                <label className="form-label">Max Query Length to Log</label>
                <input
                  type="number"
                  className="input"
                  value={settings.detection.maxQueryLength}
                  onChange={(e) => updateSetting('detection', 'maxQueryLength', parseInt(e.target.value))}
                  min={100}
                  max={50000}
                />
              </div>
            </div>
          )}

          {activeTab === 'database' && (
            <div className="card">
              <div className="card-header">
                <Database size={20} style={{ marginRight: '0.5rem' }} />
                Database Configuration
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div className="form-group">
                  <label className="form-label">PostgreSQL Host</label>
                  <input
                    type="text"
                    className="input"
                    value={settings.database.postgresHost}
                    onChange={(e) => updateSetting('database', 'postgresHost', e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">PostgreSQL Port</label>
                  <input
                    type="number"
                    className="input"
                    value={settings.database.postgresPort}
                    onChange={(e) => updateSetting('database', 'postgresPort', parseInt(e.target.value))}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Database Name</label>
                  <input
                    type="text"
                    className="input"
                    value={settings.database.postgresDatabase}
                    onChange={(e) => updateSetting('database', 'postgresDatabase', e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Redis Host</label>
                  <input
                    type="text"
                    className="input"
                    value={settings.database.redisHost}
                    onChange={(e) => updateSetting('database', 'redisHost', e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Redis Port</label>
                  <input
                    type="number"
                    className="input"
                    value={settings.database.redisPort}
                    onChange={(e) => updateSetting('database', 'redisPort', parseInt(e.target.value))}
                  />
                </div>
              </div>

              <div style={{ marginTop: '1.5rem', display: 'flex', gap: '1rem' }}>
                <button className="btn btn-secondary" onClick={testConnection}>
                  <RefreshCw size={16} style={{ marginRight: '0.5rem' }} />
                  Test Connection
                </button>
                {testResult && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {testResult.ok ? <CheckCircle size={16} style={{ color: 'var(--accent-success)' }} /> : <AlertTriangle size={16} style={{ color: 'var(--accent-danger)' }} />}
                    <span style={{ color: testResult.ok ? 'var(--accent-success)' : 'var(--accent-danger)' }}>{testResult.details}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          <div style={{ marginTop: '1.5rem', display: 'flex', justifyContent: 'flex-end' }}>
            <button
              className="btn btn-primary"
              onClick={handleSave}
              disabled={saving}
            >
              {saving ? (
                <span className="loading-spinner" />
              ) : (
                <>
                  <Save size={16} style={{ marginRight: '0.5rem' }} />
                  Save Settings
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;