import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams, Link } from 'react-router-dom';
import api from '../services/api';
import { ArrowLeft, ShieldAlert, AlertTriangle, Activity, Clock3, Fingerprint, MapPin, Shield, TrendingUp, CheckCircle2, Loader2 } from 'lucide-react';

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

const IncidentDetail = () => {
  const { incidentId } = useParams();
  const navigate = useNavigate();
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [resolving, setResolving] = useState(false);

  const fetchIncident = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const response = await api.get(`/incidents/${incidentId}`);
      setIncident(response.data);
    } catch (err) {
      console.error('Failed to load incident detail:', err);
      setError('Unable to load incident details right now.');
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => {
    fetchIncident();
  }, [fetchIncident]);

  const riskColor = useMemo(() => {
    if (!incident) return 'low';
    if (incident.risk_score >= 80) return 'critical';
    if (incident.risk_score >= 60) return 'high';
    if (incident.risk_score >= 35) return 'medium';
    return 'low';
  }, [incident]);

  const uniqueSources = incident?.related_ips?.length || 0;
  const attackTypeCount = incident?.related_attack_types?.length || 0;
  const relatedAttacks = useMemo(() => incident?.attacks || [], [incident]);

  const eventTrend = useMemo(() => {
    if (!relatedAttacks.length) return [];
    return [...relatedAttacks]
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
      .map((attack, index) => ({
        label: new Date(attack.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        events: index + 1,
      }));
  }, [relatedAttacks]);

  const resolveIncident = useCallback(async () => {
    setResolving(true);
    setError('');
    try {
      await api.post(`/incidents/${incidentId}/resolve`, {
        resolution_note: 'Resolved from incident detail view',
      });
      await fetchIncident();
    } catch (err) {
      console.error('Failed to resolve incident:', err);
      setError('Unable to resolve this incident right now.');
    } finally {
      setResolving(false);
    }
  }, [incidentId, fetchIncident]);

  if (loading) {
    return (
      <div className="page-container">
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
          <span className="loading-spinner" />
        </div>
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="page-container">
        <button onClick={() => navigate(-1)} className="btn btn-secondary" style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <ArrowLeft size={18} />
          Back
        </button>
        <div className="card" style={{ padding: '2rem', textAlign: 'center' }}>
          <AlertTriangle size={40} color="var(--accent-warning)" style={{ marginBottom: '1rem' }} />
          <h2 style={{ marginBottom: '0.5rem' }}>Incident not available</h2>
          <p style={{ color: 'var(--text-secondary)' }}>{error || 'We could not locate this incident.'}</p>
          <button onClick={fetchIncident} className="btn btn-primary" style={{ marginTop: '1rem' }}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', gap: '1rem' }}>
        <div>
          <button onClick={() => navigate(-1)} className="btn btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <ArrowLeft size={18} />
            Back
          </button>
          <h1 className="page-title" style={{ marginBottom: 0 }}>{incident.title}</h1>
          <div style={{ color: 'var(--text-secondary)', marginTop: '0.35rem' }}>
            Incident #{incident.id} • Created {new Date(incident.created_at).toLocaleString()}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.5rem' }}>
          <span className={`badge ${getSeverityClass(incident.severity)}`}>{incident.severity}</span>
          <span className={`badge badge-${incident.status === 'open' ? 'warning' : 'success'}`}>{incident.status}</span>
          {incident.status !== 'resolved' && (
            <button
              onClick={resolveIncident}
              disabled={resolving}
              className="btn btn-primary"
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', minWidth: '150px', justifyContent: 'center' }}
            >
              {resolving ? <Loader2 size={16} className="spin" /> : <CheckCircle2 size={16} />}
              {resolving ? 'Resolving...' : 'Resolve Incident'}
            </button>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-danger)', marginBottom: '0.5rem' }}>
            <ShieldAlert size={22} />
            <span>Risk Score</span>
          </div>
          <div className="stat-value">{incident.risk_score}</div>
          <div className="stat-label">Derived from severity and event count</div>
          <div className="security-meter" style={{ marginTop: '0.75rem' }}>
            <div className={`security-meter-fill ${riskColor}`} style={{ width: `${incident.risk_score}%` }} />
          </div>
        </div>

        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-primary)', marginBottom: '0.5rem' }}>
            <Activity size={22} />
            <span>Events</span>
          </div>
          <div className="stat-value">{incident.event_count}</div>
          <div className="stat-label">Correlated attacks</div>
        </div>

        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-warning)', marginBottom: '0.5rem' }}>
            <MapPin size={22} />
            <span>Sources</span>
          </div>
          <div className="stat-value">{uniqueSources}</div>
          <div className="stat-label">Unique IPs</div>
        </div>

        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-success)', marginBottom: '0.5rem' }}>
            <TrendingUp size={22} />
            <span>Attack Types</span>
          </div>
          <div className="stat-value">{attackTypeCount}</div>
          <div className="stat-label">Distinct signatures</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem', marginBottom: '1.5rem' }}>
        <div className="card">
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Clock3 size={20} />
            Incident Timeline
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {eventTrend.length > 0 ? eventTrend.map((point) => (
              <div key={`${point.label}-${point.events}`} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.85rem 1rem', background: 'var(--bg-tertiary)', borderRadius: '0.75rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>{point.label}</span>
                <span className="badge badge-info">Event {point.events}</span>
              </div>
            )) : (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
                No correlated events available
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Fingerprint size={20} />
            Correlation Metadata
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem', color: 'var(--text-secondary)' }}>
            <div>
              <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Fingerprint</div>
              <div style={{ fontSize: '0.875rem', wordBreak: 'break-all', color: 'var(--text-primary)' }}>{incident.fingerprint || 'n/a'}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>First Seen</div>
              <div style={{ color: 'var(--text-primary)' }}>{incident.first_seen ? new Date(incident.first_seen).toLocaleString() : 'n/a'}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Last Seen</div>
              <div style={{ color: 'var(--text-primary)' }}>{incident.last_seen ? new Date(incident.last_seen).toLocaleString() : 'n/a'}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Attack Types</div>
              <div style={{ color: 'var(--text-primary)' }}>{incident.related_attack_types?.length ? incident.related_attack_types.join(', ') : 'n/a'}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Source IPs</div>
              <div style={{ color: 'var(--text-primary)' }}>{incident.related_ips?.length ? incident.related_ips.join(', ') : 'n/a'}</div>
            </div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Shield size={20} />
          Correlated Attack Events
        </div>
        {relatedAttacks.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Attack Type</th>
                <th>Severity</th>
                <th>Detection Method</th>
                <th>IP Address</th>
                <th>Timestamp</th>
                <th>Payload</th>
              </tr>
            </thead>
            <tbody>
              {relatedAttacks.map((attack) => (
                <tr key={attack.id}>
                  <td>{attack.id}</td>
                  <td>{attack.attack_type}</td>
                  <td>
                    <span className={`badge ${getSeverityClass(attack.severity)}`}>{attack.severity}</span>
                  </td>
                  <td>{attack.detection_method}</td>
                  <td>{attack.ip_address}</td>
                  <td>{new Date(attack.timestamp).toLocaleString()}</td>
                  <td style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis' }}>{attack.payload || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            This incident has no expanded attack list yet.
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertTriangle size={20} />
          Investigator Notes
        </div>
        <div style={{ color: 'var(--text-secondary)', lineHeight: 1.7 }}>
          <p style={{ marginTop: 0 }}>
            This incident groups attacks by fingerprint and activity window. The derived risk score grows with the number of correlated events and the severity of the underlying attacks.
          </p>
          <p style={{ marginBottom: 0 }}>
            Related activity is linked from the dashboard and can be extended to include resolution actions or analyst notes later.
          </p>
          {incident.status === 'resolved' && (
            <div style={{ marginTop: '1rem', padding: '1rem', background: 'rgba(16, 185, 129, 0.1)', borderRadius: '0.75rem', border: '1px solid rgba(16, 185, 129, 0.25)' }}>
              <strong style={{ color: 'var(--accent-success)' }}>Resolved</strong>
              <div style={{ marginTop: '0.35rem' }}>
                {incident.metadata?.resolution_note || 'This incident has been marked resolved.'}
              </div>
            </div>
          )}
          <div style={{ marginTop: '1rem' }}>
            <Link to="/dashboard" className="btn btn-secondary">Back to Dashboard</Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default IncidentDetail;
