import React, { useState } from 'react';
import api from '../services/api';
import { Brain, Send, Loader } from 'lucide-react';

const AIPredictions = () => {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);

  const analyzeQuery = async () => {
    if (!query.trim()) return;
    
    setLoading(true);
    try {
      const response = await api.post('/detection/ai-analyze', null, {
        params: { query }
      });
      
      const prediction = response.data;
      setResult(prediction);
      setHistory([{ query, result: prediction, timestamp: new Date() }, ...history.slice(0, 9)]);
    } catch (error) {
      console.error('AI analysis failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const getPredictionColor = (prediction, score) => {
    if (prediction === 'malicious') return 'var(--accent-danger)';
    if (prediction === 'suspicious') return 'var(--accent-warning)';
    return 'var(--accent-success)';
  };

  return (
    <div className="page-container">
      <h1 className="page-title">AI-Powered Detection</h1>

      <div className="card" style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
          <Brain size={24} color="var(--accent-secondary)" />
          <span style={{ fontWeight: 600 }}>Query Analysis</span>
        </div>

        <div className="form-group">
          <label className="form-label">Enter SQL Query to Analyze</label>
          <textarea
            className="input"
            rows={4}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="SELECT * FROM users WHERE id = 1 OR 1=1"
            style={{ fontFamily: 'monospace' }}
          />
        </div>

        <button
          onClick={analyzeQuery}
          disabled={loading || !query.trim()}
          className="btn btn-primary"
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
        >
          {loading ? <Loader size={18} className="spin" /> : <Send size={18} />}
          Analyze with AI
        </button>

        {result && (
          <div style={{ marginTop: '1.5rem', padding: '1.5rem', background: 'var(--bg-tertiary)', borderRadius: '0.75rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
              <div>
                <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>
                  Prediction
                </div>
                <div style={{ 
                  fontWeight: 600, 
                  color: getPredictionColor(result.prediction, result.threat_score),
                  textTransform: 'uppercase'
                }}>
                  {result.prediction}
                </div>
              </div>
              
              <div>
                <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>
                  Threat Score
                </div>
                <div style={{ 
                  fontWeight: 700, 
                  fontSize: '1.5rem',
                  color: getPredictionColor(result.prediction, result.threat_score)
                }}>
                  {(result.threat_score * 100).toFixed(1)}%
                </div>
              </div>
              
              <div>
                <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>
                  Confidence
                </div>
                <div style={{ fontWeight: 600 }}>
                  {(result.confidence * 100).toFixed(1)}%
                </div>
              </div>
            </div>

            <div style={{ marginTop: '1rem' }}>
              <div className="security-meter">
                <div 
                  className={`security-meter-fill ${result.threat_score > 0.7 ? 'low' : result.threat_score > 0.4 ? 'medium' : 'high'}`}
                  style={{ width: `${result.threat_score * 100}%` }}
                />
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">Analysis History</div>
        {history.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {history.map((item, index) => (
              <div 
                key={index}
                style={{ 
                  padding: '1rem', 
                  background: 'var(--bg-tertiary)', 
                  borderRadius: '0.5rem',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}
              >
                <div style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginRight: '1rem' }}>
                  <code style={{ fontSize: '0.875rem' }}>{item.query}</code>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <span className={`badge badge-${item.result.prediction === 'malicious' ? 'danger' : item.result.prediction === 'suspicious' ? 'warning' : 'success'}`}>
                    {item.result.prediction}
                  </span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {(item.result.threat_score * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            No analysis history yet
          </div>
        )}
      </div>
    </div>
  );
};

export default AIPredictions;