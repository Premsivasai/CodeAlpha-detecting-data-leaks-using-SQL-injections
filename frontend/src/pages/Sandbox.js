import React, { useState } from 'react';
import { useToast } from '../components/Toast';
import { Shield, Play, AlertTriangle, CheckCircle, Terminal, Code, Zap } from 'lucide-react';

const SAMPLE_PAYLOADS = [
  { name: 'Simple UNION', payload: "' UNION SELECT * FROM users--", type: 'union_based', severity: 'high' },
  { name: 'Boolean Tautology', payload: "admin' OR '1'='1", type: 'tautology', severity: 'high' },
  { name: 'Comment Injection', payload: "admin'--", type: 'comment_injection', severity: 'medium' },
  { name: 'Time-Based Blind', payload: "'; WAITFOR DELAY '00:00:05'--", type: 'time_based', severity: 'critical' },
  { name: 'Error-Based', payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", type: 'error_based', severity: 'medium' },
  { name: 'Stacked Query', payload: "'; DROP TABLE users;--", type: 'stacked_query', severity: 'critical' },
  { name: 'Information Schema', payload: " UNION SELECT * FROM information_schema.tables--", type: 'information_gathering', severity: 'medium' },
  { name: 'Normal Query', payload: "SELECT * FROM users WHERE id = 1", type: 'benign', severity: 'low' }
];

const Sandbox = () => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const toast = useToast();

  const analyzeQuery = async (payload = query) => {
    if (!payload.trim()) return;

    setIsAnalyzing(true);

    try {
      const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1'}/detection/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`
        },
        body: JSON.stringify({ query: payload })
      });

      const data = await response.json();

      const result = {
        id: Date.now(),
        query: payload,
        isMalicious: data.is_malicious,
        attackType: data.attack_type,
        severity: data.severity,
        confidence: data.confidence,
        detectionMethod: data.detection_method,
        timestamp: new Date().toISOString()
      };

      setResults(prev => [result, ...prev].slice(0, 10));

      if (result.isMalicious) {
        toast.attack(
          'Attack Detected! 🚨',
          `${result.attackType || 'SQL Injection'} blocked (${(result.confidence * 100).toFixed(0)}% confidence)`
        );
      } else {
        toast.success('Query Safe ✓', 'No malicious patterns detected');
      }
    } catch (error) {
      toast.error('Analysis Failed', error.message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const loadSamplePayload = (payload) => {
    setQuery(payload);
    analyzeQuery(payload);
  };

  const clearResults = () => {
    setResults([]);
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#ef4444',
      high: '#f59e0b',
      medium: '#3b82f6',
      low: '#10b981'
    };
    return colors[severity] || colors.low;
  };

  return (
    <div className="page-container">
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '2rem' }}>
        <div style={{ 
          background: 'linear-gradient(135deg, var(--accent-primary) 0%, var(--accent-secondary) 100%)',
          padding: '0.75rem',
          borderRadius: '0.75rem'
        }}>
          <Terminal size={24} color="white" />
        </div>
        <div>
          <h1 className="page-title" style={{ marginBottom: '0.25rem' }}>Detection Sandbox</h1>
          <p style={{ color: 'var(--text-secondary)', margin: 0 }}>
            Test SQL injection detection with sample payloads
          </p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <Code size={20} style={{ color: 'var(--accent-primary)' }} />
          <h3 style={{ margin: 0 }}>Query Analyzer</h3>
        </div>

        <div style={{ position: 'relative' }}>
          <textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Enter a SQL query to analyze..."
            style={{
              width: '100%',
              minHeight: '120px',
              padding: '1rem',
              paddingRight: '4rem',
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-color)',
              borderRadius: '0.75rem',
              color: 'var(--text-primary)',
              fontFamily: 'monospace',
              fontSize: '0.875rem',
              resize: 'vertical'
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && e.ctrlKey) {
                analyzeQuery();
              }
            }}
          />
          <button
            onClick={() => analyzeQuery()}
            disabled={isAnalyzing || !query.trim()}
            style={{
              position: 'absolute',
              bottom: '1rem',
              right: '1rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.5rem 1rem',
              background: isAnalyzing ? 'var(--bg-tertiary)' : 'var(--accent-primary)',
              color: 'white',
              border: 'none',
              borderRadius: '0.5rem',
              cursor: isAnalyzing ? 'not-allowed' : 'pointer',
              fontWeight: 500
            }}
          >
            <Zap size={16} />
            {isAnalyzing ? 'Analyzing...' : 'Analyze'}
          </button>
        </div>

        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
          Tip: Press Ctrl+Enter to analyze quickly
        </p>
      </div>

      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Play size={20} style={{ color: 'var(--accent-secondary)' }} />
            <h3 style={{ margin: 0 }}>Sample Payloads</h3>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '0.75rem' }}>
          {SAMPLE_PAYLOADS.map((sample, index) => (
            <button
              key={index}
              onClick={() => loadSamplePayload(sample.payload)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                padding: '0.75rem',
                background: 'var(--bg-tertiary)',
                border: '1px solid var(--border-color)',
                borderRadius: '0.5rem',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all 0.2s ease'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--accent-primary)';
                e.currentTarget.style.transform = 'translateY(-2px)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--border-color)';
                e.currentTarget.style.transform = 'translateY(0)';
              }}
            >
              <div style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: sample.severity === 'critical' ? '#ef4444' :
                           sample.severity === 'high' ? '#f59e0b' :
                           sample.severity === 'medium' ? '#3b82f6' : '#10b981',
                flexShrink: 0
              }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 500, fontSize: '0.875rem', marginBottom: '0.25rem' }}>
                  {sample.name}
                </div>
                <div style={{ 
                  fontSize: '0.75rem', 
                  color: 'var(--text-muted)',
                  fontFamily: 'monospace',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap'
                }}>
                  {sample.payload}
                </div>
              </div>
            </button>
          ))}
        </div>
      </div>

      {results.length > 0 && (
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Shield size={20} style={{ color: 'var(--accent-success)' }} />
              <h3 style={{ margin: 0 }}>Analysis Results</h3>
            </div>
            <button
              onClick={clearResults}
              style={{
                padding: '0.25rem 0.75rem',
                background: 'var(--bg-tertiary)',
                border: '1px solid var(--border-color)',
                borderRadius: '0.5rem',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                fontSize: '0.75rem'
              }}
            >
              Clear
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {results.map((result) => (
              <div
                key={result.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '1rem',
                  padding: '1rem',
                  background: result.isMalicious ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
                  border: `1px solid ${result.isMalicious ? '#ef4444' : '#10b981'}`,
                  borderRadius: '0.75rem',
                  animation: 'fadeIn 0.3s ease-out'
                }}
              >
                <div style={{ fontSize: '1.5rem' }}>
                  {result.isMalicious ? <AlertTriangle size={24} color="#ef4444" /> : <CheckCircle size={24} color="#10b981" />}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ 
                    fontFamily: 'monospace', 
                    fontSize: '0.875rem', 
                    marginBottom: '0.5rem',
                    color: 'var(--text-primary)'
                  }}>
                    {result.query.length > 80 ? result.query.slice(0, 80) + '...' : result.query}
                  </div>
                  <div style={{ display: 'flex', gap: '1rem', fontSize: '0.75rem' }}>
                    <span style={{ color: getSeverityColor(result.severity), fontWeight: 600 }}>
                      {result.severity.toUpperCase()}
                    </span>
                    <span style={{ color: 'var(--text-secondary)' }}>
                      {(result.confidence * 100).toFixed(0)}% confidence
                    </span>
                    <span style={{ color: 'var(--text-muted)' }}>
                      {result.detectionMethod}
                    </span>
                  </div>
                </div>
                <div style={{ 
                  padding: '0.25rem 0.75rem',
                  borderRadius: '0.25rem',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  background: result.isMalicious ? '#ef4444' : '#10b981',
                  color: 'white'
                }}>
                  {result.isMalicious ? 'BLOCKED' : 'ALLOWED'}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default Sandbox;