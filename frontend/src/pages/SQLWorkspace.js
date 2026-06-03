import React, { useState, useCallback, useRef, useEffect } from 'react';
import Editor from '@monaco-editor/react';
import { Play, Shield, Brain, RotateCcw, Table2, Terminal, AlertTriangle, CheckCircle, XCircle, BarChart3, FileJson, FileSpreadsheet, Loader2, History, Columns, Database, Code2, Minimize2, Maximize2, Copy } from 'lucide-react';
import api from '../services/api';

const DEFAULT_QUERY = `SELECT
  u.id,
  u.username,
  u.email,
  COUNT(a.id) as attack_count
FROM users u
LEFT JOIN attack_logs a ON a.user_id = u.id
GROUP BY u.id, u.username, u.email
ORDER BY attack_count DESC
LIMIT 20;`;

const INITIAL_TABS = [{ id: 'tab-1', name: 'query_1.sql', query: DEFAULT_QUERY }];

const SQLWorkspace = () => {
  const [tabs, setTabs] = useState(INITIAL_TABS);
  const [activeTabId, setActiveTabId] = useState('tab-1');
  const [connections, setConnections] = useState([]);
  const [selectedConnection, setSelectedConnection] = useState(null);
  const [activePanel, setActivePanel] = useState('results');
  const [queryResult, setQueryResult] = useState(null);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [sandboxResult, setSandboxResult] = useState(null);
  const [queryHistory, setQueryHistory] = useState([]);
  const [executing, setExecuting] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [sandboxing, setSandboxing] = useState(false);
  const [error, setError] = useState(null);
  const [showHistory, setShowHistory] = useState(true);
  const [editorHeight, setEditorHeight] = useState(55);
  const [maximized, setMaximized] = useState(false);
  const editorRef = useRef(null);
  const resizingRef = useRef(false);

  const editorContainerRef = useRef(null);

  useEffect(() => { fetchConnections(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { fetchHistory(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const el = editorContainerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      const editor = editorRef.current;
      if (editor) editor.layout();
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const fetchConnections = async () => {
    try {
      const res = await api.get('/connections');
      setConnections(res.data || []);
      if (res.data?.length > 0 && !selectedConnection) {
        setSelectedConnection(res.data[0]);
      }
    } catch (e) { console.error('Failed to fetch connections', e); }
  };

  const fetchHistory = async () => {
    try {
      const res = await api.get('/logs/attacks?limit=10');
      setQueryHistory(res.data || []);
    } catch (e) { /* silent */ }
  };

  const handleConnectionChange = (e) => {
    const conn = connections.find(c => c.id === parseInt(e.target.value));
    setSelectedConnection(conn);
  };

  const getActiveQuery = () => { const tab = tabs.find(t => t.id === activeTabId); return tab ? tab.query : ''; };
  const setActiveQuery = (query) => { setTabs(prev => prev.map(t => t.id === activeTabId ? { ...t, query } : t)); };

  const addTab = () => {
    const id = `tab-${Date.now()}`;
    setTabs(prev => [...prev, { id, name: `query_${prev.length + 1}.sql`, query: '-- New query\nSELECT ' }]);
    setActiveTabId(id);
  };

  const closeTab = (id, e) => {
    e.stopPropagation();
    if (tabs.length === 1) return;
    setTabs(prev => prev.filter(t => t.id !== id));
    if (activeTabId === id) setActiveTabId(tabs[0].id === id ? tabs[1]?.id : tabs[0].id);
  };

  const handleRun = async () => {
    if (!selectedConnection) { setError('Select a database connection first'); return; }
    setExecuting(true); setError(null); setQueryResult(null); setActivePanel('results');
    try {
      const res = await api.post(`/connections/${selectedConnection.id}/execute`, { query: getActiveQuery() });
      setQueryResult(res.data);
    } catch (e) { setError(e.response?.data?.detail || e.message || 'Execution failed'); }
    finally { setExecuting(false); }
  };

  const handleAIAnalyze = async () => {
    setAnalyzing(true); setError(null); setAiAnalysis(null); setActivePanel('ai');
    try {
      const res = await api.post('/detection/ai-analyze', { query: getActiveQuery() }, { headers: { 'Content-Type': 'application/json' }, params: { query: getActiveQuery() } });
      setAiAnalysis(res.data);
    } catch (e) {
      try {
        const fallback = await api.post('/detection/analyze', { query: getActiveQuery(), target: selectedConnection?.db_type || 'database' });
        setAiAnalysis({ threat_score: fallback.data.threat_score || 0, prediction: fallback.data.is_malicious ? 'malicious' : 'benign', confidence: fallback.data.confidence, details: fallback.data });
      } catch (e2) { setError('AI analysis failed'); }
    } finally { setAnalyzing(false); }
  };

  const handleSandbox = async () => {
    setSandboxing(true); setError(null); setSandboxResult(null); setActivePanel('sandbox');
    try {
      const res = await api.post('/detection/analyze', { query: getActiveQuery(), target: selectedConnection?.db_type || 'database' });
      setSandboxResult(res.data);
    } catch (e) { setError(e.response?.data?.detail || 'Sandbox analysis failed'); }
    finally { setSandboxing(false); }
  };

  const handleExplain = async () => {
    if (!selectedConnection) { setError('Select a database connection first'); return; }
    setExecuting(true); setError(null); setQueryResult(null); setActivePanel('explain');
    try {
      const explainQuery = `EXPLAIN ANALYZE ${getActiveQuery().replace(/;$/, '')}`;
      const res = await api.post(`/connections/${selectedConnection.id}/execute`, { query: explainQuery, fetch_all: true });
      setQueryResult({ ...res.data, is_explain: true });
    } catch (e) { setError(e.response?.data?.detail || 'EXPLAIN failed'); }
    finally { setExecuting(false); }
  };

  const handleCopyQuery = () => {
    navigator.clipboard.writeText(getActiveQuery());
  };

  const handleFormatQuery = () => {
    const editor = editorRef.current;
    if (editor) editor.getAction('editor.action.formatDocument')?.run();
  };

  const handleExportJSON = () => {
    if (!queryResult?.results) return;
    const blob = new Blob([JSON.stringify(queryResult.results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'query_results.json'; a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportCSV = () => {
    if (!queryResult?.results?.length) return;
    const rows = queryResult.results;
    const headers = Object.keys(rows[0]);
    const csv = [headers.join(','), ...rows.map(r => headers.map(h => JSON.stringify(r[h] ?? '')).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'query_results.csv'; a.click();
    URL.revokeObjectURL(url);
  };

  const handleEditorMount = (editor, monaco) => {
    editorRef.current = editor;
    window.monaco = monaco;
    editor.addAction({
      id: 'run-query', label: 'Run Query', keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter],
      run: () => handleRun(),
    });
    editor.addAction({
      id: 'format-query', label: 'Format Query', keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyF],
      run: () => editor.getAction('editor.action.formatDocument')?.run(),
    });
    setTimeout(() => editor.focus(), 100);
  };

  const getSeverityColor = (severity) => {
    const map = { critical: 'var(--accent-danger)', high: 'var(--accent-warning)', medium: 'var(--accent-primary)', low: 'var(--accent-success)', info: 'var(--text-muted)' };
    return map[severity?.toLowerCase()] || 'var(--text-muted)';
  };

  const getRiskBadge = (score) => {
    if (score >= 0.8) return { label: 'CRITICAL', color: 'var(--accent-danger)' };
    if (score >= 0.6) return { label: 'HIGH', color: 'var(--accent-warning)' };
    if (score >= 0.4) return { label: 'MEDIUM', color: 'var(--accent-primary)' };
    return { label: 'LOW', color: 'var(--accent-success)' };
  };


  const handleVResizeStart = useCallback((e) => {
    resizingRef.current = true;
    const handleMouseMove = (e) => {
      if (!resizingRef.current) return;
      const container = document.querySelector('.workspace-body');
      if (!container) return;
      const rect = container.getBoundingClientRect();
      const newH = ((e.clientY - rect.top) / rect.height) * 100;
      setEditorHeight(Math.min(Math.max(newH, 20), 80));
    };
    const handleMouseUp = () => { resizingRef.current = false; document.removeEventListener('mousemove', handleMouseMove); document.removeEventListener('mouseup', handleMouseUp); };
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, []);

  return (
    <div className="workspace-container">
      {/* ── Top Bar: Tabs + Connection ── */}
      <div className="workspace-header">
        <div className="workspace-tabs">
          {tabs.map(tab => (
            <div key={tab.id} className={`workspace-tab ${tab.id === activeTabId ? 'active' : ''}`} onClick={() => setActiveTabId(tab.id)}>
              <Terminal size={13} />
              <span>{tab.name}</span>
              <button className="workspace-tab-close" onClick={(e) => closeTab(tab.id, e)}>&times;</button>
            </div>
          ))}
          <button className="workspace-tab-add" onClick={addTab} title="New query tab (Ctrl+T)">+</button>
        </div>
        <div className="workspace-header-actions">
          <select className="workspace-connection-select" value={selectedConnection?.id || ''} onChange={handleConnectionChange}>
            <option value="" disabled>Select database...</option>
            {connections.map(c => <option key={c.id} value={c.id}>{c.name} ({c.db_type})</option>)}
          </select>
          <button className={`ws-toggle-btn ${showHistory ? 'active' : ''}`} onClick={() => setShowHistory(s => !s)} title="Toggle Query History">
            <History size={15} />
          </button>
        </div>
      </div>

      {/* ── Main Body ── */}
      <div className="workspace-body">
        {/* Left: History Panel */}
        {showHistory && (
          <div className="workspace-schema-panel">
            <div className="schema-header">
              <History size={13} /> Recent Activity
              <button className="ws-toggle-btn ws-toggle-btn-sm" onClick={() => setShowHistory(false)}><XCircle size={12} /></button>
            </div>
            <div className="history-list">
              {queryHistory.length > 0 ? queryHistory.map((item, i) => (
                <div key={item.id || i} className="history-item" onClick={() => { const q = item.payload || item.query || ''; if (q) { setActiveQuery(q); setActivePanel('results'); } }}>
                  <div className="history-item-type" style={{ color: getSeverityColor(item.severity) }}>
                    {item.attack_type || 'query'}
                  </div>
                  <div className="history-item-detail">
                    <span className="history-item-severity" style={{ color: getSeverityColor(item.severity) }}>{item.severity}</span>
                    <span className="history-item-time">{item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : ''}</span>
                  </div>
                  <div className="history-item-payload">{(item.payload || item.query || '').slice(0, 60)}</div>
                </div>
              )) : <div className="panel-placeholder" style={{ padding: '2rem' }}>No recent activity</div>}
            </div>
          </div>
        )}

        {/* Center: Editor + Output */}
        <div className="workspace-center">
          {/* Editor */}
          <div className="workspace-editor-area" ref={editorContainerRef} style={{ height: maximized ? '100%' : `${editorHeight}%` }}>
            <Editor
              height="100%"
              defaultLanguage="sql"
              theme="vs-dark"
              value={getActiveQuery()}
              onChange={(val) => setActiveQuery(val || '')}
              onMount={handleEditorMount}
              options={{
                minimap: { enabled: false },
                fontSize: 13,
                lineNumbers: 'on',
                roundedSelection: false,
                scrollBeyondLastLine: false,
                automaticLayout: false,
                suggestOnTriggerCharacters: true,
                tabCompletion: 'on',
                wordBasedSuggestions: 'currentDocument',
                quickSuggestions: true,
                formatOnPaste: true,
                bracketPairColorization: { enabled: true },
                padding: { top: 8 },
              }}
            />
            <div className="workspace-toolbar">
              <button className="btn btn-primary btn-sm" onClick={handleRun} disabled={executing || !selectedConnection}>
                {executing ? <Loader2 size={14} className="spin" /> : <Play size={14} />} Run <kbd>Ctrl+Enter</kbd>
              </button>
              <div className="toolbar-divider" />
              <button className="btn btn-secondary btn-sm" onClick={handleAIAnalyze} disabled={analyzing}>
                {analyzing ? <Loader2 size={14} className="spin" /> : <Brain size={14} />} AI Analyze
              </button>
              <button className="btn btn-secondary btn-sm" onClick={handleExplain} disabled={executing || !selectedConnection}>
                <BarChart3 size={14} /> Explain
              </button>
              <button className="btn btn-secondary btn-sm" onClick={handleSandbox} disabled={sandboxing}>
                {sandboxing ? <Loader2 size={14} className="spin" /> : <Shield size={14} />} Sandbox
              </button>
              <div className="toolbar-divider" />
              <button className="btn btn-text btn-sm" onClick={handleFormatQuery} title="Format SQL (Ctrl+Shift+F)">
                <Code2 size={14} />
              </button>
              <button className="btn btn-text btn-sm" onClick={handleCopyQuery} title="Copy query">
                <Copy size={14} />
              </button>
              <button className="btn btn-text btn-sm" onClick={() => setActiveQuery(DEFAULT_QUERY)} title="Reset to default">
                <RotateCcw size={14} />
              </button>
              <div className="toolbar-spacer" />
              <button className="btn btn-text btn-sm" onClick={handleExportJSON} disabled={!queryResult?.results} title="Export JSON">
                <FileJson size={14} />
              </button>
              <button className="btn btn-text btn-sm" onClick={handleExportCSV} disabled={!queryResult?.results?.length} title="Export CSV">
                <FileSpreadsheet size={14} />
              </button>
              <div className="toolbar-divider" />
              <button className="btn btn-text btn-sm" onClick={() => setMaximized(m => !m)} title={maximized ? 'Restore' : 'Maximize editor'}>
                {maximized ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
              </button>
            </div>
          </div>

          {/* Vertical Resizer */}
          {!maximized && <div className="workspace-vresizer" onMouseDown={handleVResizeStart} />}

          {/* Output */}
          {!maximized && (
            <div className="workspace-output-area" style={{ height: `${100 - editorHeight}%` }}>
              <div className="workspace-output-tabs">
                {[
                  { id: 'results', icon: Table2, label: 'Results', badge: queryResult?.row_count ?? null },
                  { id: 'explain', icon: BarChart3, label: 'Explain' },
                  { id: 'sandbox', icon: Shield, label: 'Sandbox', badge: sandboxResult?.sandbox_blocked ? 'BLOCKED' : null, badgeClass: 'badge-danger' },
                  { id: 'ai', icon: Brain, label: 'AI Analysis', badge: aiAnalysis ? `${Math.round((aiAnalysis.threat_score || 0) * 100)}%` : null, badgeClass: aiAnalysis?.threat_score >= 0.6 ? 'badge-danger' : '' },
                ].map(p => (
                  <button key={p.id} className={`workspace-output-tab ${activePanel === p.id ? 'active' : ''}`} onClick={() => setActivePanel(p.id)}>
                    <p.icon size={13} />
                    <span>{p.label}</span>
                    {p.badge !== null && p.badge !== undefined && (
                      <span className={`ws-badge ${p.badgeClass || ''}`}>{p.badge}</span>
                    )}
                  </button>
                ))}
                <div className="toolbar-spacer" />
                <span className="output-info">
                  {queryResult && !queryResult.is_explain && `Rows: ${queryResult.row_count} | ${queryResult.execution_time?.toFixed(2)}s`}
                </span>
              </div>

              <div className="workspace-output-content">
                {error && (
                  <div className="workspace-error">
                    <XCircle size={16} /> <span>{error}</span>
                    <button className="btn btn-text btn-sm" onClick={() => setError(null)}>&times;</button>
                  </div>
                )}

                {activePanel === 'results' && (
                  queryResult ? (
                    queryResult.is_explain ? (
                      <div className="explain-output">
                        <h4>Query Execution Plan</h4>
                        <pre>{JSON.stringify(queryResult.results, null, 2)}</pre>
                      </div>
                    ) : (
                      <div className="results-panel">
                        {queryResult.results?.length > 0 ? (
                          <div className="results-table-wrapper">
                            <table className="results-table">
                              <thead>
                                <tr>{Object.keys(queryResult.results[0]).map(key => <th key={key}>{key}</th>)}</tr>
                              </thead>
                              <tbody>
                                {queryResult.results.slice(0, 500).map((row, i) => (
                                  <tr key={i}>
                                    {Object.values(row).map((val, j) => (
                                      <td key={j}>{val === null ? <span className="null-value">NULL</span> : String(val).length > 100 ? String(val).slice(0, 100) + '...' : String(val)}</td>
                                    ))}
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                            {queryResult.results.length > 500 && (
                              <div className="results-truncated">Showing 500 of {queryResult.results.length} rows</div>
                            )}
                          </div>
                        ) : <div className="panel-placeholder">Query executed. No rows returned.</div>}
                      </div>
                    )
                  ) : executing ? (
                    <div className="panel-loading"><Loader2 size={20} className="spin" /> Executing query...</div>
                  ) : !selectedConnection ? (
                    <div className="panel-placeholder"><Database size={24} /> Select a database connection to run queries</div>
                  ) : (
                    <div className="panel-placeholder"><Play size={24} /> Run a query to see results</div>
                  )
                )}

                {activePanel === 'explain' && (
                  queryResult?.is_explain ? (
                    <div className="explain-output">
                      <h4>Execution Plan</h4>
                      <div className="explain-plan">
                        {Array.isArray(queryResult.results) ? queryResult.results.map((step, i) => (
                          <div key={i} className="explain-step">
                            <div className="explain-step-header">
                              <span className="explain-step-num">{i + 1}</span>
                              <span className="explain-step-op">{step['QUERY PLAN']?.split(' ')[0] || 'Operation'}</span>
                              <span className="explain-step-cost">Cost: {step['QUERY PLAN']?.match(/cost=([\d.]+)\.\.([\d.]+)/)?.[0] || 'N/A'}</span>
                            </div>
                            <pre className="explain-step-detail">{step['QUERY PLAN']}</pre>
                          </div>
                        )) : <pre>{JSON.stringify(queryResult.results, null, 2)}</pre>}
                      </div>
                    </div>
                  ) : executing ? (
                    <div className="panel-loading"><Loader2 size={20} className="spin" /> Generating plan...</div>
                  ) : (
                    <div className="panel-placeholder"><BarChart3 size={24} /> Click Explain to analyze query performance</div>
                  )
                )}

                {activePanel === 'sandbox' && (
                  sandboxResult ? (
                    <div className="sandbox-panel">
                      <div className={`sandbox-banner ${sandboxResult.sandbox_blocked ? 'banner-danger' : 'banner-success'}`}>
                        {sandboxResult.sandbox_blocked ? <XCircle size={20} /> : <CheckCircle size={20} />}
                        <span className="sandbox-banner-text">{sandboxResult.sandbox_blocked ? 'Query Blocked' : 'Query Allowed'}</span>
                      </div>
                      <div className="sandbox-grid">
                        <div className="sandbox-card">
                          <div className="sandbox-card-label">Threat Score</div>
                          <div className="sandbox-card-value" style={{ color: getSeverityColor(sandboxResult.risk_level) }}>
                            {Math.round((sandboxResult.threat_score || 0) * 100)}%
                          </div>
                        </div>
                        <div className="sandbox-card">
                          <div className="sandbox-card-label">Risk Level</div>
                          <div className="sandbox-card-value" style={{ color: getSeverityColor(sandboxResult.risk_level) }}>
                            {sandboxResult.risk_level || 'N/A'}
                          </div>
                        </div>
                        <div className="sandbox-card">
                          <div className="sandbox-card-label">Method</div>
                          <div className="sandbox-card-value">{sandboxResult.detection_method || 'N/A'}</div>
                        </div>
                        <div className="sandbox-card">
                          <div className="sandbox-card-label">Attack Type</div>
                          <div className="sandbox-card-value">{sandboxResult.attack_type || 'None'}</div>
                        </div>
                      </div>
                      {sandboxResult.explanation && (
                        <div className="sandbox-section">
                          <div className="sandbox-section-title"><AlertTriangle size={13} /> Analysis</div>
                          <p className="sandbox-text">{sandboxResult.explanation}</p>
                        </div>
                      )}
                      {sandboxResult.affected_tables?.length > 0 && (
                        <div className="sandbox-section">
                          <div className="sandbox-section-title"><Table2 size={13} /> Affected Tables</div>
                          <div className="sandbox-tags">{sandboxResult.affected_tables.map(t => <span key={t} className="sandbox-tag">{t}</span>)}</div>
                        </div>
                      )}
                      <div className="sandbox-recommendation" style={{ borderLeftColor: getSeverityColor(sandboxResult.risk_level) }}>
                        <strong>Recommendation:</strong> {sandboxResult.recommended_action || 'Review query before execution'}
                      </div>
                    </div>
                  ) : sandboxing ? (
                    <div className="panel-loading"><Loader2 size={20} className="spin" /> Running sandbox simulation...</div>
                  ) : (
                    <div className="panel-placeholder"><Shield size={24} /> Sandbox simulates query execution safely</div>
                  )
                )}

                {activePanel === 'ai' && (
                  aiAnalysis ? (
                    <div style={{ padding: '1rem' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem', padding: '1.5rem', background: 'var(--bg-secondary)', borderRadius: '8px', marginBottom: '1rem' }}>
                        <div style={{ position: 'relative', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                          <svg viewBox="0 0 120 120" style={{ width: '120px', height: '120px' }}>
                            <circle cx="60" cy="60" r="52" fill="none" stroke="var(--bg-tertiary)" strokeWidth="8" />
                            <circle cx="60" cy="60" r="52" fill="none" stroke={getRiskBadge(aiAnalysis.threat_score || 0).color} strokeWidth="8"
                              strokeDasharray={`${(aiAnalysis.threat_score || 0) * 327} 327`} strokeLinecap="round" transform="rotate(-90 60 60)" />
                          </svg>
                          <div style={{ position: 'absolute', top: '1.75rem', fontSize: '2rem', fontWeight: 800, lineHeight: 1, color: getRiskBadge(aiAnalysis.threat_score || 0).color }}>
                            {Math.round((aiAnalysis.threat_score || 0) * 100)}
                          </div>
                          <div style={{ position: 'absolute', bottom: '0.75rem', fontSize: '0.625rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Threat Score</div>
                        </div>
                        <div style={{ textAlign: 'center', fontSize: '0.875rem', fontWeight: 700, padding: '0.25rem 1rem', border: '2px solid', borderRadius: '4px', borderColor: getRiskBadge(aiAnalysis.threat_score || 0).color, color: getRiskBadge(aiAnalysis.threat_score || 0).color }}>
                          {getRiskBadge(aiAnalysis.threat_score || 0).label} RISK
                        </div>
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', marginBottom: '1rem' }}>
                        {[{ label: 'Confidence', value: `${Math.round((aiAnalysis.confidence || 0) * 100)}%` },
                          { label: 'Classification', value: aiAnalysis.prediction || 'N/A' },
                          { label: 'Threat Level', value: getRiskBadge(aiAnalysis.threat_score || 0).label },
                        ].map(s => (
                          <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0', borderBottom: '1px solid var(--border-color)', fontSize: '0.8125rem' }}>
                            <span style={{ color: 'var(--text-secondary)' }}>{s.label}</span>
                            <span style={{ color: s.label === 'Threat Level' ? getRiskBadge(aiAnalysis.threat_score || 0).color : 'var(--text-primary)', fontWeight: 600 }}>{s.value}</span>
                          </div>
                        ))}
                      </div>
                      {aiAnalysis.details && (
                        <div>
                          <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '0.5rem', fontWeight: 600 }}>Raw Analysis</div>
                          <pre style={{ fontSize: '0.75rem', background: 'var(--bg-secondary)', padding: '0.625rem', borderRadius: '4px', overflow: 'auto', maxHeight: '200px', color: 'var(--text-primary)' }}>{JSON.stringify(aiAnalysis.details, null, 2)}</pre>
                        </div>
                      )}
                    </div>
                  ) : analyzing ? (
                    <div className="panel-loading"><Loader2 size={20} className="spin" /> Running AI analysis...</div>
                  ) : (
                    <div className="panel-placeholder"><Brain size={24} /> Click AI Analyze to analyze query security</div>
                  )
                )}
              </div>
            </div>
          )}
        </div>

      </div>

      {/* ── Status Bar ── */}
      <div className="workspace-statusbar">
        <div className="statusbar-left">
          <span className="statusbar-item">
            <span className={`statusbar-dot ${selectedConnection ? 'connected' : 'disconnected'}`} />
            {selectedConnection ? `${selectedConnection.name}` : 'No Connection'}
          </span>
          <span className="statusbar-divider" />
          <span className="statusbar-item"><Database size={11} /> {selectedConnection?.db_type || 'SQL'}</span>
          <span className="statusbar-divider" />
          <span className="statusbar-item"><Shield size={11} /> SSL {selectedConnection?.ssl_enabled ? 'On' : 'Off'}</span>
        </div>
        <div className="statusbar-right">
          <span className="statusbar-item"><Brain size={11} /> AI {analyzing ? 'Busy' : 'Ready'}</span>
          <span className="statusbar-divider" />
          <span className="statusbar-item"><Columns size={11} /> Ln {getActiveQuery().split('\n').length}</span>
        </div>
      </div>
    </div>
  );
};

export default SQLWorkspace;
