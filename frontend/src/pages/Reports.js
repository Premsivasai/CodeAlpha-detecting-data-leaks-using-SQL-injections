import React, { useState, useEffect } from 'react';
import api from '../services/api';
import {
  Download, Calendar,
  BarChart2, PieChart, TrendingUp, AlertCircle
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, LineChart, Line,
  PieChart as RechartsPie, Pie, Cell
} from 'recharts';

const Reports = () => {
  const [reportType, setReportType] = useState('attacks');
  const [dateRange, setDateRange] = useState('7d');
  const [loading, setLoading] = useState(true);
  const [reportData, setReportData] = useState(null);

  useEffect(() => {
    const fetchReportData = async () => {
      setLoading(true);
      try {
        const [statsRes, attacksRes, alertsRes] = await Promise.allSettled([
          api.get('/security/stats'),
          api.get('/logs/attacks?limit=1000'),
          api.get('/alerts')
        ]);

        const stats = statsRes.status === 'fulfilled' ? statsRes.value.data : {};
        const attacks = attacksRes.status === 'fulfilled' ? attacksRes.value.data : [];
        const alerts = alertsRes.status === 'fulfilled' ? alertsRes.value.data : [];

        const processedData = processReportData(stats, attacks, alerts, dateRange);
        setReportData(processedData);
      } catch (error) {
        console.error('Failed to fetch report data:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchReportData();
  }, [dateRange]);

  const processReportData = (stats, attacks, alerts, range) => {
    const days = range === '7d' ? 7 : range === '30d' ? 30 : 90;
    
    const attacksByDay = {};
    const attacksByType = {};
    const attacksBySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    const attacksByIP = {};

    const now = new Date();
    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(now - i * 24 * 60 * 60 * 1000);
      const dateKey = date.toISOString().split('T')[0];
      attacksByDay[dateKey] = 0;
    }

    if (attacks && Array.isArray(attacks)) {
      attacks.forEach(attack => {
        const attackDate = new Date(attack.timestamp).toISOString().split('T')[0];
        if (attacksByDay[attackDate] !== undefined) {
          attacksByDay[attackDate]++;
        }

        attacksByType[attack.attack_type] = (attacksByType[attack.attack_type] || 0) + 1;
        if (attack.severity) {
          attacksBySeverity[attack.severity] = (attacksBySeverity[attack.severity] || 0) + 1;
        }
        if (attack.ip_address) {
          attacksByIP[attack.ip_address] = (attacksByIP[attack.ip_address] || 0) + 1;
        }
      });
    }

    const topAttackTypes = Object.entries(attacksByType)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 5);

    const topIPs = Object.entries(attacksByIP)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const timeSeriesData = Object.entries(attacksByDay)
      .map(([date, count]) => ({
        date: new Date(date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        attacks: count
      }));

    const severityData = Object.entries(attacksBySeverity)
      .map(([name, value]) => ({ name, value }));

    const totalAttacks = stats?.total_attacks_blocked || 0;
    const attacksToday = stats?.attacks_today || 0;
    const detectionRate = totalAttacks > 0 
      ? Math.round((1 - (attacksToday / totalAttacks)) * 100)
      : 100;

    return {
      summary: {
        totalAttacks,
        attacksToday,
        blockedIPs: stats?.active_blocked_ips || 0,
        activeAlerts: stats?.active_alerts || 0,
        aiPredictions: stats?.ai_predictions_today || 0,
        avgDaily: Math.round(totalAttacks / days),
        detectionRate: Math.max(0, Math.min(100, detectionRate))
      },
      timeSeriesData,
      topAttackTypes,
      topIPs,
      severityData,
      alerts: (alerts && Array.isArray(alerts) ? alerts : []).slice(0, 10)
    };
  };

  const handleDownload = async (format) => {
    if (format === 'csv') {
      const csvContent = generateCSVContent(reportData, dateRange);
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `secureshield-report-${dateRange}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } else if (format === 'pdf') {
      const printContent = generatePrintableHTML(reportData, dateRange);
      const printWindow = window.open('', '_blank');
      printWindow.document.write(printContent);
      printWindow.document.close();
      printWindow.onload = () => {
        printWindow.print();
      };
    } else {
      const reportContent = generateReportContent(reportData, reportType, dateRange);
      const blob = new Blob([reportContent], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `secureshield-report-${dateRange}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  };

  const generateCSVContent = (data, range) => {
    if (!data) return '';

    const headers = ['Metric', 'Value'];
    const summaryRows = [
      ['Report Period', `Last ${range === '7d' ? '7 Days' : range === '30d' ? '30 Days' : '90 Days'}`],
      ['Total Attacks', data.summary.totalAttacks],
      ['Attacks Today', data.summary.attacksToday],
      ['Blocked IPs', data.summary.blockedIPs],
      ['Active Alerts', data.summary.activeAlerts],
      ['Detection Rate', `${data.summary.detectionRate}%`],
      ['', ''],
      ['Top Attack Types', ''],
      ...data.topAttackTypes.map((t, i) => [`${i + 1}. ${t.name}`, t.value]),
      ['', ''],
      ['Top Attacking IPs', ''],
      ...data.topIPs.map((ip, i) => [`${i + 1}. ${ip.ip}`, ip.count]),
      ['', ''],
      ['Severity Distribution', ''],
      ...data.severityData.map(s => [s.name, s.value]),
    ];

    const csvRows = [
      headers.join(','),
      ...summaryRows.map(row => row.map(cell => `"${cell}"`).join(','))
    ];

    return csvRows.join('\n');
  };

  const generatePrintableHTML = (data, range) => {
    return `
<!DOCTYPE html>
<html>
<head>
  <title>SecureShield Security Report</title>
  <style>
    body { font-family: Arial, sans-serif; padding: 40px; max-width: 800px; margin: 0 auto; }
    h1 { color: #1e40af; border-bottom: 3px solid #3b82f6; padding-bottom: 10px; }
    h2 { color: #1e40af; margin-top: 30px; }
    .summary { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }
    .stat { background: #f3f4f6; padding: 15px; border-radius: 8px; text-align: center; }
    .stat-value { font-size: 2em; font-weight: bold; color: #dc2626; }
    .stat-label { color: #6b7280; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { border: 1px solid #e5e7eb; padding: 12px; text-align: left; }
    th { background: #1e40af; color: white; }
    tr:nth-child(even) { background: #f9fafb; }
    .footer { margin-top: 40px; text-align: center; color: #6b7280; font-size: 12px; }
    @media print { body { padding: 20px; } }
  </style>
</head>
<body>
  <h1>SecureShield Security Report</h1>
  <p><strong>Period:</strong> Last ${range === '7d' ? '7 Days' : range === '30d' ? '30 Days' : '90 Days'}</p>
  <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>

  <h2>Executive Summary</h2>
  <div class="summary">
    <div class="stat">
      <div class="stat-value">${data.summary.totalAttacks}</div>
      <div class="stat-label">Total Attacks</div>
    </div>
    <div class="stat">
      <div class="stat-value">${data.summary.attacksToday}</div>
      <div class="stat-label">Today</div>
    </div>
    <div class="stat">
      <div class="stat-value">${data.summary.detectionRate}%</div>
      <div class="stat-label">Detection Rate</div>
    </div>
    <div class="stat">
      <div class="stat-value">${data.summary.blockedIPs}</div>
      <div class="stat-label">Blocked IPs</div>
    </div>
    <div class="stat">
      <div class="stat-value">${data.summary.activeAlerts}</div>
      <div class="stat-label">Active Alerts</div>
    </div>
    <div class="stat">
      <div class="stat-value">${data.summary.avgDaily}</div>
      <div class="stat-label">Avg Daily</div>
    </div>
  </div>

  <h2>Top Attack Types</h2>
  <table>
    <tr><th>Rank</th><th>Attack Type</th><th>Count</th></tr>
    ${data.topAttackTypes.map((t, i) => `<tr><td>${i + 1}</td><td>${t.name}</td><td>${t.value}</td></tr>`).join('')}
  </table>

  <h2>Top Attacking IPs</h2>
  <table>
    <tr><th>Rank</th><th>IP Address</th><th>Count</th></tr>
    ${data.topIPs.map((ip, i) => `<tr><td>${i + 1}</td><td>${ip.ip}</td><td>${ip.count}</td></tr>`).join('')}
  </table>

  <h2>Severity Distribution</h2>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    ${data.severityData.map(s => `<tr><td>${s.name}</td><td>${s.value}</td></tr>`).join('')}
  </table>

  <div class="footer">
    <p>SecureShield - Enterprise SQL Injection Detection Platform</p>
    <p>Generated on ${new Date().toISOString()}</p>
  </div>
</body>
</html>`;
  };

  const generateReportContent = (data, type, range) => {
    if (!data) return '';
    
    const lines = [
      '═══════════════════════════════════════════════════════════════',
      '           SECURESHIELD SECURITY REPORT',
      `           Date Range: Last ${range === '7d' ? '7 Days' : range === '30d' ? '30 Days' : '90 Days'}`,
      '═══════════════════════════════════════════════════════════════',
      '',
      'EXECUTIVE SUMMARY',
      '───────────────────────────────────────────────────────────────',
      `Total Attacks Detected: ${data.summary.totalAttacks}`,
      `Attacks Today: ${data.summary.attacksToday}`,
      `Currently Blocked IPs: ${data.summary.blockedIPs}`,
      `Active Alerts: ${data.summary.activeAlerts}`,
      `Detection Rate: ${data.summary.detectionRate}%`,
      '',
      'TOP ATTACK TYPES',
      '───────────────────────────────────────────────────────────────',
      ...data.topAttackTypes.map((t, i) => `${i + 1}. ${t.name}: ${t.value} attacks`),
      '',
      'TOP ATTACK SOURCE IPs',
      '───────────────────────────────────────────────────────────────',
      ...data.topIPs.slice(0, 5).map((ip, i) => `${i + 1}. ${ip.ip}: ${ip.count} attacks`),
      '',
      'Generated: ' + new Date().toISOString(),
      'SecureShield - Enterprise SQL Injection Detection Platform'
    ];
    
    return lines.join('\n');
  };

  const COLORS = ['#ef4444', '#f59e0b', '#3b82f6', '#10b981'];

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <span className="loading-spinner" />
      </div>
    );
  }

  return (
    <div className="page-container">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <h1 className="page-title">Security Reports</h1>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="btn btn-secondary" onClick={() => handleDownload('csv')}>
            <Download size={16} style={{ marginRight: '0.5rem' }} />
            Export CSV
          </button>
          <button className="btn btn-secondary" onClick={() => handleDownload('pdf')}>
            <Download size={16} style={{ marginRight: '0.5rem' }} />
            Export PDF
          </button>
          <button className="btn btn-secondary" onClick={() => handleDownload('txt')}>
            <Download size={16} style={{ marginRight: '0.5rem' }} />
            Export TXT
          </button>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Report Type</label>
            <select 
              className="input" 
              value={reportType} 
              onChange={(e) => setReportType(e.target.value)}
              style={{ width: '150px' }}
            >
              <option value="attacks">Attack Analysis</option>
              <option value="alerts">Alert Summary</option>
              <option value="trends">Trend Analysis</option>
            </select>
          </div>

          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Date Range</label>
            <select 
              className="input" 
              value={dateRange} 
              onChange={(e) => setDateRange(e.target.value)}
              style={{ width: '150px' }}
            >
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
              <option value="90d">Last 90 Days</option>
            </select>
          </div>

          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)' }}>
            <Calendar size={16} />
            <span>Report Generated: {new Date().toLocaleString()}</span>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-danger)', marginBottom: '0.5rem' }}>
            <AlertCircle size={20} />
            <span>Total Attacks</span>
          </div>
          <div className="stat-value">{reportData?.summary.totalAttacks || 0}</div>
          <div className="stat-label">Blocked</div>
        </div>

        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-warning)', marginBottom: '0.5rem' }}>
            <TrendingUp size={20} />
            <span>Today's Attacks</span>
          </div>
          <div className="stat-value">{reportData?.summary.attacksToday || 0}</div>
          <div className="stat-label">Detected</div>
        </div>

        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-primary)', marginBottom: '0.5rem' }}>
            <BarChart2 size={20} />
            <span>Avg Daily</span>
          </div>
          <div className="stat-value">{reportData?.summary.avgDaily || 0}</div>
          <div className="stat-label">Attacks</div>
        </div>

        <div className="stat-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-success)', marginBottom: '0.5rem' }}>
            <PieChart size={20} />
            <span>Detection Rate</span>
          </div>
          <div className="stat-value">{reportData?.summary.detectionRate || 0}%</div>
          <div className="stat-label">Rate</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem', marginBottom: '2rem' }}>
        <div className="card">
          <div className="card-header">
            <TrendingUp size={20} style={{ marginRight: '0.5rem' }} />
            Attack Timeline
          </div>
          <div style={{ height: '300px' }}>
            {reportData?.timeSeriesData?.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={reportData.timeSeriesData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                  <XAxis dataKey="date" stroke="var(--text-secondary)" />
                  <YAxis stroke="var(--text-secondary)" />
                  <Tooltip 
                    contentStyle={{ 
                      background: 'var(--bg-secondary)', 
                      border: '1px solid var(--border-color)',
                      borderRadius: '0.5rem'
                    }} 
                  />
                  <Line 
                    type="monotone" 
                    dataKey="attacks" 
                    stroke="var(--accent-danger)" 
                    strokeWidth={2}
                    dot={{ fill: 'var(--accent-danger)' }}
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-secondary)' }}>
                No data available
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <PieChart size={20} style={{ marginRight: '0.5rem' }} />
            Severity Distribution
          </div>
          <div style={{ height: '300px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <RechartsPie>
                <Pie
                  data={reportData?.severityData?.filter(s => s.value > 0) || []}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {reportData?.severityData?.filter(s => s.value > 0).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ 
                    background: 'var(--bg-secondary)', 
                    border: '1px solid var(--border-color)',
                    borderRadius: '0.5rem'
                  }} 
                />
              </RechartsPie>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        <div className="card">
          <div className="card-header">
            <BarChart2 size={20} style={{ marginRight: '0.5rem' }} />
            Top Attack Types
          </div>
          <div style={{ height: '300px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={reportData?.topAttackTypes || []} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                <XAxis type="number" stroke="var(--text-secondary)" />
                <YAxis dataKey="name" type="category" stroke="var(--text-secondary)" width={120} />
                <Tooltip 
                  contentStyle={{ 
                    background: 'var(--bg-secondary)', 
                    border: '1px solid var(--border-color)',
                    borderRadius: '0.5rem'
                  }} 
                />
                <Bar dataKey="value" fill="var(--accent-primary)" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <AlertCircle size={20} style={{ marginRight: '0.5rem' }} />
            Top Attacking IPs
          </div>
          <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Attack Count</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {reportData?.topIPs.slice(0, 8).map((ip, index) => (
                  <tr key={index}>
                    <td style={{ fontFamily: 'monospace' }}>{ip.ip}</td>
                    <td>{ip.count}</td>
                    <td>
                      <button className="btn btn-danger" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}>
                        Block
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Reports;