import React, { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  BarChart3,
  Bell,
  Brain,
  Ban,
  Key,
  Activity,
  FileText,
  Settings,
  Terminal,
  Database,
  Keyboard,
  Code2,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';

const Sidebar = () => {
  const [collapsed, setCollapsed] = useState(() => {
    return localStorage.getItem('sidebar-collapsed') === 'true';
  });

  useEffect(() => {
    localStorage.setItem('sidebar-collapsed', String(collapsed));
  }, [collapsed]);

  const links = [
    { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    { to: '/attacks', icon: ShieldAlert, label: 'Attack Logs' },
    { to: '/security', icon: BarChart3, label: 'Security Stats' },
    { to: '/alerts', icon: Bell, label: 'Alerts' },
    { to: '/activity', icon: Activity, label: 'Activity' },
    { to: '/ai-predictions', icon: Brain, label: 'AI Predictions' },
    { to: '/workspace', icon: Code2, label: 'SQL Workspace' },
    { to: '/ip-blocking', icon: Ban, label: 'IP Blocking' },
    { to: '/capabilities', icon: Key, label: 'Capabilities' },
    { to: '/sandbox', icon: Terminal, label: 'Sandbox', badge: 'NEW' },
    { to: '/reports', icon: FileText, label: 'Reports' },
    { to: '/settings', icon: Settings, label: 'Settings' },
  ];

  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-topbar">
        {!collapsed && <span className="sidebar-title">Navigation</span>}
        <button
          type="button"
          className="sidebar-toggle"
          onClick={() => setCollapsed((value) => !value)}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-expanded={!collapsed}
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </div>

      {links.map((link) => (
        <NavLink
          key={link.to}
          to={link.to}
          className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          title={collapsed ? link.label : undefined}
        >
          <div className="sidebar-link-inner">
            <link.icon size={20} />
            <span className="sidebar-link-label">{link.label}</span>
            {link.badge && !collapsed && (
              <span style={{
                marginLeft: 'auto',
                padding: '0.125rem 0.5rem',
                background: 'var(--accent-primary)',
                color: 'white',
                borderRadius: '0.25rem',
                fontSize: '0.625rem',
                fontWeight: 700
              }}>
                {link.badge}
              </span>
            )}
          </div>
        </NavLink>
      ))}
      
      {collapsed ? (
        <div className="sidebar-chip" aria-label="System status: all systems operational">
          <span className="sidebar-chip-dot" />
          <span className="sidebar-chip-text">OK</span>
        </div>
      ) : (
        <div className="sidebar-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-success)', marginBottom: '0.5rem' }}>
            <Activity size={18} />
            <span style={{ fontWeight: 600 }}>System Status</span>
          </div>
          <div className="sidebar-card-copy">
            All systems operational
          </div>
        </div>
      )}
      
      {!collapsed && (
        <div className="sidebar-card sidebar-card-dashed">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
          <Keyboard size={14} />
          <span style={{ fontSize: '0.75rem', fontWeight: 600 }}>Keyboard Shortcuts</span>
        </div>
        <div style={{ fontSize: '0.625rem', color: 'var(--text-muted)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
            <span>Search</span>
            <span style={{ fontFamily: 'monospace', background: 'var(--bg-secondary)', padding: '0.125rem 0.25rem', borderRadius: '0.125rem' }}>Ctrl+K</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>Export</span>
            <span style={{ fontFamily: 'monospace', background: 'var(--bg-secondary)', padding: '0.125rem 0.25rem', borderRadius: '0.125rem' }}>Ctrl+E</span>
          </div>
        </div>
        </div>
      )}
    </aside>
  );
};

export default Sidebar;