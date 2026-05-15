import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  BarChart3, 
  Bell, 
  Brain, 
  Ban, 
  Key,
  Activity
} from 'lucide-react';

const Sidebar = () => {
  const links = [
    { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    { to: '/attacks', icon: ShieldAlert, label: 'Attack Logs' },
    { to: '/security', icon: BarChart3, label: 'Security Stats' },
    { to: '/alerts', icon: Bell, label: 'Alerts' },
    { to: '/ai-predictions', icon: Brain, label: 'AI Predictions' },
    { to: '/ip-blocking', icon: Ban, label: 'IP Blocking' },
    { to: '/capabilities', icon: Key, label: 'Capabilities' },
  ];

  return (
    <aside className="sidebar">
      {links.map((link) => (
        <NavLink
          key={link.to}
          to={link.to}
          className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <link.icon size={20} />
            <span>{link.label}</span>
          </div>
        </NavLink>
      ))}
      
      <div style={{ marginTop: '2rem', padding: '1rem', background: 'var(--bg-tertiary)', borderRadius: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-success)', marginBottom: '0.5rem' }}>
          <Activity size={18} />
          <span style={{ fontWeight: 600 }}>System Status</span>
        </div>
        <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
          All systems operational
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;