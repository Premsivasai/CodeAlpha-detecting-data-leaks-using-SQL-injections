import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, LogOut, ChevronDown, Mail, Phone, BadgeInfo, Settings, UserCircle2 } from 'lucide-react';

const Navbar = () => {
  const { user, isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef(null);

  const handleLogout = () => {
    setMenuOpen(false);
    logout();
    navigate('/login');
  };

  const userInitials = useMemo(() => {
    const source = user?.username || user?.email || 'U';
    return source
      .split(/[^a-zA-Z0-9]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0].toUpperCase())
      .join('') || 'U';
  }, [user]);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <nav className="navbar">
      <Link to="/" className="navbar-brand">
        <Shield size={28} />
        <span>SecureShield</span>
      </Link>
      
      {isAuthenticated && (
        <div className="navbar-links">
          <Link to="/dashboard" className="navbar-link">Dashboard</Link>
          <Link to="/security" className="navbar-link">Security</Link>
          <Link to="/alerts" className="navbar-link">Alerts</Link>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div className="user-menu" ref={menuRef}>
              <button
                type="button"
                className="user-menu-trigger"
                onClick={() => setMenuOpen((value) => !value)}
                aria-expanded={menuOpen}
                aria-haspopup="menu"
              >
                <span className="user-avatar">{userInitials}</span>
                <span className="user-menu-name">{user?.username || 'Account'}</span>
                <ChevronDown size={16} />
              </button>

              {menuOpen && (
                <div className="user-menu-panel" role="menu">
                  <div className="user-menu-header">
                    <div className="user-avatar user-avatar-large">{userInitials}</div>
                    <div>
                      <div className="user-menu-title">{user?.username || 'Unknown user'}</div>
                      <div className="user-menu-subtitle">{user?.role || 'user'}</div>
                    </div>
                  </div>

                  <div className="user-detail-list">
                    <div className="user-detail-row">
                      <UserCircle2 size={14} />
                      <span className="user-detail-label">Username</span>
                      <span className="user-detail-value">{user?.username || 'Not set'}</span>
                    </div>
                    <div className="user-detail-row">
                      <Mail size={14} />
                      <span className="user-detail-label">Email</span>
                      <span className="user-detail-value">{user?.email || 'Not set'}</span>
                    </div>
                    <div className="user-detail-row">
                      <Phone size={14} />
                      <span className="user-detail-label">Phone</span>
                      <span className="user-detail-value">{user?.phone_number || 'Not set'}</span>
                    </div>
                    <div className="user-detail-row">
                      <BadgeInfo size={14} />
                      <span className="user-detail-label">Role</span>
                      <span className="user-detail-value">{user?.role || 'user'}</span>
                    </div>
                  </div>

                  <div className="user-menu-actions">
                    <button type="button" className="user-menu-action" onClick={() => { setMenuOpen(false); navigate('/settings'); }}>
                      <Settings size={16} />
                      Account Settings
                    </button>
                    <button type="button" className="user-menu-action" onClick={handleLogout}>
                      <LogOut size={16} />
                      Logout
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </nav>
  );
};

export default Navbar;