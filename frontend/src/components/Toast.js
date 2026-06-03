import React, { createContext, useContext, useState, useCallback } from 'react';
import { X, CheckCircle, AlertTriangle, AlertCircle, Info, Bug } from 'lucide-react';

const ToastContext = createContext(null);

export const useToast = () => {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within ToastProvider');
  }
  return context;
};

const toastIcons = {
  success: CheckCircle,
  warning: AlertTriangle,
  error: AlertCircle,
  info: Info,
  attack: Bug
};

const toastColors = {
  success: { bg: 'rgba(16, 185, 129, 0.15)', border: 'var(--accent-success)', icon: 'var(--accent-success)' },
  warning: { bg: 'rgba(245, 158, 11, 0.15)', border: 'var(--accent-warning)', icon: 'var(--accent-warning)' },
  error: { bg: 'rgba(239, 68, 68, 0.15)', border: 'var(--accent-danger)', icon: 'var(--accent-danger)' },
  info: { bg: 'rgba(59, 130, 246, 0.15)', border: 'var(--accent-primary)', icon: 'var(--accent-primary)' },
  attack: { bg: 'rgba(239, 68, 68, 0.15)', border: 'var(--accent-danger)', icon: 'var(--accent-danger)' }
};

const Toast = ({ id, type, title, message, onClose, duration = 5000 }) => {
  const Icon = toastIcons[type] || Info;
  const colors = toastColors[type] || toastColors.info;

  useState(() => {
    if (duration > 0) {
      const timer = setTimeout(() => onClose(id), duration);
      return () => clearTimeout(timer);
    }
  }, [id, duration, onClose]);

  return (
    <div
      className="toast-item"
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: '0.75rem',
        padding: '1rem',
        background: colors.bg,
        border: `1px solid ${colors.border}`,
        borderRadius: '0.75rem',
        boxShadow: '0 10px 25px rgba(0, 0, 0, 0.3)',
        minWidth: '300px',
        maxWidth: '400px',
        animation: 'slideIn 0.3s ease-out',
        backdropFilter: 'blur(10px)'
      }}
    >
      <div style={{ color: colors.icon, flexShrink: 0, marginTop: '0.125rem' }}>
        <Icon size={20} />
      </div>
      <div style={{ flex: 1 }}>
        {title && (
          <div style={{ fontWeight: 600, marginBottom: '0.25rem', color: 'var(--text-primary)' }}>
            {title}
          </div>
        )}
        <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
          {message}
        </div>
      </div>
      <button
        onClick={() => onClose(id)}
        style={{
          background: 'none',
          border: 'none',
          color: 'var(--text-muted)',
          cursor: 'pointer',
          padding: '0.25rem',
          borderRadius: '0.25rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}
      >
        <X size={16} />
      </button>
    </div>
  );
};

const ToastContainer = ({ toasts, onClose }) => {
  if (!toasts || toasts.length === 0) return null;

  return (
    <div
      className="toast-container"
      style={{
        position: 'fixed',
        top: '1rem',
        right: '1rem',
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        gap: '0.5rem',
        maxHeight: 'calc(100vh - 2rem)',
        overflowY: 'auto'
      }}
    >
      {toasts.map((toast) => (
        <Toast key={toast.id} {...toast} onClose={onClose} />
      ))}
    </div>
  );
};

export const ToastProvider = ({ children }) => {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback((type, title, message, duration = 5000) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, type, title, message, duration }]);
  }, []);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  }, []);

  const toast = {
    success: (title, message) => addToast('success', title, message),
    warning: (title, message) => addToast('warning', title, message),
    error: (title, message) => addToast('error', title, message),
    info: (title, message) => addToast('info', title, message),
    attack: (title, message) => addToast('attack', title, message)
  };

  return (
    <ToastContext.Provider value={toast}>
      {children}
      <ToastContainer toasts={toasts} onClose={removeToast} />
    </ToastContext.Provider>
  );
};

export default ToastProvider;