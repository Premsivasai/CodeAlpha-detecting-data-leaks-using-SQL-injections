import React, { useState, useEffect, useCallback } from 'react';

export const AnimatedCounter = ({ value, duration = 1000, prefix = '', suffix = '' }) => {
  const [displayValue, setDisplayValue] = useState(0);

  useEffect(() => {
    let startTime;
    let animationFrame;

    const animate = (timestamp) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / duration, 1);
      
      const easeOut = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(value * easeOut);
      
      setDisplayValue(current);

      if (progress < 1) {
        animationFrame = requestAnimationFrame(animate);
      }
    };

    animationFrame = requestAnimationFrame(animate);

    return () => {
      if (animationFrame) cancelAnimationFrame(animationFrame);
    };
  }, [value, duration]);

  return (
    <span className="animated-counter">
      {prefix}{displayValue.toLocaleString()}{suffix}
    </span>
  );
};

export const StatCard = ({ icon: Icon, title, value, prefix = '', suffix = '', color = 'primary', trend = null }) => {
  const getColorClass = () => {
    const colors = {
      primary: 'var(--accent-primary)',
      danger: 'var(--accent-danger)',
      warning: 'var(--accent-warning)',
      success: 'var(--accent-success)',
      secondary: 'var(--accent-secondary)'
    };
    return colors[color] || colors.primary;
  };

  return (
    <div className="stat-card animate-on-hover">
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: getColorClass(), marginBottom: '0.5rem' }}>
        <Icon size={24} />
        <span>{title}</span>
        {trend && (
          <span className={`badge badge-${trend > 0 ? 'danger' : 'success'}`} style={{ marginLeft: 'auto' }}>
            {trend > 0 ? '+' : ''}{trend}%
          </span>
        )}
      </div>
      <div className="stat-value" style={{ color: getColorClass() }}>
        <AnimatedCounter value={value} prefix={prefix} suffix={suffix} />
      </div>
    </div>
  );
};

export const Skeleton = ({ width, height, borderRadius = '0.5rem', style = {} }) => (
  <div
    className="skeleton"
    style={{
      width: width || '100%',
      height: height || '1rem',
      borderRadius,
      background: 'linear-gradient(90deg, var(--bg-tertiary) 25%, var(--bg-secondary) 50%, var(--bg-tertiary) 75%)',
      backgroundSize: '200% 100%',
      animation: 'skeleton-pulse 1.5s ease-in-out infinite',
      ...style
    }}
  />
);

export const SkeletonCard = ({ showImage = false }) => (
  <div className="card">
    <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
      <Skeleton width="48px" height="48px" borderRadius="50%" />
      <div style={{ flex: 1 }}>
        <Skeleton width="60%" height="1rem" style={{ marginBottom: '0.5rem' }} />
        <Skeleton width="40%" height="0.75rem" />
      </div>
    </div>
    <Skeleton height="0.75rem" style={{ marginBottom: '0.5rem' }} />
    <Skeleton height="0.75rem" style={{ marginBottom: '0.5rem' }} />
    <Skeleton width="80%" height="0.75rem" />
  </div>
);

export const SkeletonTable = ({ rows = 5, columns = 4 }) => (
  <div className="card">
    <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem', padding: '0 1rem' }}>
      {Array.from({ length: columns }).map((_, i) => (
        <Skeleton key={i} width={`${100/columns}%`} height="1rem" />
      ))}
    </div>
    {Array.from({ length: rows }).map((_, rowIndex) => (
      <div key={rowIndex} style={{ display: 'flex', gap: '1rem', padding: '0.75rem 1rem', borderTop: '1px solid var(--border-color)' }}>
        {Array.from({ length: columns }).map((_, colIndex) => (
          <Skeleton key={colIndex} width={`${100/columns}%`} height="0.75rem" />
        ))}
      </div>
    ))}
  </div>
);

export const AttackTypeExplanation = ({ attackType, children }) => {
  const explanations = {
    union_based: {
      title: 'UNION-Based SQL Injection',
      description: 'Attacker uses UNION to combine malicious queries with legitimate ones, extracting data from other tables.',
      risk: 'High - Can expose sensitive database data',
      mitigation: 'Use parameterized queries, disable UNION in ORM'
    },
    boolean_based: {
      title: 'Boolean-Based Injection',
      description: 'Attacker injects conditions that return different results based on true/false evaluations.',
      risk: 'Medium - Can extract data through boolean logic',
      mitigation: 'Input validation, prepared statements'
    },
    time_based: {
      title: 'Time-Based Blind Injection',
      description: 'Attacker uses sleep functions to measure response time and infer information.',
      risk: 'High - Works even with no visible output',
      mitigation: 'Query timeout limits, disable sleep functions'
    },
    error_based: {
      title: 'Error-Based Injection',
      description: 'Attacker forces database errors that reveal structure and data.',
      risk: 'Medium - Information disclosure through errors',
      mitigation: 'Custom error pages, disable detailed errors'
    },
    stacked_query: {
      title: 'Stacked Queries',
      description: 'Attacker uses semicolons to execute multiple SQL statements.',
      risk: 'Critical - Can run multiple commands',
      mitigation: 'Disable multiple statements per query'
    },
    tautology: {
      title: 'Tautology Attack',
      description: 'Attacker injects conditions that are always true (e.g., OR 1=1) to bypass authentication.',
      risk: 'High - Full data access possible',
      mitigation: 'Input sanitization, parameterized queries'
    },
    comment_injection: {
      title: 'Comment Injection',
      description: 'Attacker uses SQL comments to truncate and modify query logic.',
      risk: 'Medium - Alters query behavior',
      mitigation: 'Escape special characters'
    }
  };

  const info = explanations[attackType] || { title: attackType, description: 'SQL injection attack', risk: 'Unknown', mitigation: 'Review and secure' };

  return (
    <div className="attack-type-tooltip">
      <div className="tooltip-header" style={{ background: 'var(--accent-primary)', padding: '0.75rem', borderRadius: '0.5rem 0.5rem 0 0' }}>
        <h4 style={{ margin: 0, color: 'white' }}>{info.title}</h4>
      </div>
      <div className="tooltip-body" style={{ padding: '0.75rem', background: 'var(--bg-secondary)' }}>
        <p style={{ marginBottom: '0.5rem', fontSize: '0.875rem' }}>{info.description}</p>
        <div style={{ marginBottom: '0.5rem' }}>
          <span style={{ color: 'var(--accent-danger)', fontWeight: 600, fontSize: '0.75rem' }}>Risk: </span>
          <span style={{ fontSize: '0.75rem' }}>{info.risk}</span>
        </div>
        <div>
          <span style={{ color: 'var(--accent-success)', fontWeight: 600, fontSize: '0.75rem' }}>Fix: </span>
          <span style={{ fontSize: '0.75rem' }}>{info.mitigation}</span>
        </div>
      </div>
    </div>
  );
};

export const QuickActionButton = ({ icon: Icon, label, onClick, color = 'primary', disabled = false }) => {
  const colorMap = {
    primary: 'var(--accent-primary)',
    danger: 'var(--accent-danger)',
    success: 'var(--accent-success)',
    warning: 'var(--accent-warning)'
  };

  return (
    <button
      className="quick-action-btn"
      onClick={onClick}
      disabled={disabled}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.5rem',
        padding: '0.75rem 1rem',
        background: disabled ? 'var(--bg-tertiary)' : colorMap[color],
        color: 'white',
        border: 'none',
        borderRadius: '0.5rem',
        cursor: disabled ? 'not-allowed' : 'pointer',
        fontWeight: 500,
        transition: 'all 0.2s ease',
        opacity: disabled ? 0.5 : 1
      }}
    >
      <Icon size={18} />
      {label}
    </button>
  );
};

export const useKeyboardShortcuts = (shortcuts) => {
  useEffect(() => {
    const handleKeyDown = (e) => {
      const key = e.key.toLowerCase();
      
      if (e.ctrlKey || e.metaKey) {
        const shortcut = shortcuts[key];
        if (shortcut && !e.target.matches('input, textarea')) {
          e.preventDefault();
          shortcut();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [shortcuts]);
};

export const SecurityBadge = ({ type, label }) => {
  const badges = {
    streak: { emoji: '🔥', color: '#f59e0b', label: 'Streak' },
    defender: { emoji: '🛡️', color: '#10b981', label: 'Defender' },
    first_block: { emoji: '⚡', color: '#3b82f6', label: 'First Block' },
    top_contributor: { emoji: '⭐', color: '#8b5cf6', label: 'Top' },
    analyst: { emoji: '🔍', color: '#ec4899', label: 'Analyst' },
    admin: { emoji: '👑', color: '#f59e0b', label: 'Admin' }
  };

  const badge = badges[type] || badges.defender;

  return (
    <span
      className="security-badge"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.25rem',
        padding: '0.25rem 0.5rem',
        background: `${badge.color}20`,
        color: badge.color,
        borderRadius: '999px',
        fontSize: '0.75rem',
        fontWeight: 600,
        border: `1px solid ${badge.color}40`
      }}
    >
      <span>{badge.emoji}</span>
      {label || badge.label}
    </span>
  );
};

export const SecurityScoreGauge = ({ score }) => {
  const getScoreColor = () => {
    if (score >= 80) return 'var(--accent-success)';
    if (score >= 60) return 'var(--accent-warning)';
    return 'var(--accent-danger)';
  };

  const getScoreLabel = () => {
    if (score >= 80) return 'Excellent';
    if (score >= 60) return 'Good';
    if (score >= 40) return 'Fair';
    return 'Needs Attention';
  };

  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="score-gauge" style={{ position: 'relative', width: '120px', height: '120px' }}>
      <svg width="120" height="120" viewBox="0 0 120 120">
        <circle
          cx="60"
          cy="60"
          r="45"
          fill="none"
          stroke="var(--bg-tertiary)"
          strokeWidth="10"
        />
        <circle
          cx="60"
          cy="60"
          r="45"
          fill="none"
          stroke={getScoreColor()}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          transform="rotate(-90 60 60)"
          style={{ transition: 'stroke-dashoffset 1s ease-out' }}
        />
      </svg>
      <div style={{
        position: 'absolute',
        top: '50%',
        left: '50%',
        transform: 'translate(-50%, -50%)',
        textAlign: 'center'
      }}>
        <div style={{ fontSize: '1.5rem', fontWeight: 700, color: getScoreColor() }}>{score}</div>
        <div style={{ fontSize: '0.625rem', color: 'var(--text-secondary)' }}>{getScoreLabel()}</div>
      </div>
    </div>
  );
};

export default {
  AnimatedCounter,
  StatCard,
  Skeleton,
  SkeletonCard,
  SkeletonTable,
  AttackTypeExplanation,
  QuickActionButton,
  useKeyboardShortcuts,
  SecurityBadge,
  SecurityScoreGauge
};