import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Brain, Lock, Activity, Zap, BarChart3, ArrowRight, Database, Server, Globe } from 'lucide-react';

const Landing = () => {
  const navigate = useNavigate();
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 50);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const features = [
    {
      icon: Brain,
      title: 'AI-Powered Detection',
      description: 'Machine learning models detect sophisticated SQL injection attacks in real-time with 99.9% accuracy.',
      color: '#3b82f6'
    },
    {
      icon: Shield,
      title: 'Zero-Trust Security',
      description: 'Advanced zero-trust architecture with continuous authentication and device fingerprinting.',
      color: '#10b981'
    },
    {
      icon: Lock,
      title: 'Encryption & Privacy',
      description: 'End-to-end encryption with hardware security module support for sensitive data protection.',
      color: '#6366f1'
    },
    {
      icon: Activity,
      title: 'Real-Time Monitoring',
      description: 'Live attack feed with instant alerts and automated incident response capabilities.',
      color: '#f59e0b'
    },
    {
      icon: Zap,
      title: 'Threat Intelligence',
      description: 'Global threat intelligence feeds integrated with predictive attack pattern recognition.',
      color: '#ef4444'
    },
    {
      icon: BarChart3,
      title: 'Advanced Analytics',
      description: 'Comprehensive dashboards with ML-powered insights and customizable security reports.',
      color: '#8b5cf6'
    }
  ];

  const stats = [
    { value: '99.9%', label: 'Detection Accuracy' },
    { value: '<50ms', label: 'Response Time' },
    { value: '24/7', label: 'Active Monitoring' },
    { value: '50K+', label: 'Attacks Blocked' }
  ];

  return (
    <div className="landing-page">
      <style>{`
        .landing-page {
          min-height: 100vh;
          background: var(--bg-primary);
          overflow-x: hidden;
        }
        
        .landing-nav {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          z-index: 1000;
          padding: 1.25rem 2rem;
          display: flex;
          justify-content: space-between;
          align-items: center;
          background: ${scrolled ? 'rgba(15, 23, 42, 0.9)' : 'transparent'};
          backdrop-filter: ${scrolled ? 'blur(20px)' : 'none'};
          border-bottom: ${scrolled ? '1px solid var(--border-color)' : 'none'};
          transition: all 0.3s ease;
        }
        
        .landing-logo {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          font-size: 1.5rem;
          font-weight: 700;
          color: var(--accent-primary);
        }
        
        .landing-logo svg {
          width: 2.5rem;
          height: 2.5rem;
        }
        
        .landing-nav-actions {
          display: flex;
          gap: 1rem;
          align-items: center;
        }
        
        .landing-btn {
          padding: 0.65rem 1.5rem;
          border-radius: 0.75rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s ease;
          border: none;
          font-size: 0.95rem;
        }
        
        .landing-btn-ghost {
          background: transparent;
          color: var(--text-secondary);
          border: 1px solid var(--border-color);
        }
        
        .landing-btn-ghost:hover {
          color: var(--text-primary);
          border-color: var(--accent-primary);
          transform: translateY(-2px);
        }
        
        .landing-btn-primary {
          background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
          color: white;
          box-shadow: 0 4px 20px rgba(59, 130, 246, 0.4);
        }
        
        .landing-btn-primary:hover {
          transform: translateY(-2px);
          box-shadow: 0 8px 30px rgba(59, 130, 246, 0.5);
        }
        
        .hero-section {
          min-height: 100vh;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
          text-align: center;
          padding: 8rem 2rem 4rem;
          position: relative;
          overflow: hidden;
        }
        
        .hero-bg {
          position: absolute;
          inset: 0;
          background: 
            radial-gradient(circle at 20% 30%, rgba(59, 130, 246, 0.15) 0%, transparent 40%),
            radial-gradient(circle at 80% 70%, rgba(99, 102, 241, 0.12) 0%, transparent 40%),
            radial-gradient(circle at 50% 50%, rgba(16, 185, 129, 0.08) 0%, transparent 50%);
          animation: pulse 8s ease-in-out infinite;
        }
        
        .hero-grid {
          position: absolute;
          inset: 0;
          background-image: 
            linear-gradient(rgba(59, 130, 246, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(59, 130, 246, 0.03) 1px, transparent 1px);
          background-size: 60px 60px;
          mask-image: radial-gradient(ellipse at center, black 30%, transparent 70%);
        }
        
        .hero-content {
          position: relative;
          z-index: 1;
          max-width: 900px;
        }
        
        .hero-badge {
          display: inline-flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.5rem 1rem;
          background: rgba(59, 130, 246, 0.1);
          border: 1px solid rgba(59, 130, 246, 0.3);
          border-radius: 999px;
          font-size: 0.85rem;
          color: var(--accent-primary);
          margin-bottom: 1.5rem;
          animation: fadeIn 0.6s ease-out;
        }
        
        .hero-title {
          font-size: clamp(2.5rem, 6vw, 4.5rem);
          font-weight: 800;
          line-height: 1.1;
          margin-bottom: 1.5rem;
          background: linear-gradient(135deg, var(--text-primary) 0%, var(--accent-primary) 50%, var(--accent-secondary) 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
          animation: slideUp 0.6s ease-out;
        }
        
        .hero-title span {
          display: block;
          background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }
        
        .hero-desc {
          font-size: 1.25rem;
          color: var(--text-secondary);
          max-width: 650px;
          margin: 0 auto 2.5rem;
          line-height: 1.7;
          animation: slideUp 0.7s ease-out;
        }
        
        .hero-actions {
          display: flex;
          gap: 1rem;
          justify-content: center;
          flex-wrap: wrap;
          animation: slideUp 0.8s ease-out;
        }
        
        .hero-btn {
          display: inline-flex;
          align-items: center;
          gap: 0.5rem;
          padding: 1rem 2rem;
          border-radius: 0.75rem;
          font-weight: 600;
          font-size: 1rem;
          cursor: pointer;
          transition: all 0.2s ease;
          border: none;
        }
        
        .hero-btn-primary {
          background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
          color: white;
          box-shadow: 0 4px 25px rgba(59, 130, 246, 0.4);
        }
        
        .hero-btn-primary:hover {
          transform: translateY(-3px);
          box-shadow: 0 8px 40px rgba(59, 130, 246, 0.5);
        }
        
        .hero-btn-secondary {
          background: var(--bg-secondary);
          color: var(--text-primary);
          border: 1px solid var(--border-color);
        }
        
        .hero-btn-secondary:hover {
          border-color: var(--accent-primary);
          transform: translateY(-3px);
        }
        
        .stats-section {
          padding: 4rem 2rem;
          background: var(--bg-secondary);
          border-top: 1px solid var(--border-color);
          border-bottom: 1px solid var(--border-color);
        }
        
        .stats-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 2rem;
          max-width: 1000px;
          margin: 0 auto;
        }
        
        .stat-item {
          text-align: center;
        }
        
        .stat-value {
          font-size: 2.5rem;
          font-weight: 800;
          color: var(--accent-primary);
          margin-bottom: 0.25rem;
        }
        
        .stat-label {
          font-size: 0.9rem;
          color: var(--text-muted);
        }

        .features-section {
          padding: 6rem 2rem;
          max-width: 1200px;
          margin: 0 auto;
        }
        
        .section-header {
          text-align: center;
          margin-bottom: 4rem;
        }
        
        .section-title {
          font-size: 2.5rem;
          font-weight: 700;
          margin-bottom: 1rem;
          color: var(--text-primary);
        }
        
        .section-desc {
          font-size: 1.1rem;
          color: var(--text-secondary);
          max-width: 600px;
          margin: 0 auto;
        }
        
        .features-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 1.5rem;
        }
        
        .feature-card {
          background: var(--bg-secondary);
          border: 1px solid var(--border-color);
          border-radius: 1rem;
          padding: 2rem;
          transition: all 0.3s ease;
        }
        
        .feature-card:hover {
          transform: translateY(-8px);
          border-color: var(--accent-primary);
          box-shadow: 0 20px 40px rgba(59, 130, 246, 0.15);
        }
        
        .feature-icon {
          width: 3.5rem;
          height: 3.5rem;
          border-radius: 0.75rem;
          display: flex;
          align-items: center;
          justify-content: center;
          margin-bottom: 1.25rem;
          background: rgba(59, 130, 246, 0.1);
        }
        
        .feature-icon svg {
          width: 1.75rem;
          height: 1.75rem;
        }
        
        .feature-title {
          font-size: 1.25rem;
          font-weight: 600;
          margin-bottom: 0.75rem;
          color: var(--text-primary);
        }
        
        .feature-desc {
          font-size: 0.95rem;
          color: var(--text-secondary);
          line-height: 1.6;
        }
        
        .tech-section {
          padding: 6rem 2rem;
          background: var(--bg-secondary);
        }
        
        .tech-grid {
          display: flex;
          justify-content: center;
          gap: 3rem;
          flex-wrap: wrap;
          max-width: 1000px;
          margin: 0 auto;
        }
        
        .tech-item {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 0.75rem;
          padding: 1.5rem;
          background: var(--bg-primary);
          border: 1px solid var(--border-color);
          border-radius: 1rem;
          transition: all 0.3s ease;
        }
        
        .tech-item:hover {
          transform: scale(1.05);
          border-color: var(--accent-primary);
        }
        
        .tech-icon {
          width: 3rem;
          height: 3rem;
          display: flex;
          align-items: center;
          justify-content: center;
          color: var(--accent-primary);
        }
        
        .tech-label {
          font-size: 0.9rem;
          color: var(--text-secondary);
          font-weight: 500;
        }
        
        .cta-section {
          padding: 6rem 2rem;
          text-align: center;
          position: relative;
          overflow: hidden;
        }
        
        .cta-bg {
          position: absolute;
          inset: 0;
          background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(99, 102, 241, 0.1));
        }
        
        .cta-content {
          position: relative;
          z-index: 1;
        }
        
        .cta-title {
          font-size: 2.5rem;
          font-weight: 700;
          margin-bottom: 1rem;
          color: var(--text-primary);
        }
        
        .cta-desc {
          font-size: 1.1rem;
          color: var(--text-secondary);
          margin-bottom: 2rem;
          max-width: 500px;
          margin-left: auto;
          margin-right: auto;
        }
        
        .landing-footer {
          padding: 3rem 2rem;
          border-top: 1px solid var(--border-color);
          text-align: center;
          color: var(--text-muted);
        }
        
        @media (max-width: 900px) {
          .features-grid {
            grid-template-columns: repeat(2, 1fr);
          }
          .stats-grid {
            grid-template-columns: repeat(2, 1fr);
          }
        }
        
        @media (max-width: 600px) {
          .features-grid {
            grid-template-columns: 1fr;
          }
          .stats-grid {
            grid-template-columns: 1fr 1fr;
          }
          .hero-title {
            font-size: 2rem;
          }
        }
      `}</style>

      <nav className="landing-nav">
        <div className="landing-logo">
          <Shield size={40} />
          <span>SecureShield</span>
        </div>
        <div className="landing-nav-actions">
          <button className="landing-btn landing-btn-ghost" onClick={() => navigate('/login')}>Login</button>
          <button className="landing-btn landing-btn-primary" onClick={() => navigate('/register')}>Get Started</button>
        </div>
      </nav>

      <section className="hero-section">
        <div className="hero-bg" />
        <div className="hero-grid" />
        <div className="hero-content">
          <div className="hero-badge">
            <Zap size={16} />
            Advanced SQL Injection Detection System
          </div>
          <h1 className="hero-title">
            Protect Your Database
            <span>From SQL Injection Attacks</span>
          </h1>
          <p className="hero-desc">
            Enterprise-grade security powered by AI and machine learning. 
            Detect, prevent, and neutralize SQL injection threats in real-time 
            with our advanced detection engine.
          </p>
          <div className="hero-actions">
            <button className="hero-btn hero-btn-primary" onClick={() => navigate('/register')}>
              Start Free Trial
              <ArrowRight size={18} />
            </button>
            <button className="hero-btn hero-btn-secondary" onClick={() => navigate('/login')}>
              View Demo
            </button>
          </div>
        </div>
      </section>

      <section className="stats-section">
        <div className="stats-grid">
          {stats.map((stat, i) => (
            <div className="stat-item" key={i}>
              <div className="stat-value">{stat.value}</div>
              <div className="stat-label">{stat.label}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="features-section">
        <div className="section-header">
          <h2 className="section-title">Powerful Security Features</h2>
          <p className="section-desc">
            Comprehensive protection against modern web threats with advanced AI capabilities
          </p>
        </div>
        <div className="features-grid">
          {features.map((feature, i) => (
            <div className="feature-card" key={i}>
              <div className="feature-icon" style={{ background: `${feature.color}15` }}>
                <feature.icon size={28} style={{ color: feature.color }} />
              </div>
              <h3 className="feature-title">{feature.title}</h3>
              <p className="feature-desc">{feature.description}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="tech-section">
        <div className="section-header">
          <h2 className="section-title">Powered by Modern Tech</h2>
          <p className="section-desc">
            Built with cutting-edge technologies for maximum security and performance
          </p>
        </div>
        <div className="tech-grid">
          <div className="tech-item">
            <div className="tech-icon"><Database size={32} /></div>
            <span className="tech-label">PostgreSQL</span>
          </div>
          <div className="tech-item">
            <div className="tech-icon"><Server size={32} /></div>
            <span className="tech-label">FastAPI</span>
          </div>
          <div className="tech-item">
            <div className="tech-icon"><Brain size={32} /></div>
            <span className="tech-label">ML/AI Models</span>
          </div>
          <div className="tech-item">
            <div className="tech-icon"><Globe size={32} /></div>
            <span className="tech-label">Real-time</span>
          </div>
        </div>
      </section>

      <section className="cta-section">
        <div className="cta-bg" />
        <div className="cta-content">
          <h2 className="cta-title">Ready to Secure Your Data?</h2>
          <p className="cta-desc">
            Start your free trial today and experience enterprise-grade SQL injection protection.
          </p>
          <button className="hero-btn hero-btn-primary" onClick={() => navigate('/register')}>
            Get Started Now
            <ArrowRight size={18} />
          </button>
        </div>
      </section>

      <footer className="landing-footer">
        <p>SecureShield - Advanced SQL Injection Detection System</p>
      </footer>
    </div>
  );
};

export default Landing;