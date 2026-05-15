import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import AttackLogs from './pages/AttackLogs';
import SecurityStats from './pages/SecurityStats';
import Alerts from './pages/Alerts';
import AIPredictions from './pages/AIPredictions';
import IPBlocking from './pages/IPBlocking';
import Capabilities from './pages/Capabilities';
import MFASetup from './pages/MFASetup';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';

const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();
  
  if (loading) {
    return <div className="loading-spinner" />;
  }
  
  if (!isAuthenticated) {
    return <Navigate to="/login" />;
  }
  
  return children;
};

const AppLayout = ({ children }) => {
  return (
    <div className="app-container">
      <Navbar />
      <div style={{ display: 'flex' }}>
        <Sidebar />
        <main className="main-content">
          {children}
        </main>
      </div>
    </div>
  );
};

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/" element={
            <ProtectedRoute>
              <AppLayout>
                <Dashboard />
              </AppLayout>
            </ProtectedRoute>
          } />
          <Route path="/dashboard" element={
            <ProtectedRoute>
              <AppLayout>
                <Dashboard />
              </AppLayout>
            </ProtectedRoute>
          } />
          <Route path="/attacks" element={
            <ProtectedRoute>
              <AppLayout>
                <AttackLogs />
              </AppLayout>
            </ProtectedRoute>
          } />
          <Route path="/security" element={
            <ProtectedRoute>
              <AppLayout>
                <SecurityStats />
              </AppLayout>
            </ProtectedRoute>
          } />
          <Route path="/alerts" element={
            <ProtectedRoute>
              <AppLayout>
                <Alerts />
              </AppLayout>
            </ProtectedRoute>
          } />
          <Route path="/ai-predictions" element={
            <ProtectedRoute>
              <AppLayout>
                <AIPredictions />
              </AppLayout>
            </ProtectedRoute>
          } />
          <Route path="/ip-blocking" element={
            <ProtectedRoute>
              <AppLayout>
                <IPBlocking />
              </AppLayout>
            </ProtectedRoute>
          } />
          <Route path="/capabilities" element={
            <ProtectedRoute>
              <AppLayout>
                <Capabilities />
              </AppLayout>
            </ProtectedRoute>
          } />
          <Route path="/mfa-setup" element={
            <ProtectedRoute>
              <AppLayout>
                <MFASetup />
              </AppLayout>
            </ProtectedRoute>
          } />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;