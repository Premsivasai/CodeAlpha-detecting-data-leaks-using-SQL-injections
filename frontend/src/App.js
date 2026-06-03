import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Login from './pages/Login';
import Register from './pages/Register';
import Landing from './pages/Landing';
import Dashboard from './pages/Dashboard';
import AttackLogs from './pages/AttackLogs';
import SecurityStats from './pages/SecurityStats';
import Alerts from './pages/Alerts';
import IncidentDetail from './pages/IncidentDetail';
import Activity from './pages/Activity';
import AIPredictions from './pages/AIPredictions';
import IPBlocking from './pages/IPBlocking';
import Capabilities from './pages/Capabilities';
import MFASetup from './pages/MFASetup';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import Sandbox from './pages/Sandbox';
import AdminConfig from './pages/AdminConfig';
import SQLWorkspace from './pages/SQLWorkspace';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import ToastProvider from './components/Toast';

const PublicRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();
  
  if (loading) {
    return <div className="loading-spinner" />;
  }
  
  if (isAuthenticated) {
    return <Navigate to="/dashboard" />;
  }
  
  return children;
};

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
      <div className="app-shell">
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
      <ToastProvider>
        <Router>
          <Routes>
          <Route path="/" element={
            <PublicRoute>
              <Landing />
            </PublicRoute>
          } />
          <Route path="/login" element={
            <PublicRoute>
              <Login />
            </PublicRoute>
          } />
          <Route path="/register" element={
            <PublicRoute>
              <Register />
            </PublicRoute>
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
          <Route path="/activity" element={
            <ProtectedRoute>
              <AppLayout>
                <Activity />
              </AppLayout>
            </ProtectedRoute>
          } />
          <Route path="/incidents/:incidentId" element={
            <ProtectedRoute>
              <AppLayout>
                <IncidentDetail />
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
          <Route path="/reports" element={
            <ProtectedRoute>
              <AppLayout>
                <Reports />
              </AppLayout>
            </ProtectedRoute>
          } />
          <Route path="/settings" element={
            <ProtectedRoute>
              <AppLayout>
                <Settings />
              </AppLayout>
            </ProtectedRoute>
          } />
          <Route path="/admin/config" element={
            <ProtectedRoute>
              <AppLayout>
                <AdminConfig />
              </AppLayout>
            </ProtectedRoute>
          } />
          <Route path="/sandbox" element={
            <ProtectedRoute>
              <AppLayout>
                <Sandbox />
              </AppLayout>
            </ProtectedRoute>
          } />
          <Route path="/workspace" element={
            <ProtectedRoute>
              <AppLayout>
                <SQLWorkspace />
              </AppLayout>
            </ProtectedRoute>
          } />
        </Routes>
      </Router>
      </ToastProvider>
    </AuthProvider>
  );
}

export default App;