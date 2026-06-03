import React, { useState } from 'react';
import api from '../services/api';

const MFASetup = () => {
  const [provisioningUri, setProvisioningUri] = useState(null);
  const [secret, setSecret] = useState(null);
  const [token, setToken] = useState('');
  const [status, setStatus] = useState(null);

  const init = async () => {
    try {
      const res = await api.post('/auth/mfa/setup');
      setProvisioningUri(res.data.provisioning_uri);
      setSecret(res.data.secret);
    } catch (e) {
      console.error(e);
    }
  };

  const verify = async () => {
    try {
      await api.post('/auth/mfa/verify', { token });
      setStatus('MFA enabled');
    } catch (e) {
      setStatus('Invalid token');
    }
  };

  return (
    <div className="page-container">
      <h1>MFA Setup</h1>
      <p>Use an authenticator app (Google Authenticator, Authy) to scan the QR or enter the secret.</p>
      <div style={{ marginBottom: '1rem' }}>
        <button onClick={init} className="btn">Initialize MFA</button>
      </div>
      {provisioningUri && (
        <div style={{ marginBottom: '1rem' }}>
          <img alt="QR" src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(provisioningUri)}`} />
          <div>Secret: {secret}</div>
        </div>
      )}

      {provisioningUri && (
        <div>
          <input value={token} onChange={(e) => setToken(e.target.value)} placeholder="Enter code from app" />
          <button onClick={verify} className="btn">Verify</button>
        </div>
      )}

      {status && <div>{status}</div>}
    </div>
  );
};

export default MFASetup;
