import React, { useEffect, useState } from 'react';
import api from '../services/api';

const Activity = () => {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    const fetchActivity = async () => {
      try {
        const res = await api.get('/activity');
        if (mounted) setItems(res.data);
      } catch (e) {
        console.error('Failed to load activity', e);
      } finally {
        if (mounted) setLoading(false);
      }
    };

    fetchActivity();
    return () => { mounted = false; };
  }, []);

  return (
    <div>
      <h2>Activity</h2>
      {loading ? (
        <div>Loading...</div>
      ) : (
        <div>
          {items.length === 0 && <div>No recent activity.</div>}
          <ul style={{ listStyle: 'none', padding: 0 }}>
            {items.map((it) => (
              <li key={`${it.type}-${it.id}`} style={{ padding: '0.75rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ fontWeight: 600 }}>{it.type === 'notification_attempt' ? (it.details.title || 'Notification') : 'Incident'}</div>
                  <div style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>{it.type}</div>
                  <div style={{ marginTop: '0.25rem', fontSize: '0.9rem' }}>{JSON.stringify(it.details)}</div>
                </div>
                <div style={{ textAlign: 'right', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  {new Date(it.created_at).toLocaleString()}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default Activity;
