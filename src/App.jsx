import { useEffect, useMemo, useState } from 'react';

const emptyAccessForm = {
  employee: '',
  team: '',
  role: '',
  accessType: 'software',
  priority: 'medium',
  justification: '',
};

const emptyAuthForm = {
  email: '',
  password: '',
  fullName: '',
  team: 'General',
};

const statusColors = {
  pending: 'status-pending',
  approved: 'status-approved',
  rejected: 'status-rejected',
  revoked: 'status-revoked',
};

const formatDate = (value) => {
  if (!value) return '—';
  return new Date(value).toLocaleString([], {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
};

async function fetchJson(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload.success) {
    throw new Error(payload?.error?.message || 'Request failed');
  }

  return payload.data;
}

export default function App() {
  const [session, setSession] = useState(null);
  const [activeView, setActiveView] = useState('dashboard');
  const [authMode, setAuthMode] = useState('login');
  const [authForm, setAuthForm] = useState(emptyAuthForm);
  const [authError, setAuthError] = useState('');
  const [requests, setRequests] = useState([]);
  const [stats, setStats] = useState({ total: 0, pending: 0, approved: 0, rejected: 0, revoked: 0 });
  const [users, setUsers] = useState([]);
  const [teamSummary, setTeamSummary] = useState(null);
  const [accessForm, setAccessForm] = useState(emptyAccessForm);
  const [statusFilter, setStatusFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [error, setError] = useState('');

  const loadSession = async () => {
    try {
      const sessionData = await fetchJson('/api/auth/session');
      setSession(sessionData.user);
      return sessionData.user;
    } catch {
      setSession(null);
      return null;
    }
  };

  const loadProtectedData = async (currentUser) => {
    if (!currentUser) return;

    try {
      const [requestData, statsData, userData, teamData] = await Promise.all([
        fetchJson('/api/requests').catch(() => []),
        fetchJson('/api/stats').catch(() => ({ total: 0, pending: 0, approved: 0, rejected: 0, revoked: 0 })),
        currentUser.role === 'admin' ? fetchJson('/api/users').catch(() => []) : Promise.resolve([]),
        currentUser.role === 'manager' || currentUser.role === 'admin'
          ? fetchJson('/api/team/summary').catch(() => null)
          : Promise.resolve(null),
      ]);

      setRequests(requestData);
      setStats(statsData);
      setUsers(userData);
      setTeamSummary(teamData);
      setError('');
    } catch (err) {
      setError(err.message);
    }
  };

  useEffect(() => {
    loadSession().then((user) => user && loadProtectedData(user));
  }, []);

  useEffect(() => {
    if (session) {
      loadProtectedData(session);
    }
  }, [session]);

  const visibleRequests = useMemo(() => {
    return requests.filter((request) => {
      const matchesStatus = statusFilter === 'all' || request.status === statusFilter;
      const haystack = `${request.employee} ${request.team} ${request.role} ${request.justification}`.toLowerCase();
      const matchesSearch = haystack.includes(search.toLowerCase());
      return matchesStatus && matchesSearch;
    });
  }, [requests, search, statusFilter]);

  const handleAuthFieldChange = (event) => {
    const { name, value } = event.target;
    setAuthForm((current) => ({ ...current, [name]: value }));
  };

  const handleAuthSubmit = async (event) => {
    event.preventDefault();
    setAuthError('');

    try {
      const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/register';
      const payload = authMode === 'login'
        ? { email: authForm.email, password: authForm.password }
        : {
            email: authForm.email,
            password: authForm.password,
            fullName: authForm.fullName,
            team: authForm.team,
          };

      const data = await fetchJson(endpoint, {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      setSession(data.user);
      setAuthForm(emptyAuthForm);
    } catch (err) {
      setAuthError(err.message);
    }
  };

  const handleLogout = async () => {
    try {
      await fetchJson('/api/auth/logout', { method: 'POST' });
    } catch {
      // no-op; still clear local UI state
    }

    setSession(null);
    setRequests([]);
    setStats({ total: 0, pending: 0, approved: 0, rejected: 0, revoked: 0 });
    setUsers([]);
    setTeamSummary(null);
    setActiveView('dashboard');
  };

  const handleAccessChange = (event) => {
    const { name, value } = event.target;
    setAccessForm((current) => ({ ...current, [name]: value }));
  };

  const handleAccessSubmit = async (event) => {
    event.preventDefault();
    setError('');

    try {
      await fetchJson('/api/requests', {
        method: 'POST',
        body: JSON.stringify(accessForm),
      });
      setAccessForm(emptyAccessForm);
      await loadProtectedData(session);
    } catch (err) {
      setError(err.message);
    }
  };

  const updateRequestStatus = async (id, status, reviewer = session?.fullName || 'AccessHub') => {
    setError('');

    try {
      await fetchJson(`/api/requests/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status, reviewer }),
      });
      await loadProtectedData(session);
    } catch (err) {
      setError(err.message);
    }
  };

  const deleteRequest = async (id) => {
    setError('');

    try {
      await fetchJson(`/api/requests/${id}`, { method: 'DELETE' });
      await loadProtectedData(session);
    } catch (err) {
      setError(err.message);
    }
  };

  if (!session) {
    return (
      <div className="auth-shell">
        <div className="auth-card">
          <div className="auth-header">
            <p className="eyebrow">Access operations</p>
            <h1>AccessHub</h1>
          </div>

          <div className="auth-toggle">
            <button
              type="button"
              className={authMode === 'login' ? 'active' : ''}
              onClick={() => setAuthMode('login')}
            >
              Login
            </button>
            <button
              type="button"
              className={authMode === 'register' ? 'active' : ''}
              onClick={() => setAuthMode('register')}
            >
              Register
            </button>
          </div>

          <form onSubmit={handleAuthSubmit} className="auth-form">
            {authMode === 'register' ? (
              <label>
                Full name
                <input
                  type="text"
                  name="fullName"
                  value={authForm.fullName}
                  onChange={handleAuthFieldChange}
                  placeholder="Jane Doe"
                  required
                />
              </label>
            ) : null}

            <label>
              Email
              <input
                type="email"
                name="email"
                value={authForm.email}
                onChange={handleAuthFieldChange}
                placeholder="you@company.com"
                required
              />
            </label>

            <label>
              Password
              <input
                type="password"
                name="password"
                value={authForm.password}
                onChange={handleAuthFieldChange}
                placeholder="Enter password"
                required
              />
            </label>

            {authMode === 'register' ? (
              <label>
                Team
                <input
                  type="text"
                  name="team"
                  value={authForm.team}
                  onChange={handleAuthFieldChange}
                  placeholder="Engineering"
                />
              </label>
            ) : null}

            {authError ? <p className="form-error">{authError}</p> : null}

            <button type="submit" className="primary-button auth-submit">
              {authMode === 'login' ? 'Sign in' : 'Create account'}
            </button>
          </form>

          <div className="demo-box">
            <strong>Getting started</strong>
            <p>Register to create a User account. Configure seed passwords before first launch to create admin or manager accounts.</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Access operations</p>
          <h1>AccessHub</h1>
        </div>

        <div className="topbar-actions">
          <div className="user-pill">
            {session.fullName} · {session.role}
          </div>
          <button type="button" className="secondary-button" onClick={handleLogout}>Logout</button>
        </div>
      </header>

      <nav className="nav-tabs">
        <button type="button" className={activeView === 'dashboard' ? 'active' : ''} onClick={() => setActiveView('dashboard')}>Dashboard</button>
        <button type="button" className={activeView === 'profile' ? 'active' : ''} onClick={() => setActiveView('profile')}>Profile</button>
        {session.role === 'admin' ? (
          <button type="button" className={activeView === 'users' ? 'active' : ''} onClick={() => setActiveView('users')}>User management</button>
        ) : null}
      </nav>

      <section className="metrics-grid">
        {[
          { label: 'Total', value: stats.total, tone: 'blue' },
          { label: 'Pending', value: stats.pending, tone: 'amber' },
          { label: 'Approved', value: stats.approved, tone: 'green' },
          { label: 'Rejected', value: stats.rejected, tone: 'red' },
        ].map((item) => (
          <article key={item.label} className={`metric-card ${item.tone}`}>
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </article>
        ))}
      </section>

      {activeView === 'dashboard' ? (
        <main className="content-grid">
          <section className="panel form-panel">
            <div className="panel-header">
              <h2>New access request</h2>
              <span>Secure workflow</span>
            </div>

            <form onSubmit={handleAccessSubmit} className="access-form">
              <label>
                Employee
                <input name="employee" value={accessForm.employee} onChange={handleAccessChange} placeholder="Jordan Smith" required />
              </label>
              <label>
                Team
                <input name="team" value={accessForm.team} onChange={handleAccessChange} placeholder="Finance" required />
              </label>
              <label>
                Role
                <input name="role" value={accessForm.role} onChange={handleAccessChange} placeholder="Data Analyst" required />
              </label>

              <div className="two-column">
                <label>
                  Access type
                  <select name="accessType" value={accessForm.accessType} onChange={handleAccessChange}>
                    <option value="software">Software</option>
                    <option value="system">System</option>
                    <option value="facility">Facility</option>
                    <option value="data">Data</option>
                    <option value="other">Other</option>
                  </select>
                </label>

                <label>
                  Priority
                  <select name="priority" value={accessForm.priority} onChange={handleAccessChange}>
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                  </select>
                </label>
              </div>

              <label>
                Justification
                <textarea
                  name="justification"
                  value={accessForm.justification}
                  onChange={handleAccessChange}
                  rows={4}
                  placeholder="Describe the business need and duration of access."
                  required
                />
              </label>

              {error ? <p className="form-error">{error}</p> : null}

              <button type="submit" className="primary-button">Submit request</button>
            </form>
          </section>

          <section className="panel list-panel">
            <div className="panel-header">
              <h2>Access queue</h2>
              <span>{visibleRequests.length} items</span>
            </div>

            {(session.role === 'manager' || session.role === 'admin') && teamSummary ? (
              <div className="team-summary">
                <strong>{teamSummary.team}</strong>
                <span>{teamSummary.totalMembers} members</span>
                <span>{teamSummary.pendingRequests} pending</span>
              </div>
            ) : null}

            <div className="queue-toolbar">
              <input
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search employee or team"
              />
              <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
                <option value="all">All states</option>
                <option value="pending">Pending</option>
                <option value="approved">Approved</option>
                <option value="rejected">Rejected</option>
                <option value="revoked">Revoked</option>
              </select>
            </div>

            <div className="request-list">
              {visibleRequests.length === 0 ? (
                <div className="empty-state">No access requests match the current filters.</div>
              ) : (
                visibleRequests.map((request) => (
                  <article key={request.id} className="request-card">
                    <div className="request-header">
                      <div>
                        <h3>{request.employee}</h3>
                        <p>{request.team} • {request.role}</p>
                      </div>
                      <span className={`status-badge ${statusColors[request.status] || 'status-pending'}`}>
                        {request.status}
                      </span>
                    </div>

                    <div className="meta-row">
                      <span>{request.accessType}</span>
                      <span>Priority: {request.priority}</span>
                      <span>Requested: {formatDate(request.requestedAt)}</span>
                    </div>

                    <p className="justification">{request.justification}</p>

                    <div className="card-actions">
                      <button type="button" className="action approve" onClick={() => updateRequestStatus(request.id, 'approved')}>
                        Approve
                      </button>
                      <button type="button" className="action reject" onClick={() => updateRequestStatus(request.id, 'rejected')}>
                        Reject
                      </button>
                      <button type="button" className="action pending" onClick={() => updateRequestStatus(request.id, 'pending')}>
                        Pending
                      </button>
                      <button type="button" className="action delete" onClick={() => deleteRequest(request.id)}>
                        Delete
                      </button>
                    </div>

                    <div className="request-footer">
                      <span>Reviewer: {request.reviewer || 'Awaiting review'}</span>
                      <span>Updated: {formatDate(request.updatedAt)}</span>
                    </div>
                  </article>
                ))
              )}
            </div>
          </section>
        </main>
      ) : null}

      {activeView === 'profile' ? (
        <section className="panel profile-panel">
          <div className="panel-header">
            <h2>Profile</h2>
            <span>{session.role}</span>
          </div>

          <div className="profile-grid">
            <div className="profile-box">
              <h3>{session.fullName}</h3>
              <p>{session.email}</p>
              <p>Team: {session.team}</p>
            </div>
            <div className="profile-box">
              <p><strong>Role:</strong> {session.role}</p>
              <p><strong>Created:</strong> {formatDate(session.createdAt)}</p>
              <p><strong>Status:</strong> {session.status}</p>
            </div>
          </div>
        </section>
      ) : null}

      {activeView === 'users' && session.role === 'admin' ? (
        <section className="panel users-panel">
          <div className="panel-header">
            <h2>Users</h2>
            <span>{users.length} total</span>
          </div>

          <div className="user-table">
            {users.map((user) => (
              <div key={user.id} className="user-row">
                <div>
                  <strong>{user.fullName}</strong>
                  <small>{user.email}</small>
                </div>
                <span>{user.team}</span>
                <span className={`role-pill ${user.role}`}>{user.role}</span>
                <button
                  type="button"
                  className="secondary-button small"
                  onClick={async () => {
                    const nextRole = user.role === 'user' ? 'manager' : 'user';
                    await fetchJson(`/api/users/${user.id}`, {
                      method: 'PATCH',
                      body: JSON.stringify({ role: nextRole }),
                    });
                    await loadProtectedData(session);
                  }}
                >
                  Toggle role
                </button>
              </div>
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}
