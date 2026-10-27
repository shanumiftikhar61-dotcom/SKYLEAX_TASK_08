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

const emptyAdminForm = {
  fullName: '',
  email: '',
  password: '',
  team: 'General',
  role: 'user',
};

const roleLabel = (role) => role === 'user' ? 'Member' : role[0].toUpperCase() + role.slice(1);

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
    const message = payload?.error?.details?.length
      ? `${payload.error.message}: ${payload.error.details.join(' ')}`
      : payload?.error?.message || 'Request failed';
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  return payload.data;
}

export default function App() {
  const [session, setSession] = useState(null);
  const [checkingSession, setCheckingSession] = useState(true);
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
  const [profileForm, setProfileForm] = useState({ fullName: '', email: '' });
  const [adminForm, setAdminForm] = useState(emptyAdminForm);
  const [notice, setNotice] = useState('');

  const loadSession = async () => {
    try {
      const sessionData = await fetchJson('/api/auth/session');
      setSession(sessionData.user);
      setProfileForm({ fullName: sessionData.user.fullName, email: sessionData.user.email });
      setAccessForm({ ...emptyAccessForm, employee: sessionData.user.fullName, team: sessionData.user.team });
      return sessionData.user;
    } catch (err) {
      if (err.status === 401) setSession(null);
      else setError(err.message);
      return null;
    } finally {
      setCheckingSession(false);
    }
  };

  const loadProtectedData = async (currentUser) => {
    if (!currentUser) return;

    try {
      const [requestData, statsData, userData, teamData] = await Promise.all([
        fetchJson('/api/requests'),
        fetchJson('/api/stats'),
        currentUser.role === 'admin' ? fetchJson('/api/users') : Promise.resolve([]),
        currentUser.role === 'manager' || currentUser.role === 'admin'
          ? fetchJson('/api/team/summary')
          : Promise.resolve(null),
      ]);

      setRequests(requestData);
      setStats(statsData);
      setUsers(userData);
      setTeamSummary(teamData);
      setError('');
    } catch (err) {
      if (err.status === 401) setSession(null);
      setError(err.message);
    }
  };

  useEffect(() => {
    loadSession();
  }, []);

  useEffect(() => {
    if (session) {
      loadProtectedData(session);
    }
  }, [session]);

  useEffect(() => {
    const resolveView = () => {
      const requestedView = window.location.hash.slice(1) || 'dashboard';
      if (requestedView === 'dashboard' || requestedView === 'profile') {
        setActiveView(requestedView);
      } else if (requestedView === 'users' && session?.role === 'admin') {
        setActiveView('users');
      } else {
        setActiveView('access-denied');
      }
    };

    resolveView();
    window.addEventListener('hashchange', resolveView);
    return () => window.removeEventListener('hashchange', resolveView);
  }, [session]);

  const navigateTo = (view) => {
    setActiveView(view);
    const nextHash = view === 'dashboard' ? '' : `#${view}`;
    if (window.location.hash !== nextHash) window.location.hash = nextHash;
  };

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
    setError('');
    setNotice('');

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
      setProfileForm({ fullName: data.user.fullName, email: data.user.email });
      setAccessForm({ ...emptyAccessForm, employee: data.user.fullName, team: data.user.team });
      setAuthForm(emptyAuthForm);
      setError('');
    } catch (err) {
      setAuthError(err.message);
    }
  };

  const handleLogout = async () => {
    try {
      await fetchJson('/api/auth/logout', { method: 'POST' });
    } catch (err) {
      if (err.status !== 401) {
        setError(`Unable to log out: ${err.message}`);
        return;
      }
    }

    setSession(null);
    setNotice('You have been signed out.');
    setRequests([]);
    setStats({ total: 0, pending: 0, approved: 0, rejected: 0, revoked: 0 });
    setUsers([]);
    setTeamSummary(null);
    navigateTo('dashboard');
  };

  const updateProfile = async (event) => {
    event.preventDefault();
    setError('');
    setNotice('');
    try {
      const updated = await fetchJson(`/api/users/${session.id}`, {
        method: 'PATCH',
        body: JSON.stringify(profileForm),
      });
      setSession(updated);
      setProfileForm({ fullName: updated.fullName, email: updated.email });
      setNotice('Your profile has been updated.');
    } catch (err) {
      setError(err.message);
    }
  };

  const provisionUser = async (event) => {
    event.preventDefault();
    setError('');
    setNotice('');
    try {
      const created = await fetchJson('/api/users', {
        method: 'POST',
        body: JSON.stringify(adminForm),
      });
      setAdminForm(emptyAdminForm);
      setNotice(`${created.fullName} was added as a ${roleLabel(created.role)}.`);
      await loadProtectedData(session);
    } catch (err) {
      setError(err.message);
    }
  };

  const handleAccessChange = (event) => {
    const { name, value } = event.target;
    setAccessForm((current) => ({ ...current, [name]: value }));
  };

  const handleAccessSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setNotice('');

    try {
      await fetchJson('/api/requests', {
        method: 'POST',
        body: JSON.stringify({
          ...accessForm,
          team: session.role === 'admin' ? accessForm.team : session.team,
        }),
      });
      setAccessForm({ ...emptyAccessForm, employee: session.fullName, team: session.team });
      await loadProtectedData(session);
      setNotice('Your access request has been submitted for review.');
    } catch (err) {
      setError(err.message);
    }
  };

  const updateRequestStatus = async (id, status) => {
    setError('');

    try {
      await fetchJson(`/api/requests/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
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

  if (checkingSession) {
    return <main className="loading-state" aria-live="polite">Checking your secure session…</main>;
  }

  if (!session) {
    return (
      <div className="auth-shell">
        <div className="auth-card">
          <div className="auth-header">
            <p className="eyebrow">Access operations</p>
            <h1>AccessHub <span>Team Access Portal</span></h1>
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
                placeholder={authMode === 'register' ? '10+ characters with upper, lower & number' : 'Enter password'}
                minLength={authMode === 'register' ? 10 : undefined}
                maxLength={authMode === 'register' ? 128 : undefined}
                pattern={authMode === 'register' ? '(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{10,128}' : undefined}
                autoComplete={authMode === 'register' ? 'new-password' : 'current-password'}
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

          {error ? <p className="form-error" role="alert">{error}</p> : null}
          <div className="demo-box">
            <strong>Getting started</strong>
            <p>Create a Member account or sign in with credentials provisioned by your administrator. Accounts and roles are stored securely on the server.</p>
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
          <h1>AccessHub <span>Team Access Portal</span></h1>
        </div>

        <div className="topbar-actions">
          <div className="user-pill">
            {session.fullName} · {roleLabel(session.role)}
          </div>
          <button type="button" className="secondary-button" onClick={handleLogout}>Logout</button>
        </div>
      </header>

      <nav className="nav-tabs">
        <button type="button" aria-current={activeView === 'dashboard' ? 'page' : undefined} className={activeView === 'dashboard' ? 'active' : ''} onClick={() => navigateTo('dashboard')}>Dashboard</button>
        <button type="button" aria-current={activeView === 'profile' ? 'page' : undefined} className={activeView === 'profile' ? 'active' : ''} onClick={() => navigateTo('profile')}>Profile</button>
        {session.role === 'admin' ? (
          <button type="button" aria-current={activeView === 'users' ? 'page' : undefined} className={activeView === 'users' ? 'active' : ''} onClick={() => navigateTo('users')}>User management</button>
        ) : null}
      </nav>

      {error ? <p className="form-error global-error" role="alert">{error}</p> : null}
      {notice ? <p className="success-message" role="status">{notice}</p> : null}

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
                <input
                  name="team"
                  value={session.role === 'admin' ? accessForm.team : session.team}
                  onChange={session.role === 'admin' ? handleAccessChange : undefined}
                  placeholder="Finance"
                  readOnly={session.role !== 'admin'}
                  required
                />
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

              <button type="submit" className="primary-button">Submit request</button>
            </form>
          </section>

          <section className="panel list-panel">
            <div className="panel-header">
              <h2>{session.role === 'user' ? 'My requests' : session.role === 'manager' ? 'Team access queue' : 'Access queue'}</h2>
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
                      {session.role !== 'user' ? (
                        <>
                          <button type="button" className="action approve" onClick={() => updateRequestStatus(request.id, 'approved')}>Approve</button>
                          <button type="button" className="action reject" onClick={() => updateRequestStatus(request.id, 'rejected')}>Reject</button>
                          <button type="button" className="action pending" onClick={() => updateRequestStatus(request.id, 'pending')}>Reopen</button>
                          <button type="button" className="action delete" onClick={() => {
                            if (window.confirm(`Delete the request for ${request.employee}? This cannot be undone.`)) deleteRequest(request.id);
                          }}>Delete</button>
                        </>
                      ) : null}
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

      {activeView === 'access-denied' ? (
        <main className="panel access-denied">
          <p className="eyebrow">403 · Access restricted</p>
          <h2>You do not have permission to view this page.</h2>
          <p>Your account can only access pages and data assigned to its role.</p>
          <button type="button" className="primary-button" onClick={() => navigateTo('dashboard')}>Return to dashboard</button>
        </main>
      ) : null}

      {activeView === 'profile' ? (
        <section className="panel profile-panel">
          <div className="panel-header">
            <h2>Profile</h2>
            <span>{roleLabel(session.role)}</span>
          </div>

          <div className="profile-grid">
            <div className="profile-box">
              <h3>Account details</h3>
              <form className="access-form" onSubmit={updateProfile}>
                <label>
                  Full name
                  <input value={profileForm.fullName} onChange={(event) => setProfileForm({ ...profileForm, fullName: event.target.value })} minLength={2} required />
                </label>
                <label>
                  Email
                  <input type="email" value={profileForm.email} onChange={(event) => setProfileForm({ ...profileForm, email: event.target.value })} required />
                </label>
                <button type="submit" className="primary-button">Save profile</button>
              </form>
            </div>
            <div className="profile-box">
              <p><strong>Role:</strong> {roleLabel(session.role)}</p>
              <p><strong>Team:</strong> {session.team}</p>
              <p><strong>Created:</strong> {formatDate(session.createdAt)}</p>
              <p><strong>Status:</strong> {session.status}</p>
              <p className="help-text">Role, team, and account status can only be changed by an administrator.</p>
            </div>
          </div>
        </section>
      ) : null}

      {activeView === 'users' && session.role === 'admin' ? (
        <section className="panel users-panel">
          <div className="panel-header">
            <h2>User management</h2>
            <span>{users.length} total</span>
          </div>

          <form className="admin-provision-form" onSubmit={provisionUser}>
            <h3>Provision an account</h3>
            <div className="admin-provision-fields">
              <label>
                Full name
                <input value={adminForm.fullName} onChange={(event) => setAdminForm({ ...adminForm, fullName: event.target.value })} minLength={2} required />
              </label>
              <label>
                Email
                <input type="email" value={adminForm.email} onChange={(event) => setAdminForm({ ...adminForm, email: event.target.value })} required />
              </label>
              <label>
                Temporary password
                <input
                  type="password"
                  value={adminForm.password}
                  onChange={(event) => setAdminForm({ ...adminForm, password: event.target.value })}
                  minLength={10}
                  maxLength={128}
                  pattern="(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{10,128}"
                  autoComplete="new-password"
                  required
                />
              </label>
              <label>
                Team
                <input value={adminForm.team} onChange={(event) => setAdminForm({ ...adminForm, team: event.target.value })} required />
              </label>
              <label>
                Role
                <select value={adminForm.role} onChange={(event) => setAdminForm({ ...adminForm, role: event.target.value })}>
                  <option value="user">Member</option>
                  <option value="manager">Manager</option>
                  <option value="admin">Admin</option>
                </select>
              </label>
            </div>
            <button type="submit" className="primary-button">Create account</button>
          </form>

          <div className="user-table">
            {users.length === 0 ? <div className="empty-state">No accounts are available yet.</div> : null}
            {users.map((user) => (
              <div key={user.id} className="user-row">
                <div>
                  <strong>{user.fullName}</strong>
                  <small>{user.email}</small>
                </div>
                <span>{user.team}</span>
                <span className={`role-pill ${user.role}`}>{roleLabel(user.role)} · {user.status}</span>
                <button
                  type="button"
                  className="secondary-button small"
                  disabled={user.id === session.id}
                  title={user.id === session.id ? 'Administrators cannot change their own role here.' : 'Switch member and manager permissions.'}
                  onClick={async () => {
                    const nextRole = user.role === 'user' ? 'manager' : 'user';
                    setError('');
                    setNotice('');
                    try {
                      await fetchJson(`/api/users/${user.id}`, {
                        method: 'PATCH',
                        body: JSON.stringify({ role: nextRole }),
                      });
                      setNotice(`${user.fullName} is now a ${roleLabel(nextRole)}.`);
                      await loadProtectedData(session);
                    } catch (err) {
                      setError(err.message);
                    }
                  }}
                >
                  Change role
                </button>
                <button
                  type="button"
                  className="secondary-button small"
                  disabled={user.id === session.id}
                  onClick={async () => {
                    const nextStatus = user.status === 'active' ? 'suspended' : 'active';
                    if (nextStatus === 'suspended' && !window.confirm(`Suspend ${user.fullName}'s account and end their active sessions?`)) return;
                    setError('');
                    setNotice('');
                    try {
                      await fetchJson(`/api/users/${user.id}`, {
                        method: 'PATCH',
                        body: JSON.stringify({ status: nextStatus }),
                      });
                      setNotice(`${user.fullName}'s account is ${nextStatus}.`);
                      await loadProtectedData(session);
                    } catch (err) {
                      setError(err.message);
                    }
                  }}
                >
                  {user.status === 'active' ? 'Suspend' : 'Reactivate'}
                </button>
              </div>
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}
