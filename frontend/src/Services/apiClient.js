let inMemoryCsrfToken = null;

export function setCsrfToken(token) {
  inMemoryCsrfToken = token || null;
}

export function clearCsrfToken() {
  inMemoryCsrfToken = null;
}

export class ApiError extends Error {
  constructor(message, status, code, details) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

async function request(path, options = {}) {
  const { method = 'GET', body } = options;
  const headers = {};

  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  if (method !== 'GET' && method !== 'HEAD' && inMemoryCsrfToken) {
    headers['X-CSRF-Token'] = inMemoryCsrfToken;
  }

  const response = await fetch(path, {
    method,
    headers,
    credentials: 'include',
    body: body !== undefined ? JSON.stringify(body) : undefined
  });

  const data = await response.json().catch(() => ({}));

  if (data?.csrfToken) {
    setCsrfToken(data.csrfToken);
  }

  if (!response.ok) {
    const firstDetail = Array.isArray(data?.details) && data.details[0]?.message;
    const message = firstDetail || data?.error || `Error HTTP ${response.status}`;
    throw new ApiError(message, response.status, data?.code || 'API_ERROR', data?.details);
  }

  return data;
}

export const apiClient = {
  auth: {
    me: () => request('/api/auth/me'),
    register: (payload) => request('/api/auth/register', { method: 'POST', body: payload }),
    login: (payload) => request('/api/auth/login', { method: 'POST', body: payload }),
    verifyMfa: (payload) => request('/api/auth/mfa/verify', { method: 'POST', body: payload }),
    logout: async () => {
      const res = await request('/api/auth/logout', { method: 'POST' });
      clearCsrfToken();
      return res;
    },
    forgotPassword: (payload) => request('/api/auth/forgot-password', { method: 'POST', body: payload }),
    resetPassword: (payload) => request('/api/auth/reset-password', { method: 'POST', body: payload })
  },
  users: {
    getProfile: () => request('/api/users/me'),
    updateProfile: (payload) => request('/api/users/me', { method: 'PUT', body: payload }),
    revealPhone: (payload) => request('/api/users/me/reveal-phone', { method: 'POST', body: payload }),
    changePassword: (payload) => request('/api/users/me/password', { method: 'PUT', body: payload }),
    setupMfa: () => request('/api/users/me/mfa/setup', { method: 'POST' }),
    enableMfa: (payload) => request('/api/users/me/mfa/enable', { method: 'POST', body: payload }),
    disableMfa: (payload) => request('/api/users/me/mfa/disable', { method: 'POST', body: payload })
  },
  notes: {
    list: () => request('/api/notes'),
    get: (id) => request(`/api/notes/${id}`),
    create: (payload) => request('/api/notes', { method: 'POST', body: payload }),
    update: (id, payload) => request(`/api/notes/${id}`, { method: 'PUT', body: payload }),
    remove: (id) => request(`/api/notes/${id}`, { method: 'DELETE' })
  },
  admin: {
    stats: () => request('/api/admin/stats'),
    users: (params = {}) => {
      const qs = new URLSearchParams();
      if (params.search) qs.set('search', params.search);
      if (params.role) qs.set('role', params.role);
      if (params.page) qs.set('page', String(params.page));
      if (params.limit) qs.set('limit', String(params.limit));
      return request(`/api/admin/users?${qs.toString()}`);
    },
    updateRole: (id, role) => request(`/api/admin/users/${id}/role`, { method: 'PATCH', body: { role } }),
    events: (params = {}) => {
      const qs = new URLSearchParams();
      if (params.severity) qs.set('severity', params.severity);
      if (params.eventType) qs.set('eventType', params.eventType);
      if (params.search) qs.set('search', params.search);
      if (params.page) qs.set('page', String(params.page));
      if (params.limit) qs.set('limit', String(params.limit));
      return request(`/api/admin/events?${qs.toString()}`);
    },
    rotateKeys: () => request('/api/admin/crypto/rotate', { method: 'POST' })
  }
};
