import { createContext, useCallback, useEffect, useState } from 'react';
import { apiClient, clearCsrfToken, setCsrfToken } from '../Services/apiClient.js';

export const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [pendingMfa, setPendingMfa] = useState(false);

  const refreshUser = useCallback(async () => {
    try {
      const data = await apiClient.auth.me();
      setUser(data.user);
      setPendingMfa(false);
      if (data.csrfToken) setCsrfToken(data.csrfToken);
      return data.user;
    } catch {
      setUser(null);
      clearCsrfToken();
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  const register = useCallback(async (payload) => {
    const data = await apiClient.auth.register(payload);
    setUser(data.user);
    setPendingMfa(false);
    return data.user;
  }, []);

  const login = useCallback(async (payload) => {
    const data = await apiClient.auth.login(payload);
    if (data.mfaRequired) {
      setPendingMfa(true);
      return { mfaRequired: true };
    }
    setUser(data.user);
    setPendingMfa(false);
    return { mfaRequired: false, user: data.user };
  }, []);

  const verifyMfa = useCallback(async (code) => {
    const data = await apiClient.auth.verifyMfa({ code });
    setUser(data.user);
    setPendingMfa(false);
    return data.user;
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiClient.auth.logout();
    } finally {
      setUser(null);
      setPendingMfa(false);
      clearCsrfToken();
    }
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        pendingMfa,
        register,
        login,
        verifyMfa,
        logout,
        refreshUser
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
