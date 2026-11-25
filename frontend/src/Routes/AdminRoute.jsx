import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../Hooks/useAuth.js';
import { LoadingSpinner } from '../Components/LoadingSpinner.jsx';

export function AdminRoute() {
  const { user, loading } = useAuth();

  if (loading) {
    return <LoadingSpinner label="Verificando privilegios..." />;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (user.role !== 'admin') {
    return <Navigate to="/dashboard" replace />;
  }

  return <Outlet />;
}
