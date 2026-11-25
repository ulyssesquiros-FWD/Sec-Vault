import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../Hooks/useAuth.js';
import { Layout } from '../Components/Layout.jsx';
import { LoadingSpinner } from '../Components/LoadingSpinner.jsx';

export function ProtectedRoute() {
  const { user, loading } = useAuth();

  if (loading) {
    return <LoadingSpinner label="Verificando sesión segura..." />;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return (
    <Layout>
      <Outlet />
    </Layout>
  );
}
