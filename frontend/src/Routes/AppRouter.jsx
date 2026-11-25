import { Navigate, Route, Routes } from 'react-router-dom';
import { useAuth } from '../Hooks/useAuth.js';
import { ProtectedRoute } from './ProtectedRoute.jsx';
import { AdminRoute } from './AdminRoute.jsx';
import { LoginPage } from '../Pages/LoginPage.jsx';
import { RegisterPage } from '../Pages/RegisterPage.jsx';
import { ForgotPasswordPage } from '../Pages/ForgotPasswordPage.jsx';
import { ResetPasswordPage } from '../Pages/ResetPasswordPage.jsx';
import { DashboardPage } from '../Pages/DashboardPage.jsx';
import { NotesPage } from '../Pages/NotesPage.jsx';
import { NoteEditorPage } from '../Pages/NoteEditorPage.jsx';
import { ProfilePage } from '../Pages/ProfilePage.jsx';
import { AdminDashboardPage } from '../Pages/AdminDashboardPage.jsx';
import { AdminUsersPage } from '../Pages/AdminUsersPage.jsx';
import { AdminEventsPage } from '../Pages/AdminEventsPage.jsx';

function PublicOnlyRedirect({ children }) {
  const { user, loading } = useAuth();
  if (!loading && user) {
    return <Navigate to="/dashboard" replace />;
  }
  return children;
}

export function AppRouter() {
  return (
    <Routes>
      <Route
        path="/login"
        element={
          <PublicOnlyRedirect>
            <LoginPage />
          </PublicOnlyRedirect>
        }
      />
      <Route
        path="/register"
        element={
          <PublicOnlyRedirect>
            <RegisterPage />
          </PublicOnlyRedirect>
        }
      />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />

      <Route element={<ProtectedRoute />}>
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/notes" element={<NotesPage />} />
        <Route path="/notes/new" element={<NoteEditorPage />} />
        <Route path="/notes/:id/edit" element={<NoteEditorPage />} />
        <Route path="/profile" element={<ProfilePage />} />

        <Route element={<AdminRoute />}>
          <Route path="/admin" element={<AdminDashboardPage />} />
          <Route path="/admin/users" element={<AdminUsersPage />} />
          <Route path="/admin/events" element={<AdminEventsPage />} />
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
