import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { KeyRound } from 'lucide-react';
import { apiClient } from '../Services/apiClient.js';
import { AlertBanner } from '../Components/AlertBanner.jsx';
import { PasswordInput } from '../Components/PasswordInput.jsx';
import { evaluatePasswordPolicy } from '../Utils/passwordStrength.js';

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const [token, setToken] = useState(() => searchParams.get('token') || '');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Limpia el token de la barra de URL inmediatamente para evitar exposición en historial o Referrer
  useEffect(() => {
    if (window.location.search.includes('token=')) {
      window.history.replaceState({}, '', '/reset-password');
    }
  }, []);

  const policy = evaluatePasswordPolicy(newPassword);

  async function handleSubmit(event) {
    event.preventDefault();
    setError('');
    setSuccess('');

    if (!policy.valid) {
      setError('La nueva contraseña no cumple los requisitos de complejidad.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Las contraseñas no coinciden.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await apiClient.auth.resetPassword({
        token: token.trim(),
        newPassword
      });
      setSuccess(res.message);
      setToken('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setError(err.message || 'No fue posible restablecer la contraseña.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="auth-shell">
      <section className="auth-card" aria-labelledby="reset-heading">
        <div className="brand-header">
          <div className="brand-icon" aria-hidden="true">
            <KeyRound size={22} />
          </div>
          <div>
            <h1 id="reset-heading" className="brand-title">
              Restablecer contraseña
            </h1>
            <p className="brand-subtitle">El cambio invalidará todas tus sesiones activas anteriores</p>
          </div>
        </div>

        <AlertBanner type="error" message={error} />
        <AlertBanner type="success" message={success} />

        <form className="form-stack" onSubmit={handleSubmit} noValidate>
          <div className="form-group">
            <label className="form-label" htmlFor="reset-token">
              Token de recuperación (64 caracteres hex)
            </label>
            <input
              id="reset-token"
              type="text"
              className="input mono"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="Pega aquí el token recibido"
              required
            />
          </div>

          <PasswordInput
            id="reset-password"
            label="Nueva contraseña"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            placeholder="Mínimo 12 caracteres"
            autoComplete="new-password"
          />

          <PasswordInput
            id="reset-confirm"
            label="Confirmar nueva contraseña"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Repite la nueva contraseña"
            autoComplete="new-password"
          />

          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'Actualizando clave...' : 'Actualizar contraseña'}
          </button>
        </form>

        <div className="auth-footer">
          <Link to="/login">Ir al inicio de sesión</Link>
          <Link to="/forgot-password">Solicitar nuevo enlace</Link>
        </div>
      </section>
    </div>
  );
}
