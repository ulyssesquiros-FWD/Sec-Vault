import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { KeyRound, Shield } from 'lucide-react';
import { useAuth } from '../Hooks/useAuth.js';
import { AlertBanner } from '../Components/AlertBanner.jsx';
import { PasswordInput } from '../Components/PasswordInput.jsx';

export function LoginPage() {
  const navigate = useNavigate();
  const { login, verifyMfa } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaStep, setMfaStep] = useState(false);
  const [mfaCode, setMfaCode] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function handleLoginSubmit(event) {
    event.preventDefault();
    setError('');
    setSubmitting(true);

    try {
      const result = await login({ email: email.trim(), password });
      if (result.mfaRequired) {
        setMfaStep(true);
      } else {
        navigate('/dashboard', { replace: true });
      }
    } catch (err) {
      if (err.status === 429 && err.details?.retryAfterSeconds) {
        setError(`${err.message} (Espera ${err.details.retryAfterSeconds}s antes de reintentar).`);
      } else {
        setError(err.message || 'No fue posible iniciar sesión.');
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function handleMfaSubmit(event) {
    event.preventDefault();
    setError('');
    setSubmitting(true);

    try {
      await verifyMfa(mfaCode.trim());
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err.message || 'Código MFA inválido.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="auth-shell">
      <section className="auth-card" aria-labelledby="login-heading">
        <div className="brand-header">
          <div className="brand-icon" aria-hidden="true">
            {mfaStep ? <KeyRound size={22} /> : <Shield size={22} />}
          </div>
          <div>
            <h1 id="login-heading" className="brand-title">
              {mfaStep ? 'Verificación MFA TOTP' : 'Iniciar sesión en SecureVault'}
            </h1>
            <p className="brand-subtitle">
              {mfaStep
                ? 'Ingresa el código de 6 dígitos de tu aplicación autenticadora'
                : 'Acceso protegido con sesiones MySQL y bloqueo anti-fuerza bruta'}
            </p>
          </div>
        </div>

        <AlertBanner type="error" message={error} />

        {!mfaStep ? (
          <form className="form-stack" onSubmit={handleLoginSubmit} noValidate>
            <div className="form-group">
              <label className="form-label" htmlFor="login-email">
                Correo electrónico
              </label>
              <input
                id="login-email"
                type="email"
                className="input"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="usuario@ejemplo.com"
                autoComplete="email"
                required
              />
            </div>

            <PasswordInput
              id="login-password"
              label="Contraseña"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Ingresa tu contraseña"
              autoComplete="current-password"
            />

            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? 'Verificando...' : 'Entrar a la bóveda'}
            </button>
          </form>
        ) : (
          <form className="form-stack" onSubmit={handleMfaSubmit} noValidate>
            <div className="form-group">
              <label className="form-label" htmlFor="mfa-code">
                Código TOTP o de recuperación
              </label>
              <input
                id="mfa-code"
                type="text"
                className="input mono"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                placeholder="123456 o A1B2C-D3E4F"
                autoComplete="one-time-code"
                required
              />
            </div>

            <div className="row-actions">
              <button type="submit" className="btn btn-primary" disabled={submitting}>
                {submitting ? 'Validando...' : 'Verificar segundo factor'}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  setMfaStep(false);
                  setMfaCode('');
                  setError('');
                }}
              >
                Volver
              </button>
            </div>
          </form>
        )}

        <div className="auth-footer">
          <Link to="/register">Crear una cuenta</Link>
          <Link to="/forgot-password">¿Olvidaste tu contraseña?</Link>
        </div>
      </section>
    </div>
  );
}
