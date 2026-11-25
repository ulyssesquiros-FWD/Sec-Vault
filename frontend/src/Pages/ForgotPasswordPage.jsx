import { useState } from 'react';
import { Link } from 'react-router-dom';
import { MailCheck } from 'lucide-react';
import { apiClient } from '../Services/apiClient.js';
import { AlertBanner } from '../Components/AlertBanner.jsx';

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [statusMessage, setStatusMessage] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setError('');
    setStatusMessage('');
    setSubmitting(true);

    try {
      const res = await apiClient.auth.forgotPassword({ email: email.trim() });
      setStatusMessage(res.message);
    } catch (err) {
      setError(err.message || 'No se pudo procesar la solicitud.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="auth-shell">
      <section className="auth-card" aria-labelledby="forgot-heading">
        <div className="brand-header">
          <div className="brand-icon" aria-hidden="true">
            <MailCheck size={22} />
          </div>
          <div>
            <h1 id="forgot-heading" className="brand-title">
              Recuperar contraseña
            </h1>
            <p className="brand-subtitle">Enlace de un solo uso con expiración y hash SHA-256</p>
          </div>
        </div>

        <AlertBanner type="error" message={error} />
        <AlertBanner type="success" message={statusMessage} />

        <form className="form-stack" onSubmit={handleSubmit} noValidate>
          <div className="form-group">
            <label className="form-label" htmlFor="forgot-email">
              Correo electrónico registrado
            </label>
            <input
              id="forgot-email"
              type="email"
              className="input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="usuario@ejemplo.com"
              autoComplete="email"
              required
            />
          </div>

          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'Enviando solicitud...' : 'Enviar enlace de recuperación'}
          </button>
        </form>

        <div className="auth-footer">
          <Link to="/login">Volver al inicio de sesión</Link>
          <Link to="/reset-password">Ya tengo un token</Link>
        </div>
      </section>
    </div>
  );
}
