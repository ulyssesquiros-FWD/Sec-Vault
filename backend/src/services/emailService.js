import nodemailer from 'nodemailer';

/**
 * Servicio de correo electrónico basado en Nodemailer con timeouts explícitos.
 * Nunca imprime tokens ni contraseñas en logs.
 */
export function createEmailService(config, logger, customTransporter = null) {
  const isConfigured = Boolean(
    customTransporter || (config.smtp.host && config.smtp.user && config.smtp.password)
  );

  const transporter =
    customTransporter ||
    (isConfigured
      ? nodemailer.createTransport({
          host: config.smtp.host,
          port: config.smtp.port,
          secure: config.smtp.secure,
          auth: {
            user: config.smtp.user,
            pass: config.smtp.password
          },
          connectionTimeout: 10000,
          greetingTimeout: 10000,
          socketTimeout: 15000
        })
      : null);

  async function sendPasswordResetEmail({ to, name, rawToken }) {
    const resetUrl = `${config.appUrl}/reset-password?token=${encodeURIComponent(rawToken)}`;

    if (!transporter) {
      logger?.warn(
        { recipientDomain: String(to).split('@')[1] || 'unknown' },
        'SMTP no configurado: no se pudo enviar correo de recuperación. Configura SMTP_HOST, SMTP_USER y SMTP_PASSWORD.'
      );
      return { sent: false, reason: 'SMTP_NOT_CONFIGURED' };
    }

    await transporter.sendMail({
      from: config.smtp.from,
      to,
      subject: 'SecureVault — Restablecimiento de contraseña',
      text: [
        `Hola ${name || 'usuario'},`,
        '',
        'Recibimos una solicitud para restablecer tu contraseña en SecureVault.',
        `Abre el siguiente enlace (válido por 30 minutos y de un solo uso):`,
        resetUrl,
        '',
        'Si no solicitaste este cambio, ignora este mensaje.'
      ].join('\n'),
      html: `
        <div style="font-family: Arial, sans-serif; color: #0f172a; line-height: 1.5;">
          <h2>SecureVault — Restablecimiento de contraseña</h2>
          <p>Hola,</p>
          <p>Recibimos una solicitud para restablecer tu contraseña en SecureVault.</p>
          <p>
            <a href="${resetUrl}" style="display:inline-block;padding:10px 18px;background:#059669;color:#ffffff;text-decoration:none;border-radius:6px;font-weight:bold;">
              Restablecer contraseña
            </a>
          </p>
          <p>Este enlace expira en <strong>30 minutos</strong> y es de un solo uso.</p>
          <p style="color:#64748b;font-size:12px;">Si no solicitaste este cambio, puedes ignorar este correo.</p>
        </div>
      `
    });

    return { sent: true };
  }

  async function sendSecurityAlertEmail({ to, subject, summary }) {
    if (!transporter || !to) {
      return { sent: false, reason: 'SMTP_OR_RECIPIENT_MISSING' };
    }

    await transporter.sendMail({
      from: config.smtp.from,
      to,
      subject: `[SecureVault ALERTA] ${subject}`,
      text: summary
    });

    return { sent: true };
  }

  return {
    isConfigured,
    sendPasswordResetEmail,
    sendSecurityAlertEmail
  };
}
