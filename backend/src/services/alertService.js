import dns from 'node:dns/promises';
import net from 'node:net';

function isPrivateOrReservedIp(ip) {
  if (!net.isIP(ip)) return true;

  // IPv4 mapeada en IPv6 (::ffff:127.0.0.1)
  if (ip.toLowerCase().startsWith('::ffff:')) {
    return isPrivateOrReservedIp(ip.slice(7));
  }

  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // Multicast / reservada
    return false;
  }

  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // Unique local
  if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) {
    return true; // Link-local
  }
  return false;
}

/**
 * Valida estrictamente la URL de webhook contra ataques SSRF (OWASP A01:2025):
 * - Exige esquema HTTPS sin credenciales embebidas.
 * - Rechaza localhost, literales IP privados y resoluciones DNS a rangos internos.
 * @param {string} rawUrl
 */
export async function validateSafeWebhookUrl(rawUrl) {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'https:') {
    throw new Error('SECURITY_ALERT_WEBHOOK_URL debe usar HTTPS exclusivamente.');
  }
  if (parsed.username || parsed.password) {
    throw new Error('La URL del webhook no debe incluir credenciales.');
  }

  const hostname = parsed.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    throw new Error('Hostname interno bloqueado por protección anti-SSRF.');
  }

  if (net.isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname)) {
      throw new Error('Dirección IP privada o reservada bloqueada por protección anti-SSRF.');
    }
    return parsed.toString();
  }

  const records = await dns.lookup(hostname, { all: true });
  if (!records.length || records.some((r) => isPrivateOrReservedIp(r.address))) {
    throw new Error('La resolución DNS del webhook apunta a una red privada bloqueada (anti-SSRF).');
  }

  return parsed.toString();
}

/**
 * Servicio de alertas de seguridad (Bitácora crítica + notificación externa opcional).
 */
export function createAlertService(config, auditService, emailService, logger, fetchImpl = globalThis.fetch) {
  async function triggerSecurityAlert({
    actorId = null,
    eventType,
    severity = 'HIGH',
    description,
    metadata = {},
    ipAddress = null
  }) {
    await auditService.recordEvent({
      actorId,
      eventType,
      severity,
      description,
      metadata,
      ipAddress
    });

    if (config.alerts.email) {
      try {
        await emailService.sendSecurityAlertEmail({
          to: config.alerts.email,
          subject: `${eventType} (${severity})`,
          summary: `${description}\nIP: ${ipAddress || 'desconocida'}\nFecha: ${new Date().toISOString()}`
        });
      } catch (err) {
        logger?.warn({ errMessage: err.message, eventType }, 'No se pudo enviar alerta por correo');
      }
    }

    if (config.alerts.webhookUrl && typeof fetchImpl === 'function') {
      try {
        const safeUrl = await validateSafeWebhookUrl(config.alerts.webhookUrl);
        await fetchImpl(safeUrl, {
          method: 'POST',
          redirect: 'error',
          headers: { 'Content-Type': 'application/json' },
          signal: AbortSignal.timeout(5000),
          body: JSON.stringify({
            service: 'SecureVault',
            eventType,
            severity,
            description,
            ipAddress,
            timestamp: new Date().toISOString()
          })
        });
      } catch (err) {
        logger?.warn({ errMessage: err.message, eventType }, 'No se pudo entregar alerta webhook externa');
      }
    }
  }

  return {
    triggerSecurityAlert
  };
}
