/**
 * Repositorio MySQL persistente para control de intentos fallidos de login y bloqueos progresivos.
 * Permite escalar horizontalmente sin depender de contadores en memoria.
 */
export function createLoginAttemptRepository(pool) {
  function computeLockDurationSeconds(attempts) {
    if (attempts >= 10) return 900; // 15 min
    if (attempts >= 8) return 300;  // 5 min
    if (attempts >= 5) return 60;   // 1 min
    return 0;
  }

  async function getByEmail(emailNormalized) {
    const [rows] = await pool.execute(
      `SELECT id, email_normalized, attempts, locked_until, last_ip, updated_at
       FROM login_attempts
       WHERE email_normalized = ?
       LIMIT 1`,
      [emailNormalized]
    );
    return rows[0] || null;
  }

  async function recordFailure(emailNormalized, ipAddress) {
    const current = await getByEmail(emailNormalized);
    const nextAttempts = (current ? Number(current.attempts) : 0) + 1;
    const lockSeconds = computeLockDurationSeconds(nextAttempts);
    const lockedUntil = lockSeconds > 0 ? new Date(Date.now() + lockSeconds * 1000) : null;

    await pool.execute(
      `INSERT INTO login_attempts (email_normalized, attempts, locked_until, last_ip)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         attempts = VALUES(attempts),
         locked_until = VALUES(locked_until),
         last_ip = VALUES(last_ip)`,
      [emailNormalized, nextAttempts, lockedUntil, ipAddress || null]
    );

    return {
      attempts: nextAttempts,
      lockSeconds,
      lockedUntil
    };
  }

  async function reset(emailNormalized) {
    await pool.execute(
      'DELETE FROM login_attempts WHERE email_normalized = ?',
      [emailNormalized]
    );
  }

  return {
    getByEmail,
    recordFailure,
    reset
  };
}
