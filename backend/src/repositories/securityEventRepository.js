/**
 * Repositorio MySQL para la bitácora de eventos de seguridad.
 */
export function createSecurityEventRepository(pool) {
  async function create({ actorId = null, eventType, severity = 'INFO', description, metadata = null, ipAddress = null }) {
    const [result] = await pool.execute(
      `INSERT INTO security_events (actor_id, event_type, severity, description, metadata, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        actorId ? Number(actorId) : null,
        String(eventType).slice(0, 64),
        severity,
        String(description).slice(0, 500),
        metadata ? JSON.stringify(metadata) : null,
        ipAddress ? String(ipAddress).slice(0, 45) : null
      ]
    );
    return Number(result.insertId);
  }

  async function list({ severity = '', eventType = '', search = '', limit = 30, offset = 0 }) {
    const conditions = [];
    const params = [];

    if (['INFO', 'WARNING', 'HIGH', 'CRITICAL'].includes(severity)) {
      conditions.push('se.severity = ?');
      params.push(severity);
    }
    if (eventType) {
      conditions.push('se.event_type = ?');
      params.push(eventType);
    }
    if (search) {
      conditions.push('(se.description LIKE ? OR se.event_type LIKE ? OR u.email LIKE ?)');
      const term = `%${search}%`;
      params.push(term, term, term);
    }

    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const safeLimit = Math.min(Math.max(Number.parseInt(limit, 10) || 30, 1), 100);
    const safeOffset = Math.max(Number.parseInt(offset, 10) || 0, 0);

    const [countRows] = await pool.execute(
      `SELECT COUNT(*) AS total
       FROM security_events se
       LEFT JOIN users u ON u.id = se.actor_id
       ${whereClause}`,
      params
    );

    const [rows] = await pool.query(
      `SELECT se.id, se.actor_id, u.email AS actor_email, se.event_type, se.severity,
              se.description, se.metadata, se.ip_address, se.created_at
       FROM security_events se
       LEFT JOIN users u ON u.id = se.actor_id
       ${whereClause}
       ORDER BY se.created_at DESC, se.id DESC
       LIMIT ? OFFSET ?`,
      [...params, safeLimit, safeOffset]
    );

    return {
      events: rows.map((row) => ({
        ...row,
        metadata: typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata
      })),
      total: Number(countRows[0]?.total || 0)
    };
  }

  async function getStats() {
    const [rows] = await pool.execute(
      `SELECT
         COUNT(*) AS totalEvents,
         SUM(CASE WHEN event_type IN ('LOGIN_FAILED', 'MFA_FAILED') THEN 1 ELSE 0 END) AS failedAuthEvents,
         SUM(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) AS highSeverityEvents
       FROM security_events`
    );
    return {
      totalEvents: Number(rows[0]?.totalEvents || 0),
      failedAuthEvents: Number(rows[0]?.failedAuthEvents || 0),
      highSeverityEvents: Number(rows[0]?.highSeverityEvents || 0)
    };
  }

  return {
    create,
    list,
    getStats
  };
}
