import { Router } from 'express';

export function createHealthRoutes() {
  const router = Router();

  // Endpoint mínimo de salud (OWASP A02/A09): nunca revela versiones, secretos ni datos internos.
  router.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  return router;
}
