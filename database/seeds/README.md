# Seeds de SecureVault

Por seguridad, este repositorio **no incluye contraseñas ni credenciales reales** en archivos SQL estáticos.

El script `backend/src/database/seed.js` lee únicamente variables de entorno explícitas (`SEED_ADMIN_NAME`, `SEED_ADMIN_EMAIL`, `SEED_ADMIN_PASSWORD`, `SEED_ADMIN_PHONE`) para inicializar de forma segura una cuenta administrativa utilizando:

- Normalización de correo electrónico.
- Hash `bcrypt` con costo mínimo 12.
- Cifrado `AES-256-GCM` del teléfono con AAD ligado al usuario.
- Transacción MySQL atómica con registro en `security_events`.

Ejecución:
```bash
npm run db:seed
```
