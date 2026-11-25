# ==============================================================================
# Stage 1: Build Frontend React + Vite
# ==============================================================================
FROM node:22-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ==============================================================================
# Stage 2: Instalar dependencias de producción del Backend
# ==============================================================================
FROM node:22-alpine AS backend-deps
WORKDIR /app/backend

RUN apk add --no-cache python3 make g++

COPY backend/package*.json ./
RUN npm ci --omit=dev

# ==============================================================================
# Stage 3: Runtime mínimo no-root
# ==============================================================================
FROM node:22-alpine AS runtime
WORKDIR /app/backend

ENV NODE_ENV=production
ENV PORT=4000

COPY --from=backend-deps /app/backend/node_modules ./node_modules
COPY backend/package*.json ./
COPY backend/src ./src
COPY database/migrations /app/database/migrations
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

RUN chown -R node:node /app
USER node

EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 4000) + '/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "src/server.js"]
