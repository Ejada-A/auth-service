# Stage 1: Build stage
FROM node:20-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci || npm install
COPY . .

# Stage 2: Production runner stage
FROM node:20-slim AS runner
WORKDIR /app

ENV NODE_ENV=production

# Copy built application and node_modules from builder
COPY --chown=node:node --from=builder /app /app

# Switch to non-root user for enhanced security
USER node

EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5001/health || exit 1

CMD ["npm", "start"]
