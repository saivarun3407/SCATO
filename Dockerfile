# SCATO - Software Composition Analysis Tool
# Multi-stage Dockerfile — works as both CLI and web dashboard

# ─── Build Stage ───
FROM oven/bun:1-alpine AS builder

WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production=false

COPY src ./src
COPY tsconfig.json ./
RUN bun build src/index.ts src/server.ts --outdir dist --target node --splitting

# ─── Runtime Stage ───
FROM oven/bun:1-alpine AS runtime

RUN addgroup -g 1001 scato && \
    adduser -D -u 1001 -G scato scato

WORKDIR /app

COPY --from=builder --chown=scato:scato /app/dist ./dist
COPY --from=builder --chown=scato:scato /app/node_modules ./node_modules
COPY --from=builder --chown=scato:scato /app/package.json ./

RUN mkdir -p /app/data && chown scato:scato /app/data

USER scato

ENV SCATO_DATA_DIR=/app/data
ENV SCATO_PORT=3001
ENV NODE_ENV=production

EXPOSE 3001

# Default: start the web dashboard
# Override with: docker run scato scan /scan
ENTRYPOINT ["bun", "dist/index.js"]
CMD ["serve", "--port", "3001"]
