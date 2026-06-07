# syntax=docker/dockerfile:1
FROM node:22-alpine AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml .npmrc ./
RUN pnpm install --frozen-lockfile

FROM node:22-alpine AS builder
WORKDIR /app
RUN corepack enable
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# GATEWAY_INTERNAL_URL is evaluated by next.config rewrites AT BUILD TIME and
# baked into .next/routes-manifest.json (verified: the standalone server
# ignores the runtime env var). Pass it as a build arg; compose sets it to the
# gateway's in-network DNS name (see docker-compose.yml build.args).
ARG GATEWAY_INTERNAL_URL=http://localhost:8080
ENV GATEWAY_INTERNAL_URL=$GATEWAY_INTERNAL_URL
RUN pnpm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
