# syntax=docker/dockerfile:1
#
# TMWAccess -- Wi-Fi access gateway for TMnodes -> TMedge.
# Builds on any machine with Docker, for linux/amd64 and linux/arm64:
#   docker build -t tmwaccess .
#   docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/tmwaccess:1.0 --push .
# Run with docker compose (host networking; see docker-compose.yml and DOCKER.md).

ARG NODE_VERSION=22

FROM node:${NODE_VERSION}-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
COPY test ./test
RUN npm run build && npm prune --omit=dev

FROM node:${NODE_VERSION}-alpine
LABEL org.opencontainers.image.title="TMWAccess" \
      org.opencontainers.image.description="Wi-Fi access gateway relaying TMnode packets to TMedge"
ENV NODE_ENV=production
WORKDIR /app
# No runtime dependencies: only the compiled gateway.
COPY --from=build /src/dist/src ./dist/src
COPY package.json ./
USER node
EXPOSE 5200/udp
# Healthy = the gateway answers on its status port and its link to TMedge is up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["node", "-e", \
  "fetch('http://127.0.0.1:'+(process.env.STATUS_PORT||5280)+'/').then(r=>r.json()).then(s=>process.exit(s.link.state==='up'?0:1)).catch(()=>process.exit(1))"]
ENTRYPOINT ["node", "dist/src/main.js"]
