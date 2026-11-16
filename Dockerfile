# Production image: the server, serving the built web app.
# Base images are pinned by digest so a moved tag cannot change what is built.

# ---- build ----
FROM node:26-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS build
WORKDIR /app

# Dependency manifests first, so this layer is reused until they change.
COPY package.json package-lock.json tsconfig.json tsconfig.base.json ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/protocol/package.json packages/protocol/
COPY packages/ratchet/package.json packages/ratchet/
COPY packages/server/package.json packages/server/
COPY packages/web/package.json packages/web/
RUN npm ci

COPY packages packages
RUN npx tsc -b \
 && npm run build -w @messager/web \
 && npm prune --omit=dev

# ---- run ----
FROM node:26-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc
ENV NODE_ENV=production
WORKDIR /app

COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules node_modules
COPY --from=build /app/packages/crypto/package.json packages/crypto/
COPY --from=build /app/packages/crypto/dist packages/crypto/dist
COPY --from=build /app/packages/protocol/package.json packages/protocol/
COPY --from=build /app/packages/protocol/dist packages/protocol/dist
COPY --from=build /app/packages/server/package.json packages/server/
COPY --from=build /app/packages/server/dist packages/server/dist
COPY --from=build /app/packages/server/migrations packages/server/migrations
COPY --from=build /app/packages/web/dist packages/web/dist
COPY deploy/start.sh /app/start.sh

# The unprivileged user that ships with the Node image.
USER node
EXPOSE 3000
CMD ["sh", "/app/start.sh"]
