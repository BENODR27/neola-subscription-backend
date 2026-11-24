FROM node:22-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN --mount=type=secret,id=npm_ca \
    if [ -s /run/secrets/npm_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/npm_ca; fi; \
    npm ci --omit=dev
COPY src ./src
COPY migrations ./migrations
COPY tools/deliver-mail.cjs ./tools/deliver-mail.cjs
USER node
EXPOSE 7020
CMD ["node", "src/server.js"]
