FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS deps

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM deps AS build

COPY tsconfig.json ./
COPY prisma ./prisma
COPY src ./src
RUN npm run prisma:generate
RUN npm run build

FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS runtime

ARG SOURCE_REVISION
ARG SOURCE_INPUTS_SHA256

LABEL org.opencontainers.image.revision="${SOURCE_REVISION}" \
      com.wiseacct.sso.source-inputs-sha256="${SOURCE_INPUTS_SHA256}"

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
RUN apk add --no-cache \
      libcrypto3=3.5.8-r0 \
      libssl3=3.5.8-r0 \
    && npm ci --omit=dev --omit=optional \
    && rm -f \
      /usr/local/bin/npm \
      /usr/local/bin/npx \
      /usr/local/bin/yarn \
      /usr/local/bin/yarnpkg \
      /usr/local/bin/corepack \
    && rm -rf \
      /usr/local/lib/node_modules/npm \
      /usr/local/lib/node_modules/corepack \
      /opt/yarn-v1.22.22 \
      /root/.npm
COPY --from=build /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=build /app/dist ./dist
COPY --from=build /app/prisma ./prisma
COPY public ./public

EXPOSE 4000
USER node
CMD ["node", "dist/src/server.js"]
