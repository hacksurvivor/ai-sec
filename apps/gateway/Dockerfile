FROM node:22-alpine AS deps
WORKDIR /app
COPY package*.json ./
COPY apps/gateway/package.json apps/gateway/package.json
COPY apps/cli/package.json apps/cli/package.json
COPY packages/security-core/package.json packages/security-core/package.json
COPY packages/redteam-runner/package.json packages/redteam-runner/package.json
RUN npm ci

FROM node:22-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/apps/gateway/dist ./apps/gateway/dist
COPY --from=build /app/packages/security-core/dist ./packages/security-core/dist
COPY --from=build /app/packages/redteam-runner/dist ./packages/redteam-runner/dist
COPY --from=build /app/policy ./policy
COPY --from=build /app/apps/gateway/package.json ./apps/gateway/package.json
COPY --from=build /app/packages/security-core/package.json ./packages/security-core/package.json
COPY --from=build /app/packages/redteam-runner/package.json ./packages/redteam-runner/package.json
EXPOSE 8080
CMD ["node", "apps/gateway/dist/index.js"]
