# syntax=docker/dockerfile:1

FROM node:20-alpine AS builder
WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci || npm install

# Copy sources
COPY tsconfig.json ./
COPY src ./src

# Build TypeScript
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app

# Install production deps only
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

# Copy built artifacts
COPY --from=builder /app/build ./build

# App environment
ENV KMS_PORT=3000 \
    KMS_WHITELIST=100.64.0.9 \
    KEY_STORE_PATH=/data/keys \
    NODE_ENV=production

# Create data dir
RUN mkdir -p /data/keys
VOLUME ["/data"]

EXPOSE 3000

CMD ["node", "build/server.js"]

