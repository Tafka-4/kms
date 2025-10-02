FROM node:20-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci || npm install

COPY tsconfig.json ./
COPY src ./src

RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app

COPY package.json ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY --from=builder /app/build ./build

RUN mkdir -p /data/keys
VOLUME ["/data"]

EXPOSE 3000

CMD ["node", "build/server.js"]

