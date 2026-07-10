# node:20-alpine is EOL; use the maintained LTS and match CI (node 22 + npm ci).
FROM node:22-alpine AS builder

WORKDIR /app
# `npm ci` requires package-lock.json; copy it explicitly (no glob) so a missing
# lockfile fails the build loudly instead of silently falling back.
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000
