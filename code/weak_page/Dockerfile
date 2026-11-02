FROM node:22-bookworm-slim

WORKDIR /app/backend

COPY backend/package*.json ./
RUN npm ci --omit=dev

COPY backend/ ./
COPY index.html ./public/index.html
COPY css ./public/css
COPY js ./public/js

RUN mkdir -p db && chown -R node:node /app/backend

USER node

ENV PORT=3009
ENV SECURITY_MODE=vulnerable
EXPOSE 3009

CMD ["sh", "-c", "if [ ! -f db/dulceNube.sqlite ]; then npm run seed; fi && npm start"]
