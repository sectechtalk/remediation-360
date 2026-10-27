# r360 container image (Azure Container Apps). Built and deployed by tools/Publish-R360Image.ps1.
FROM node:22-alpine
ENV NODE_ENV=production PORT=8080 HOST=0.0.0.0
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server ./server
COPY public ./public
USER node
EXPOSE 8080
CMD ["node", "server/index.mjs"]
