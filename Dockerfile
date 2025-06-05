# Stage 1: Build frontend and backend
FROM node:18-alpine AS builder
WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm install --legacy-peer-deps

# Copy all source code
COPY . .

# Build frontend and backend
# The build script 'vite build && esbuild server/index.ts --platform=node --packages=external --bundle --format=esm --outdir=dist'
# will place frontend assets in 'dist/public' and backend in 'dist/index.js'
RUN npm run build

# Stage 2: Production image for backend
FROM node:18-alpine
WORKDIR /app

# Only copy necessary files from builder stage
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

# Expose port
EXPOSE 5000

# Start the server
CMD ["node", "dist/index.js"]
