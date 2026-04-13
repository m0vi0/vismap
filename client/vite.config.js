import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import process from 'node:process'
import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  cacheDir: process.env.VITE_CACHE_DIR || 'node_modules/.vite',
  plugins: [react(), tailwindcss()],
  server: {
    port: 5176,
    host: '127.0.0.1',
    strictPort: true,
  },
  resolve: {
    alias: {
      '@': path.resolve(process.cwd(), 'src'),
    },
  },
})
