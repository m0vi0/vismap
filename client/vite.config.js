import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import process from 'node:process'

// https://vite.dev/config/
export default defineConfig({
  cacheDir: process.env.VITE_CACHE_DIR || 'node_modules/.vite',
  plugins: [react()],
})
