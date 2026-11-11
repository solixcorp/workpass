import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Paths served by the backend Worker. Keep in sync with assets.run_worker_first
// in ../wrangler.jsonc; anything else falls through to the SPA.
const BACKEND_PATHS = [
  '/api',
  '/.well-known',
  '/saml',
  '/wsfed',
  '/scim',
  '/sign-in',
  '/auth',
  '/oauth2',
  '/enduser',
  '/idp',
  '/health',
  '/dev',
  '/_internal',
  '/application',
]

const BACKEND_TARGET = process.env.BACKEND_URL ?? 'http://localhost:8787'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: Object.fromEntries(
      // A bare prefix would also match longer paths (`/dev` would catch `/device`), so match whole segments.
      BACKEND_PATHS.map((prefix) => [`^${prefix.replaceAll('.', '\\.')}(?:[/?]|$)`, { target: BACKEND_TARGET }]),
    ),
  },
})
