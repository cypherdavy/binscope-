import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// For GitHub Pages: builds with /binscope/ base path when GITHUB_PAGES env is set,
// otherwise dev/prod local builds use root.
const base = process.env.GITHUB_PAGES ? '/binscope-/' : '/'

export default defineConfig({
  plugins: [react()],
  base,
  optimizeDeps: {
    exclude: ['capstone-wasm']
  },
  server: {
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp'
    }
  },
  build: {
    target: 'es2022',
    chunkSizeWarningLimit: 1500
  }
})
