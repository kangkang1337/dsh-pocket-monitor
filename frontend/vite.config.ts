import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

/** Backend port used for the dev proxy. */
const backendPort = process.env.DSH_POCKET_MONITOR_PORT ?? '3099'

export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2020',
  },
  server: {
    host: true,
    port: 5173,
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${backendPort}`,
        changeOrigin: false,
      },
    },
  },
})
