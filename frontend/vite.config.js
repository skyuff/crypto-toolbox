import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      // 前端 /api 代理到后端 8080，避免跨域并统一入口
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true
      }
    }
  }
})
