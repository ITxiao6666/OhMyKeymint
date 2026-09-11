import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  base: '',
  plugins: [vue()],
  build: {
    target: 'chrome94',
    cssTarget: 'chrome94',
    outDir: '../template/webroot',
    emptyOutDir: true,
    cssCodeSplit: false,
  },
})
