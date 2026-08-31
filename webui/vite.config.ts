import { defineConfig } from 'vite'

export default defineConfig({
  base: '',
  build: {
    outDir: '../template/webroot',
    emptyOutDir: true,
    cssCodeSplit: false,
  },
})
