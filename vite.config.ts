/// <reference types="vitest" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  // 配置先のサブパス。既定はルート配信。GitHub Pages 等のサブディレクトリへ
  // 配置する場合のみ BASE_PATH を与えてビルドする（例: /CyberRiskScape/）。
  base: process.env.BASE_PATH ?? '/',
  plugins: [react()],
  server: {
    port: 5173,
    open: true,
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
  },
});
