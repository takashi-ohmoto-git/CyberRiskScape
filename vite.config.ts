/// <reference types="vitest" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  // 配置先のサブパス。既定はルート配信。GitHub Pages 等のサブディレクトリへ
  // 配置する場合のみ BASE_PATH を与えてビルドする（例: /CyberRiskScape/）。
  base: process.env.BASE_PATH ?? '/',
  plugins: [react()],
  // ヘッドレス CLI（`vite build --ssr src/cli/main.ts`）が node_modules 無しでも
  // 単体で動くよう、依存パッケージも bundle に含める。通常クライアントビルド（`vite build`、
  // `--ssr` なし）には ssr オプションは適用されないため挙動は変わらない。
  ssr: { noExternal: true },
  server: {
    port: 5173,
    open: true,
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
  },
});
