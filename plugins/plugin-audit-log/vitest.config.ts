import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/**/*.d.ts'],
    },
  },
  resolve: {
    alias: {
      '@arka/types': resolve(__dirname, '../../packages/arka-types/src'),
      '@arka/utils': resolve(__dirname, '../../packages/arka-utils/src'),
      '@arka/plugin-sdk': resolve(__dirname, '../../packages/arka-plugin-sdk/src'),
      '@arka/testing': resolve(__dirname, '../../packages/arka-testing/src'),
    },
  },
});
