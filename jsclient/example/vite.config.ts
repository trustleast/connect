import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  resolve: {
    alias: {
      'connect-signaling': resolve(__dirname, '../client/src/index.ts'),
    },
  },
});
