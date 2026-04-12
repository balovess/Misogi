/**
 * Vite configuration for Misogi React frontend.
 *
 * Configures development server, build output, and plugin chain for
 * gRPC-Web integration with Envoy proxy backend.
 *
 * @module vite.config
 * @see https://vitejs.dev/config/
 */

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      // Proxy gRPC-Web requests to Envoy during development
      '/misogi.file_transfer.v1': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        ws: false,
      },
    },
  },
  build: {
    target: 'esnext',
    outDir: 'dist',
    sourcemap: true,
  },
});
