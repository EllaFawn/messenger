import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const API_TARGET = process.env.API_TARGET ?? "http://127.0.0.1:3000";

export default defineConfig({
  plugins: [react()],
  resolve: {
    // Bundle the workspace packages from source, so the app never depends on
    // a separate build of them being present or up to date.
    alias: {
      "@messager/crypto": fileURLToPath(new URL("../crypto/src/index.ts", import.meta.url)),
      "@messager/protocol": fileURLToPath(new URL("../protocol/src/index.ts", import.meta.url)),
    },
  },
  server: {
    // Local only: not reachable from other machines on the network.
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    // The browser talks to the API through this same origin, so the server
    // needs no CORS headers. /api/register is forwarded as /register.
    proxy: {
      "/api": {
        target: API_TARGET,
        // Also forward the push WebSocket (/api/ws).
        ws: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
