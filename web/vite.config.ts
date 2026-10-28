import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// ADR-003: served from the platform, no CDN. In development the API is
// proxied to a dev gateway (scripts/ui-e2e.sh starts one on :8099).
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false, assetsInlineLimit: 0 },
  server: { proxy: { "/api": "http://localhost:8099", "/dev": "http://localhost:8099" } },
});
