import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// base "./" so the built bundle works when FastAPI serves it from "/".
export default defineConfig({
  plugins: [react()],
  base: "./",
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8077",
      "/healthz": "http://127.0.0.1:8077",
    },
  },
});
