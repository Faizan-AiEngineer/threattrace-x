import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: { "/api": process.env.TTX_API_TARGET || "http://127.0.0.1:8000" },
  },
  preview: {
    host: "127.0.0.1",
    port: 4173,
    proxy: { "/api": process.env.TTX_API_TARGET || "http://127.0.0.1:8000" },
  },
});
