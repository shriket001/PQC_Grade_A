import fs from "node:fs";
import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev-only self-signed cert (see run.py / docker/certs/dev-https), generated
// once via openssl for "localhost" + 127.0.0.1. If present, the dev server
// (and the proxy target below) switch to https automatically — a fresh clone
// with no cert generated yet still runs fine over plain http, unchanged.
const CERT_DIR = path.resolve(__dirname, "..", "docker", "certs", "dev-https");
const CERT_FILE = path.join(CERT_DIR, "server.crt");
const KEY_FILE = path.join(CERT_DIR, "server.key");
const devHttps =
  fs.existsSync(CERT_FILE) && fs.existsSync(KEY_FILE)
    ? { cert: fs.readFileSync(CERT_FILE), key: fs.readFileSync(KEY_FILE) }
    : undefined;

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  // hash-wasm ships prebuilt WebAssembly and is loaded via a dynamic async
  // import at runtime. Excluding it from esbuild's dep pre-bundling keeps the
  // .wasm asset intact (pre-bundling can mangle the async loader) — needed for
  // `argon2id` to instantiate under dev, build, and vitest (jsdom).
  optimizeDeps: { exclude: ["hash-wasm"] },
  server: {
    port: 5173,
    https: devHttps,
    // Proxy the API and WebSocket endpoints to the FastAPI backend so the
    // frontend can use same-origin `/api/v1` URLs in dev without CORS churn.
    // In Docker, the reverse proxy handles this routing instead.
    proxy: {
      // The WebSocket endpoint is /api/v1/ws, so the /api proxy MUST enable
      // ws upgrading — otherwise the browser's ws://localhost:5173/api/v1/ws
      // upgrade is never forwarded to the backend and closes immediately.
      "/api": {
        target: devHttps ? "https://localhost:8000" : "http://localhost:8000",
        changeOrigin: true,
        ws: true,
        // The backend's dev cert is the same self-signed one — trusted by
        // nothing but itself, so the proxy's own connection to it must skip
        // verification. Irrelevant when devHttps is unset (plain http target).
        secure: false,
      },
    },
  },
});
