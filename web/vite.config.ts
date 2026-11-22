import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

/** Vite dev server. `/api` is proxied to the local Worker. */
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // The passkey relying party is `localhost`, so the page has to be opened
    // at http://localhost:5173. The Worker stays on 127.0.0.1 and the proxy
    // reaches it from here. Binding only 127.0.0.1 makes that page origin
    // impossible on this machine, where `localhost` is IPv6.
    host: "localhost",
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8787",
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
