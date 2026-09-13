/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/**
 * The portal is served **same-origin with the API**, in development and in production alike.
 *
 * That is the whole reason this proxy exists. The session cookie is host-only (no `Domain`)
 * and `SameSite=Strict`, and the Milestone 3.2 CSRF cookie carries the `__Host-` prefix
 * wherever it is `Secure` -- which forbids a `Domain` attribute outright. A portal on
 * `app.example` talking to an API on `api.example` could therefore never read the CSRF
 * cookie the API set, because a cookie without `Domain` belongs to exactly one host. Putting
 * both behind one origin makes the two cookies simply *the page's* cookies, keeps every
 * request same-origin (so CORS never enters it), and keeps the browser's own cookie rules
 * doing the isolation rather than a configuration knob.
 *
 * `FIRMBATCH_API_ORIGIN` points the proxy at the API process. It is a development-time
 * address, not a secret and not a credential; in a deployed environment (M3.3) the reverse
 * proxy in front of both services does the same job and this file is not involved.
 */
const apiOrigin = process.env.FIRMBATCH_API_ORIGIN ?? "http://127.0.0.1:8081";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/v1": {
        target: apiOrigin,
        changeOrigin: false,
        // changeOrigin stays false deliberately: the API checks `Origin` against its
        // allow-list on every cookie-authenticated mutation, and rewriting the header here
        // would mean the check was passing on something this proxy invented rather than on
        // what the browser actually sent.
      },
    },
  },
  preview: {
    host: "127.0.0.1",
    port: 4173,
    proxy: {
      "/v1": { target: apiOrigin, changeOrigin: false },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    // No source map in the built asset. It is not a security control -- the bundle is the
    // source either way -- but shipping one invites pasting a stack trace with local paths
    // into a bug report, and this application deliberately puts nothing in front of a
    // customer that names its own internals.
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    include: ["tests/**/*.test.ts", "tests/**/*.test.tsx"],
    restoreMocks: true,
    clearMocks: true,
    // Comfortably above the 5 s async-query timeout `vitest.setup.ts` configures, so a query
    // that is genuinely going to fail reports *what* it could not find rather than being cut
    // off by the surrounding test's own deadline.
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
