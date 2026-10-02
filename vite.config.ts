// @lovable.dev/vite-tanstack-config already includes the following — do NOT add them manually
// or the app will break with duplicate plugins:
//   - TanStack devtools (dev-only, first), tanstackStart, viteReact, tailwindcss, tsConfigPaths,
//     nitro (build-only using cloudflare as a default target), VITE_* env injection, @ path alias,
//     React/TanStack dedupe, error logger plugins, and sandbox detection (port/host/strictPort).
// You can pass additional config via defineConfig({ vite: { ... }, etc... }) if needed.
import { defineConfig } from "@lovable.dev/vite-tanstack-config";

// GH_PAGES=1 builds a fully static SPA bundle (dist/client) for GitHub Pages.
// Run it with a base path, e.g. `bunx vite build --base=/repo-name/` and
// BASE_PATH=/repo-name/ so the router matches the sub-path. The normal build
// (no GH_PAGES) is unchanged and still targets the Lovable runtime.
const ghPages = process.env["GH_PAGES"] === "1";

export default defineConfig({
  tanstackStart: {
    // Redirect TanStack Start's bundled server entry to src/server.ts (our SSR error wrapper).
    // nitro/vite builds from this
    server: { entry: "server" },
    ...(ghPages
      ? {
          spa: { enabled: true },
          router: { basepath: process.env.BASE_PATH || "/" },
        }
      : {}),
  },
  ...(ghPages ? { nitro: false as const } : {}),
});
