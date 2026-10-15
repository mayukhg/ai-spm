import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";

export default defineConfig(async ({ mode }) => {
  // Expose Mixpanel project token to the browser without changing .env keys.
  // Service-account credentials stay server-only.
  const env = loadEnv(mode, path.resolve(import.meta.dirname), "");
  const mixpanelToken =
    env.MIXPANEL_PROJECT_TOKEN ||
    env.MIXPANEL_TOKEN ||
    env.VITE_MIXPANEL_TOKEN ||
    "";

  const cartographerPlugins =
    process.env.NODE_ENV !== "production" && process.env.REPL_ID !== undefined
      ? [
          await import("@replit/vite-plugin-cartographer").then((m) =>
            m.cartographer(),
          ),
        ]
      : [];

  return {
    plugins: [react(), runtimeErrorOverlay(), ...cartographerPlugins],
    define: {
      "import.meta.env.VITE_MIXPANEL_TOKEN": JSON.stringify(mixpanelToken),
    },
    resolve: {
      alias: {
        "@": path.resolve(import.meta.dirname, "client", "src"),
        "@shared": path.resolve(import.meta.dirname, "shared"),
        "@assets": path.resolve(import.meta.dirname, "attached_assets"),
      },
    },
    root: path.resolve(import.meta.dirname, "client"),
    build: {
      outDir: path.resolve(import.meta.dirname, "dist/public"),
      emptyOutDir: true,
    },
    server: {
      fs: {
        strict: true,
        deny: ["**/.*"],
      },
    },
  };
});
