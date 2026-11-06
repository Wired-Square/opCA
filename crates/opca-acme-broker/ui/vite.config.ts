import { applianceVite } from "@wired-square/appliance-ui/vite";
import solid from "vite-plugin-solid";
import { defineConfig } from "vitest/config";

export default defineConfig(
  applianceVite({
    plugins: [solid()],
    build: { target: "esnext", outDir: "dist" },
    // The tests are of logic alone; the plugin would otherwise ask for jsdom.
    test: { environment: "node" },
  }),
);
