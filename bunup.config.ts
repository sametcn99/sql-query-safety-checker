import { defineConfig } from "bunup";

export default defineConfig({
  entry: ["index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  outDir: "dist",
  target: "node",
  clean: true,
  external: ["express"],
});
