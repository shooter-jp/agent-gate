import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/cli.ts"],
  clean: true,
  dts: false,
  format: ["esm"],
  minify: false,
  shims: true,
  sourcemap: true,
  splitting: false,
  target: "node20"
});
