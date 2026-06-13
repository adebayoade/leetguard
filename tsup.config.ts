import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'node16',
  clean: true,
  dts: false,
  sourcemap: true,
  minify: true,
});
