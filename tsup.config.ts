import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,               // Emit type declarations
  clean: true,             // Clean output dir before build
  sourcemap: false,        // Optional
  outDir: 'dist'
});
