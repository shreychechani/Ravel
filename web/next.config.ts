import type { NextConfig } from "next";

// A static export: `ravel serve` hosts web/out and the /api routes on
// 127.0.0.1, so the page needs no Node server of its own.
const nextConfig: NextConfig = {
  output: "export",
  reactCompiler: true,
  images: { unoptimized: true },
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
