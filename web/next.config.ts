import type { NextConfig } from "next";

// GATEWAY_INTERNAL_URL: where the Go gateway listens. In compose the service
// name resolves to the gateway container; locally it's localhost:8080.
// The rewrite makes /api/* and /mcp/* same-origin from the browser's view,
// so the httpOnly gig_session cookie is sent to :3000 and forwarded here —
// no CORS, no credentials:'include' needed. Paths stay lowercase because the
// gateway mux is case-sensitive (/API/* would hit the legacy handler).
const GATEWAY =
  process.env.GATEWAY_INTERNAL_URL ?? "http://localhost:8080";

const nextConfig: NextConfig = {
  output: "standalone",
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${GATEWAY}/api/:path*` },
      { source: "/mcp/:path*", destination: `${GATEWAY}/mcp/:path*` },
    ];
  },
};

export default nextConfig;
