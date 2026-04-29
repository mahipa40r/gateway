export const config = {
  runtime: "edge",
};

const B = (process.env.API_BACKEND || "").replace(/\/$/, "");

// Minimal static set for O(1) lookup
const SH = new Set([
  "host", "connection", "keep-alive", "proxy-authenticate", 
  "proxy-authorization", "te", "trailer", "transfer-encoding", 
  "upgrade", "forwarded", "x-forwarded-host", "x-forwarded-proto", 
  "x-forwarded-port"
]);

// Fast-fail paths for automated vulnerability scanners and web crawlers
const JUNK_PATHS = ["/.env", "/wp-", "/phpmyadmin", "/.git", "/robots.txt"];

export default async function handler(req) {
  // Graceful silent fail for misconfiguration
  if (!B) return new Response(null, { status: 204 });

  const u = new URL(req.url);
  
  if (JUNK_PATHS.some(p => u.pathname.startsWith(p))) {
    return new Response(null, { status: 404 });
  }

  try {
    const h = new Headers();
    let c = null;
    
    for (const [k, v] of req.headers) {
      const lk = k.toLowerCase();
      if (SH.has(lk) || lk.startsWith("x-vercel-")) continue;
      if (lk === "x-real-ip") { c = v; continue; }
      if (lk === "x-forwarded-for") { if (!c) c = v; continue; }
      h.set(lk, v);
    }
    if (c) h.set("x-forwarded-for", c);

    const m = req.method;
    const o = { method: m, headers: h, redirect: "manual" };
    
    if (m !== "GET" && m !== "HEAD") {
      o.body = req.body;
      o.duplex = "half"; 
    }

    const up = await fetch(B + u.pathname + u.search, o);
    
    const rh = new Headers(up.headers);
    rh.delete("transfer-encoding");

    if (m === "GET" && !rh.has("cache-control")) {
      rh.set("cache-control", "public, s-maxage=60, stale-while-revalidate=300");
    }

    return new Response(up.body, { status: up.status, headers: rh });
  } catch (err) {
    return new Response(null, { status: 500 });
  }
}
