const PASS = Deno.env.get("PROXY_PASS") ?? "";
if (!PASS) throw new Error("PROXY_PASS is not set");

const DROP = new Set(["x-cfproxy-pass", "x-cfproxy-url", "x-cfproxy-queries", "x-forwarded-for", "x-forwarded-host",
  "x-forwarded-proto", "x-real-ip", "forwarded", "host", "connection", "content-length"]);

function same(a: string, b: string): boolean {
  let diff = a.length === b.length ? 0 : 1;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}
const fail = (status: number, detail: string) =>
  new Response(JSON.stringify({ status: "Error", details: [detail] }), {
    status, headers: { "content-type": "application/json", "x-cfproxy-status": "Error", "cache-control": "private, no-store" },
  });

Deno.serve(async (req) => {
  const target = req.headers.get("x-cfproxy-url");
  const pass = req.headers.get("x-cfproxy-pass");
  if (target === null || pass === null) return fail(400, "Missing headers: x-cfproxy-url, x-cfproxy-pass");
  if (!same(pass, PASS)) return fail(401, "Invalid password");
  let url: URL;
  try { url = new URL(target); if (!/^https?:$/.test(url.protocol)) throw 0; } catch { return fail(422, "Invalid URL"); }
  try {
    const q = JSON.parse(req.headers.get("x-cfproxy-queries") ?? "{}");
    if (typeof q !== "object" || q === null || Array.isArray(q)) throw 0;
    for (const [k, v] of Object.entries(q)) url.searchParams.set(k, typeof v === "object" && v !== null ? JSON.stringify(v) : String(v));
  } catch { return fail(422, "Invalid X-CFProxy-Queries"); }

  const headers = new Headers();
  for (const [k, v] of req.headers) if (!DROP.has(k.toLowerCase()) && !k.toLowerCase().startsWith("cf-")) headers.set(k, v);
  try {
    const res = await fetch(url, {
      method: req.method, headers, redirect: "follow",
      body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
      // @ts-ignore: required by Deno for streaming request bodies
      duplex: "half",
    });
    const out = new Headers(res.headers);
    out.set("x-cfproxy-status", "OK");
    out.delete("content-encoding"); out.delete("content-length");
    // Все запросы идут на один URL приложения: без запрета кеша edge кеширует
    // ответ по URL, игнорируя x-cfproxy-* заголовки, и отдаёт чужие/устаревшие
    // тела (в том числе без проверки пароля).
    out.delete("age"); out.delete("expires");
    out.set("cache-control", "private, no-store");
    return new Response(res.body, { status: res.status, headers: out });
  } catch (e) {
    return fail(500, "Proxy request failed: " + (e instanceof Error ? e.message : "Unknown error"));
  }
});
