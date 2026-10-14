// Das Klassenpasswort wird ausschließlich als Cloudflare-Secret CLASS_PASSWORD gespeichert.
// Niemals das Passwort in diese Datei oder in GitHub schreiben.
const USERNAME = "klasse";

function challenge() {
  return new Response("Bitte melde dich mit dem Klassenzugang an.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Leos Lernwelt", charset="UTF-8"',
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=utf-8",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

async function digest(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}
async function equalSecret(actual, expected) {
  const [a,b] = await Promise.all([digest(actual), digest(expected)]);
  let diff = 0;
  for (let i=0;i<a.length;i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export default {
  async fetch(request, env) {
    if (!env.CLASS_PASSWORD) {
      return new Response("Der Klassenzugang ist noch nicht eingerichtet.", {status:503, headers:{"Cache-Control":"no-store"}});
    }
    const authorization = request.headers.get("Authorization") || "";
    if (!authorization.startsWith("Basic ") || authorization.length > 1500) return challenge();
    let decoded;
    try { decoded = atob(authorization.slice(6)); }
    catch { return challenge(); }
    const colon = decoded.indexOf(":");
    if (colon < 0) return challenge();
    const user = decoded.slice(0, colon);
    const password = decoded.slice(colon + 1);
    if (user !== USERNAME || !(await equalSecret(password, env.CLASS_PASSWORD))) return challenge();
    const response = await env.ASSETS.fetch(request);
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", "private, no-store");
    headers.set("X-Content-Type-Options", "nosniff");
    return new Response(response.body, {status:response.status,statusText:response.statusText,headers});
  }
};
