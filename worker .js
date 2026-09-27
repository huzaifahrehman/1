// Salary Ledger receipt Worker: Cloudflare Workers AI + Firebase Auth + KV quota counts.
// Bindings: AI (Workers AI), SCANS (KV namespace).
// Variables: DB_URL (Realtime Database URL), ALLOWED_ORIGIN (app site origin).
// Optional variable: FIREBASE_PROJECT_ID (defaults to salary-v01).
// The first model call may require accepting Meta's model license in Cloudflare.
// Firebase ID tokens are signature-checked before usage, grant, or scan requests.
// Free scans and ad bonuses are stored in KV; receipt images are not stored.

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (err) {
      return jsonError("Internal server error. Please try again later.", 500, request, env);
    }
  }
};

const MAX_BODY_BYTES = 12.5 * 1024 * 1024;   // 12.5 MiB hard cap before parsing
const MAX_IMAGE_BYTES = 10 * 1024 * 1024;    // matches app's MAX_RECEIPT_BYTES
const DEFAULT_ALLOWED_ORIGIN = "*";           // set env.ALLOWED_ORIGIN to lock it
const FREE_SCAN_LIMIT = 3;
const AD_BONUS_MAX = 3;
const AD_COOLDOWN_MS = 4 * 60 * 60 * 1000;
const RECEIPT_MODEL = "@cf/meta/llama-3.2-11b-vision-instruct";
const RECEIPT_CATEGORIES = ["Food & Dining","Bills & Utilities","Installment / EMI","Transport","Shopping","Entertainment","Health","Other"];
const RECEIPT_PROMPT = `Read this receipt and return only a JSON object: {"merchant":"Store name","grandTotal":0,"items":[{"name":"Item","price":0,"category":"Food & Dining"}]}. Prices must be numbers with no currency symbols. Choose each category only from: ${RECEIPT_CATEGORIES.join(", ")}. Do not include markdown or text outside JSON.`;
const FIREBASE_JWKS_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
let firebaseJwksCache = null;
let firebaseJwksExpiresAt = 0;

const IMAGE_MAGIC = {
  "/9j/":    { mime: "image/jpeg",   ext: "jpg" },
  "iVBORw0": { mime: "image/png",    ext: "png" },
  "UklGR":   { mime: "image/webp",   ext: "webp" },
  "AAAAHG":  { mime: "image/heic",   ext: "heic" },
  "AAAAIG":  { mime: "image/heif",   ext: "heif" },
  "SUkq":    { mime: "image/tiff",   ext: "tiff" }
};

function addSecurityHeaders(headers, request, env) {
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Robots-Tag", "noindex, nofollow");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  const origin = request && request.headers ? request.headers.get("Origin") : null;
  const allowed = (env && env.ALLOWED_ORIGIN) || DEFAULT_ALLOWED_ORIGIN;
  const useOrigin = (allowed === "*" || !allowed) ? (origin || "*") : allowed;
  headers.set("Access-Control-Allow-Origin", useOrigin);
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Accept, X-Client-App, Authorization");
  headers.set("Access-Control-Max-Age", "86400");
  headers.set("Vary", "Origin");
  return headers;
}

function jsonError(message, status, request, env) {
  const safe = String(message || "Unknown error").substring(0, 500).replace(/[\u0000-\u001F\u007F]/g, "");
  const headers = new Headers({ "Content-Type": "application/json; charset=utf-8" });
  addSecurityHeaders(headers, request, env);
  return new Response(JSON.stringify({ error: safe }), { status, headers });
}

function jsonSuccess(data, request, extras, env) {
  const headers = new Headers({ "Content-Type": "application/json; charset=utf-8" });
  addSecurityHeaders(headers, request, env);
  if (extras && extras.truncated) headers.set("X-Truncated", "1");
  return new Response(JSON.stringify(data), { status: 200, headers });
}

function decodeBase64Url(value) {
  const b64 = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - b64.length % 4) % 4));
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function decodeJwtJson(part) {
  return JSON.parse(new TextDecoder().decode(decodeBase64Url(part)));
}

async function firebaseJwks(forceRefresh) {
  if (!forceRefresh && firebaseJwksCache && Date.now() < firebaseJwksExpiresAt) return firebaseJwksCache;
  const response = await fetch(FIREBASE_JWKS_URL, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error("Firebase public keys are unavailable");
  const data = await response.json();
  if (!data || !Array.isArray(data.keys)) throw new Error("Firebase public keys response is invalid");
  const maxAge = /max-age=(\d+)/i.exec(response.headers.get("Cache-Control") || "");
  firebaseJwksCache = data.keys;
  firebaseJwksExpiresAt = Date.now() + (maxAge ? Number(maxAge[1]) : 3600) * 1000;
  return firebaseJwksCache;
}

async function verifyFirebaseIdToken(request, env) {
  const match = /^Bearer\s+([A-Za-z0-9._~-]+)$/i.exec(request.headers.get("Authorization") || "");
  if (!match) return null;
  const parts = match[1].split(".");
  if (parts.length !== 3) return null;

  let header, claims;
  try { header = decodeJwtJson(parts[0]); claims = decodeJwtJson(parts[1]); }
  catch (_) { return null; }
  const projectId = String((env && env.FIREBASE_PROJECT_ID) || "salary-v01");
  const now = Math.floor(Date.now() / 1000);
  if (header.alg !== "RS256" || typeof header.kid !== "string" ||
      claims.aud !== projectId || claims.iss !== `https://securetoken.google.com/${projectId}` ||
      typeof claims.sub !== "string" || !claims.sub || claims.sub.length > 128 ||
      !Number.isFinite(claims.exp) || claims.exp <= now ||
      !Number.isFinite(claims.iat) || claims.iat > now + 60 ||
      !Number.isFinite(claims.auth_time) || claims.auth_time > now + 60) return null;

  let keys = await firebaseJwks(false);
  let jwk = keys.find(key => key.kid === header.kid && key.kty === "RSA");
  if (!jwk) {
    keys = await firebaseJwks(true);
    jwk = keys.find(key => key.kid === header.kid && key.kty === "RSA");
  }
  if (!jwk) return null;

  try {
    const key = await crypto.subtle.importKey("jwk", jwk, {
      name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"
    }, false, ["verify"]);
    const valid = await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" }, key, decodeBase64Url(parts[2]),
      new TextEncoder().encode(parts[0] + "." + parts[1])
    );
    return valid ? claims : null;
  } catch (_) { return null; }
}

function currentQuotaMonth() { return new Date().toISOString().slice(0, 7); }
async function kvNumber(kv, key) {
  const value = Number.parseInt(await kv.get(key) || "0", 10);
  return Number.isFinite(value) && value > 0 ? value : 0;
}
async function accountIsPro(uid, token, env) {
  if (!env || !env.DB_URL || !env.SCANS) throw new Error("Cloud data bindings are not configured");
  const url = `${String(env.DB_URL).replace(/\/$/, "")}/users/${encodeURIComponent(uid)}/pro/verified.json?auth=${encodeURIComponent(token)}`;
  const response = await fetch(url);
  if (response.status >= 500) throw new Error("Could not check account plan");
  if (!response.ok) return false;
  return (await response.json()) === true;
}
async function readQuota(uid, month, isPro, kv) {
  const used = await kvNumber(kv, `${uid}:${month}`);
  const bonus = await kvNumber(kv, `bonus:${uid}:${month}`);
  const limit = FREE_SCAN_LIMIT + bonus;
  return { month, pro: isPro, scans: { used, bonus, limit: isPro ? null : limit, remaining: isPro ? null : Math.max(0, limit - used) } };
}

async function parseAIReceipt(text) {
  if (typeof text !== "string" || !text.trim()) return null;
  let clean = text.replace(/```json/gi, "").replace(/```/g, "").trim();
  const start = clean.indexOf("{"), end = clean.lastIndexOf("}");
  if (start >= 0 && end > start) clean = clean.slice(start, end + 1);
  try {
    const normalized = normalizeReceiptPayload(JSON.parse(clean));
    if (normalized.items.length) return normalized;
  } catch (_) {}

  const merchantMatch = clean.match(/"merchant"\s*:\s*"((?:\\.|[^"\\])*)"/i);
  const items = [];
  const itemPattern = /"name"\s*:\s*"((?:\\.|[^"\\])*)"\s*,\s*"(?:price|amount)"\s*:\s*"?([^"},\s]+)"?/gi;
  let match;
  while ((match = itemPattern.exec(clean)) !== null) {
    let name = match[1];
    try { name = JSON.parse(`"${name}"`); } catch (_) {}
    const amount = _parsePrice(match[2], match[1]);
    if (name && _isReasonablePrice(amount, name)) items.push({ name, price: amount, category: "Other" });
  }
  if (!items.length) return null;
  return normalizeReceiptPayload({ merchant: merchantMatch ? merchantMatch[1] : "Store", items });
}

// ---------- Copy of strict parsing helpers (kept in sync with frontend) ----------
function _cleanShort(v) { return v == null ? "" : String(v).replace(/[\u0000-\u001F\u007F]/g, "").trim().substring(0, 200); }
function _looksLikeDate(tok) {
  if (!tok) return false;
  const s = String(tok).trim(); if (!/[0-9]/.test(s)) return false;
  if (/^\s*(19|20)\d{2}[-\/.](0?[1-9]|1[012])[-\/.](0?[1-9]|[12]\d|3[01])\s*$/.test(s)) return true;
  if (/^\s*(0?[1-9]|[12]\d|3[01])[-\/.](0?[1-9]|1[012])[-\/.](19|20)?\d{2}\s*$/.test(s)) return true;
  if (/^\s*(0?[1-9]|1[012])[-\/.](0?[1-9]|[12]\d|3[01])[-\/.](19|20)?\d{2}\s*$/.test(s)) return true;
  return false;
}
function _looksLikePhone(tok) {
  if (!tok) return false;
  const s = String(tok).trim();
  const d = s.replace(/\D/g, ""); if (d.length < 7 || d.length > 15) return false;
  return /^\+?\d[\d\s\-\(\)\.]{5,}\d$/.test(s);
}
function _looksLikeReceiptNumber(tok) {
  return tok && /^\s*(#|No\.?|Number|Inv\.?|Invoice|Bill|Order|Receipt|Ref\.?)\s*[:\-]?\s*[A-Za-z0-9\-]{2,}/i.test(String(tok));
}
function _looksLikePureId(num) {
  if (!Number.isFinite(num)) return false;
  const s = String(Math.abs(Math.round(num))); return s.length >= 8 && s.length <= 16;
}
function _looksLikeYear(num) {
  if (!Number.isFinite(num)) return false;
  const n = Math.round(num); const y = new Date().getFullYear();
  return n >= y - 5 && n <= y + 5;
}
function _isReasonablePrice(num, ctx) {
  if (!Number.isFinite(num) || !(num > 0) || num >= 1e9) return false;
  const wholeDigits = String(Math.round(num)).length; if (wholeDigits >= 11) return false;
  if (ctx && typeof ctx === "string") {
    const c = ctx.trim();
    if (_looksLikeDate(c) || _looksLikePhone(c) || _looksLikeReceiptNumber(c)) return false;
  }
  if (Number.isInteger(num)) {
    if (_looksLikePureId(num)) return false;
    const cl = String(ctx || "").toLowerCase();
    if (_looksLikeYear(num) && !/(price|amount|total|subtotal|tax|grand|sum|due|balance|rs|pkr|\$|€|£|₹|₨)/.test(cl)) return false;
  }
  return true;
}
function _parsePrice(v, ctx) {
  if (typeof v === "number") {
    const n = Number(v.toFixed(2)); return _isReasonablePrice(n, ctx) ? n : NaN;
  }
  if (typeof v !== "string") return NaN;
  const s = v.replace(/,/g, "").replace(/(?:Rs\.?|PKR|pkr|USD|EUR|GBP|INR|AED|SAR|QAR|KWD|BHD|OMR|CNY|JPY|KRW|TRY|RUB|BRL|ZAR|NGN|EGP|BDT|IDR|MYR|THB|PHP|VND|CAD|AUD|CHF|SGD|KES|GHS|\$|€|£|₹|₨|¥|₩|₺|₽|R\$|₦|৳|Rp|RM|฿|₱|₫)/gi, "").trim();
  if (!s || s.length > 30) return NaN;
  if (_looksLikeDate(s) || _looksLikePhone(s) || _looksLikeReceiptNumber(s)) return NaN;
  const val = parseFloat(s);
  if (!Number.isFinite(val)) return NaN;
  const fixed = Number(val.toFixed(2));
  return _isReasonablePrice(fixed, ctx || v) ? fixed : NaN;
}
function _parseQty(v) {
  if (v == null) return NaN; let n;
  if (typeof v === "number") n = v;
  else {
    const s = String(v).trim().replace(/,/g, "").replace(/x$/i, "").trim();
    if (!s || _looksLikeDate(s) || _looksLikePhone(s)) return NaN;
    n = parseFloat(s);
  }
  if (!Number.isFinite(n) || n <= 0 || n > 1e6) return NaN;
  return Number(n.toFixed(3));
}
function _finalItemAmount(it) {
  if (!it || typeof it !== "object") return NaN;
  const candidates = [
    _parsePrice(it.lineTotal, it.name), _parsePrice(it.line_total, it.name),
    _parsePrice(it.total, it.name), _parsePrice(it.subtotal, it.name),
    _parsePrice(it.amount, it.name), _parsePrice(it.price, it.name)
  ];
  for (let i = 0; i < candidates.length; i++) if (_isReasonablePrice(candidates[i], it.name)) return candidates[i];
  const q = _parseQty(it.quantity != null ? it.quantity : it.qty);
  const u = _parsePrice(it.unitPrice != null ? it.unitPrice : it.unit_price, it.name);
  if (_isReasonablePrice(q, "") && _isReasonablePrice(u, it.name)) {
    const p = Number((q * u).toFixed(2));
    if (_isReasonablePrice(p, it.name)) return p;
  }
  const legacy = _parsePrice(it.price != null ? it.price : it.amount, it.name);
  return _isReasonablePrice(legacy, it.name) ? legacy : NaN;
}
function _guessCategory(text) {
  const kw = {
    "Food & Dining": ["restaurant","cafe","coffee","tea","food","pizza","burger","biryani","kfc","mcdonald","hardee","chicken","bakery","snack","meal","kitchen","grocery","mart","supermarket","juice","dessert","sweet","meat","milk","bread","fruit","vegetable","dine","nando","subway","dominos"],
    "Bills & Utilities": ["electricity","wapda","k-electric","kelectric","gas bill","sui gas","internet","wifi","broadband","ptcl","mobile load","topup","utility","bill","water bill","postpaid","prepaid"],
    "Installment / EMI": ["installment","instalment","emi","loan","finance","easypaisa loan","tez"],
    "Transport": ["fuel","petrol","diesel","uber","careem","indrive","taxi","cab","bus fare","fare","parking","toll","rickshaw","cng","fuel station","pso","shell","total parco"],
    "Shopping": ["mall","store","outlet","fashion","clothing","garment","shoes","footwear","electronics","mobile shop","apparel","boutique","daraz","department"],
    "Entertainment": ["cinema","movie","netflix","imax","theatre","theater","game","gaming","park","amusement","concert","spotify"],
    "Health": ["pharmacy","medicine","hospital","clinic","doctor","medical","chemist","lab test","dawa","drug store"]
  };
  const hay = String(text || "").toLowerCase();
  for (const cat of Object.keys(kw)) {
    if (kw[cat].some(k => hay.indexOf(k) !== -1)) return cat;
  }
  return "Shopping";
}
function normalizeReceiptPayload(raw) {
  const out = { merchant:"", date:"", receiptNumber:"", phone:"", items:[], subtotal:0, tax:0, discount:0, grandTotal:0 };
  if (!raw) return out;
  let src = raw;
  if (typeof src === "string") { try { src = JSON.parse(String(src).replace(/```json/gi, "").replace(/```/g, "").trim()); } catch(_) { return out; } }
  if (typeof src !== "object") return out;
  out.merchant = _cleanShort(src.merchant || src.store || src.shop || src.supplier || src.vendor || src.retailer || "");
  out.date = _cleanShort(src.date || src.receiptDate || src.invoiceDate || src.transactionDate || src.billDate || src.issued || src.timestamp || "");
  if (out.date && !_looksLikeDate(out.date)) out.date = "";
  out.receiptNumber = _cleanShort(src.receiptNumber || src.receiptNo || src.invoiceNo || src.invoiceNumber || src.orderId || src.orderNumber || src.billNo || src.ticketNumber || src.ref || src.reference || src.id || "");
  out.phone = _cleanShort(src.phone || src.telephone || src.tel || src.mobile || src.contact || "");
  if (out.phone && !_looksLikePhone(out.phone)) out.phone = "";
  const subtotal = _parsePrice(src.subtotal != null ? src.subtotal : src.sub_total, "subtotal");
  const tax = _parsePrice(src.tax != null ? src.tax : (src.taxes != null ? src.taxes : (src.vat != null ? src.vat : (src.gst != null ? src.gst : src.totalTax))), "tax");
  const discount = _parsePrice(src.discount != null ? src.discount : (src.promo != null ? src.promo : src.coupon), "discount");
  const grandTotal = _parsePrice(src.grandTotal != null ? src.grandTotal : (src.grand_total != null ? src.grand_total : (src.total != null ? src.total : (src.totalDue != null ? src.totalDue : (src.amountDue != null ? src.amountDue : (src.balance != null ? src.balance : src.netAmount))))), "grand total");
  const itemsArr = Array.isArray(src.items || src.lineItems || src.line_items || src.products || src.purchases || src.articles)
    ? (src.items || src.lineItems || src.line_items || src.products || src.purchases || src.articles) : [];
  itemsArr.forEach(function(it) {
    if (!it || typeof it !== "object") return;
    const name = _cleanShort(it.name || it.description || it.item || it.product || it.title || it.desc || "Purchased item") || "Purchased item";
    const finalAmount = _finalItemAmount(it);
    if (!_isReasonablePrice(finalAmount, name)) return;
    let qty = _parseQty(it.quantity != null ? it.quantity : it.qty);
    let unit = _parsePrice(it.unitPrice != null ? it.unitPrice : it.unit_price, name);
    let lineTotal = _parsePrice(it.lineTotal != null ? it.lineTotal : (it.line_total != null ? it.line_total : (it.total != null ? it.total : (it.subtotal != null ? it.subtotal : (it.amount != null ? it.amount : it.price)))), name);
    if (!_isReasonablePrice(qty, "")) qty = 1;
    if (!_isReasonablePrice(unit, name)) unit = finalAmount;
    if (!_isReasonablePrice(lineTotal, name)) lineTotal = finalAmount;
    if (qty !== 1 && Math.abs(lineTotal - Number((qty * unit).toFixed(2))) > 0.02 && _isReasonablePrice(lineTotal, name)) {
      unit = Number((lineTotal / qty).toFixed(2));
      if (!_isReasonablePrice(unit, name)) unit = finalAmount;
    }
    const cat = _cleanShort(it.category) || _guessCategory(name + " " + out.merchant);
    out.items.push({ name: name, quantity: qty, unitPrice: unit, lineTotal: (_isReasonablePrice(lineTotal, name) ? lineTotal : finalAmount), category: cat || "Shopping" });
  });
  const itemsSum = out.items.reduce((a, b) => a + (b.lineTotal || 0), 0);
  out.subtotal = _isReasonablePrice(subtotal, "subtotal") ? subtotal : 0;
  out.tax      = _isReasonablePrice(tax, "tax") ? tax : 0;
  out.discount = _isReasonablePrice(discount, "discount") ? discount : 0;
  let computed = out.subtotal > 0 ? out.subtotal : itemsSum;
  computed = Number((computed + out.tax - out.discount).toFixed(2));
  if (_isReasonablePrice(grandTotal, "grand total")) {
    out.grandTotal = grandTotal;
    if (out.subtotal <= 0) {
      out.subtotal = Number((grandTotal - out.tax + out.discount).toFixed(2));
      if (!_isReasonablePrice(out.subtotal, "subtotal")) out.subtotal = itemsSum;
    }
  } else {
    out.grandTotal = _isReasonablePrice(computed, "grand total") ? computed : itemsSum;
  }
  return out;
}
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Google Play Billing purchase verification placeholder
// -----------------------------------------------------------------------------
// SECURITY: NEVER trust a purchaseToken sent from the client without verifying
// it against Google's servers server-side. This worker is the only place where
// your Google Play Developer API credentials (ServiceAccount JSON) may live.
//
// REQUIRED SECRETS (wrangler secret put ...):
//   GPAY_SERVICE_ACCOUNT_JSON  -> full JSON key contents (stringified) for the
//                                Google Play Developer API service account.
//   GPAY_APP_PACKAGE_NAME      -> e.g. "com.salaryledger.app"
//   FIREBASE_PROJECT_ID        -> e.g. "salary-v01"  (only if you want to also
//                                verify idToken here before marking RTDB)
//
// The client POSTs: { purchaseToken, productId, uid, idToken }
// We respond with:  { ok: true,  productId, purchaseToken, purchaseInfo }
//                or  { ok: false, error: "..." }
//
// Zero data is persisted in this worker. The client writes the `verified`
// flag to its own `/users/<uid>/pro` RTDB path only after this endpoint
// returns ok=true. Firebase Security Rules (database.rules.json) additionally
// restrict the shape of data written there, but the server-side check below
// is the actual gate for the `verified=true` write to be trustworthy.
//
// Requests to this route also pass the Firebase ID-token check in handleRequest.
// -----------------------------------------------------------------------------
async function handleVerifyPurchase(request, env, _ctx) {
  const bodyRaw = await readBytesWithCap(request.body, 64 * 1024);
  if (!bodyRaw || bodyRaw.length === 0) return jsonError("Empty request body.", 400, request, env);
  let body;
  try { body = JSON.parse(new TextDecoder("utf-8", { fatal: false }).decode(bodyRaw)); }
  catch (_) { return jsonError("Could not parse JSON.", 400, request, env); }
  if (!body || typeof body !== "object") return jsonError("Malformed payload.", 400, request, env);
  if (typeof body.purchaseToken !== "string" || !body.purchaseToken.trim()) return jsonError("Missing purchaseToken.", 400, request, env);
  if (typeof body.productId !== "string" || !body.productId.trim()) return jsonError("Missing productId.", 400, request, env);
  if (body.productId.trim() !== "salary_ledger_pro") return jsonError("Unknown productId.", 400, request, env);

  // Fail closed until a real Google Play verification implementation is configured.
  return jsonError("Purchase verification is not configured on the server.", 503, request, env);
}
// -----------------------------------------------------------------------------

async function handleRequest(request, env, _ctx) {
  if (request.method === "OPTIONS") {
    const h = new Headers(); addSecurityHeaders(h, request, env);
    return new Response(null, { status: 204, headers: h });
  }
  let reqUrl = null;
  try { reqUrl = new URL(request.url); } catch(_) { reqUrl = null; }
  const pathname = (reqUrl && reqUrl.pathname) ? reqUrl.pathname : "/";
  const isUsageRequest = request.method === "GET" && /\/usage\/?$/.test(pathname);
  if (!isUsageRequest && request.method !== "POST") return jsonError("Method not allowed.", 405, request, env);
  if (request.method === "POST") {
    const ct = (request.headers.get("Content-Type") || "").toLowerCase();
    if (!ct.includes("application/json")) return jsonError("Send application/json.", 415, request, env);
  }

  let authClaims;
  try { authClaims = await verifyFirebaseIdToken(request, env); }
  catch (_) { return jsonError("Authentication service is temporarily unavailable. Please try again.", 503, request, env); }
  if (!authClaims) return jsonError("Please sign in again to use this feature.", 401, request, env);
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");

  if (!env || !env.SCANS) return jsonError("Scan quota storage is not configured.", 503, request, env);
  if (isUsageRequest) {
    try {
      const isPro = await accountIsPro(authClaims.sub, token, env);
      return jsonSuccess(await readQuota(authClaims.sub, currentQuotaMonth(), isPro, env.SCANS), request, null, env);
    } catch (_) { return jsonError("Could not load your monthly usage. Please try again.", 503, request, env); }
  }

  if (/\/grant\/?$/.test(pathname)) {
    try {
      if (await accountIsPro(authClaims.sub, token, env)) return jsonError("Pro accounts have unlimited scans.", 409, request, env);
      const month = currentQuotaMonth(), lastKey = `last:${authClaims.sub}`;
      const last = await kvNumber(env.SCANS, lastKey);
      if (Date.now() - last < AD_COOLDOWN_MS) return jsonError("Please wait before claiming another ad scan.", 429, request, env);
      const bonusKey = `bonus:${authClaims.sub}:${month}`, bonus = await kvNumber(env.SCANS, bonusKey);
      if (bonus >= AD_BONUS_MAX) return jsonError("You have no more ad scans available this month.", 429, request, env);
      await env.SCANS.put(bonusKey, String(bonus + 1), { expirationTtl: 60 * 60 * 24 * 62 });
      await env.SCANS.put(lastKey, String(Date.now()), { expirationTtl: Math.ceil(AD_COOLDOWN_MS / 1000) });
      const limit = FREE_SCAN_LIMIT + bonus + 1;
      const used = await kvNumber(env.SCANS, `${authClaims.sub}:${month}`);
      return jsonSuccess({ ok: true, bonus: bonus + 1, usage: { month, pro: false, scans: { used, bonus: bonus + 1, limit, remaining: Math.max(0, limit - used) } } }, request, null, env);
    } catch (_) { return jsonError("Could not add an ad scan right now.", 503, request, env); }
  }

  if (pathname.endsWith("/verify-purchase") || /\/verify-purchase\/?$/.test(pathname)) {
    return handleVerifyPurchase(request, env, _ctx);
  }

  if (pathname !== "/" && !pathname.endsWith("/scan")) return jsonError("Not found.", 404, request, env);
  if (!env.AI || typeof env.AI.run !== "function") return jsonError("Cloudflare Workers AI is not configured.", 503, request, env);

  const clHeader = request.headers.get("Content-Length");
  if (clHeader) {
    const n = parseInt(clHeader, 10);
    if (Number.isFinite(n) && n > MAX_BODY_BYTES) return jsonError("Request Entity Too Large.", 413, request, env);
  }

  // --- Read raw body with a hard size cap to avoid OOM on malformed streams ---
  const rawBuf = await readBytesWithCap(request.body, MAX_BODY_BYTES);
  if (!rawBuf) return jsonError("Request Entity Too Large.", 413, request, env);
  if (rawBuf.length === 0) return jsonError("Empty request body.", 400, request, env);

  let body;
  try { body = JSON.parse(new TextDecoder("utf-8", { fatal: false }).decode(rawBuf)); }
  catch (_) { return jsonError("Could not parse JSON request body.", 400, request, env); }

  if (!body || typeof body !== "object") return jsonError("Malformed request payload.", 400, request, env);

  const image = body.image;
  if (typeof image !== "string" || image.length === 0) {
    return jsonError("Missing or invalid 'image' field.", 400, request, env);
  }
  if (image.length > 14 * 1024 * 1024) return jsonError("Encoded image payload is too large.", 413, request, env);

  const split = image.indexOf(",");
  const header = split >= 0 ? image.substring(0, split) : "";
  const b64 = split >= 0 ? image.substring(split + 1) : image;
  if (header && !/^data:image\/[a-zA-Z0-9+.-]+;base64$/i.test(header)) {
    return jsonError("Image must be a base64 data URL (data:image/...;base64,...).", 400, request, env);
  }
  const mimeFromHeader = /^data:(image\/[a-zA-Z0-9+.-]+);base64$/i.exec(header);
  const mime = mimeFromHeader ? mimeFromHeader[1].toLowerCase() : "";
  if (mime && !mime.startsWith("image/")) {
    return jsonError("Unsupported image MIME type.", 415, request, env);
  }

  // Validate magic bytes (first ~8 base64 chars map to the first 6 bytes)
  const head64 = (b64 || "").replace(/\s+/g, "").substring(0, 16);
  const detected = Object.keys(IMAGE_MAGIC).find(prefix => head64.startsWith(prefix));
  if (!detected) return jsonError("Could not validate image format. Use JPEG, PNG, or WebP.", 415, request, env);

  // Refuse to proceed when decoded size would exceed MAX_IMAGE_BYTES
  const approxDecoded = Math.floor((b64.length * 3) / 4);
  if (approxDecoded > MAX_IMAGE_BYTES) return jsonError("Decoded image exceeds the 10 MB limit.", 413, request, env);

  let imageBytes;
  try {
    const binary = atob(b64.replace(/\s+/g, ""));
    imageBytes = Uint8Array.from(binary, c => c.charCodeAt(0));
  } catch (_) { return jsonError("Invalid image data.", 400, request, env); }

  let isPro, quota;
  const month = currentQuotaMonth();
  try {
    isPro = await accountIsPro(authClaims.sub, token, env);
    quota = await readQuota(authClaims.sub, month, isPro, env.SCANS);
  } catch (_) { return jsonError("Could not check your account or scan limit. Please try again.", 503, request, env); }
  if (!isPro && quota.scans.used >= quota.scans.limit) return jsonError("Free scan limit reached.", 402, request, env);

  let aiResponse;
  try {
    aiResponse = await env.AI.run(RECEIPT_MODEL, { prompt: RECEIPT_PROMPT, image: [...imageBytes], max_tokens: 1024 });
  } catch (_) { return jsonError("Receipt scanning is temporarily unavailable. Please try again.", 502, request, env); }

  const data = await parseAIReceipt(aiResponse && aiResponse.response || "");
  if (!data || !data.items.length) return jsonError("Could not read item lines from this receipt. Try a clearer photo.", 422, request, env);
  if (!data.merchant) data.merchant = "Unknown Store";
  data.items = data.items.map(item => ({ ...item, price: item.lineTotal || item.amount || item.price || 0 }));

  if (!isPro) {
    try { await env.SCANS.put(`${authClaims.sub}:${month}`, String(quota.scans.used + 1), { expirationTtl: 60 * 60 * 24 * 62 }); }
    catch (_) { return jsonError("Could not save your scan count. Please try again.", 503, request, env); }
    quota.scans.used += 1;
    quota.scans.remaining = Math.max(0, quota.scans.limit - quota.scans.used);
  }
  return jsonSuccess({ ...data, usage: quota }, request, null, env);
}

async function readBytesWithCap(body, cap) {
  if (!body) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value && value.length) {
      total += value.length;
      if (total > cap) return null;
      chunks.push(value);
    }
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}
