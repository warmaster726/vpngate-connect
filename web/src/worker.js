import { connect } from "cloudflare:sockets";

/**
 * VPN Gate Connect — Isolated Cloudflare Workers Web Profile Portal
 * =================================================================
 * Zero-dependency ES Module Worker (`no_bundle = true` in `web/wrangler.toml`).
 *
 * Capabilities:
 *  - Preserves the 4-tab Obsidian/Slate Dark Console UI (`Connect`, `Relays`, `Mirrors`, `Doctor`)
 *  - Multi-stage censorship-resilient discovery (`vpngate.net` + Official Mirror Portals + HTTPS CSV/Archive Mirrors)
 *  - Recursive live-path testing via OpenVPN TCP HARD_RESET (`cloudflare:sockets`)
 *  - Native iOS / iPadOS / macOS L2TP/IPsec `.mobileconfig` — issued only after handshake
 *  - Zero-prompt patched `.ovpn` export — issued only after handshake
 *  - Completely isolated from root `Cargo.toml`, `Cargo.lock`, and desktop installer scripts.
 */

const APP_VERSION = "0.2.10";
const POOL_CACHE_TTL_MS = 180_000;
const POOL_CACHE_KEY_URL = "https://vpngate-edge-cache.internal/v1/pool-snapshot";
const VERIFY_MEM_CACHE_URL = "https://vpngate-edge-cache.internal/v1/verify-memory";
const VERIFY_IP_CACHE_PREFIX = "https://vpngate-edge-cache.internal/v1/verify-ip/";
/** Desktop default tunnel wait is 22s; web uses 80% so distant relays can still answer. */
const HANDSHAKE_TIMEOUT_MS = 17_600;
/** Client fetch abort: handshake budget plus HTTP slack, still under the Workers ~30s cap. */
const VERIFY_CLIENT_ABORT_MS = 21_000;
const DEAD_PENALTY_MS = 15 * 60 * 1000;
const USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) VPNGate-WebWorker/0.2";
const OFFICIAL_CSV_URLS = [
  "https://www.vpngate.net/api/iphone/",
  "http://www.vpngate.net/api/iphone/",
];

const OFFICIAL_HTML_URLS = [
  "https://www.vpngate.net/en/",
  "http://www.vpngate.net/en/",
];

const OFFICIAL_MIRROR_SITES_URLS = [
  "https://www.vpngate.net/en/sites.aspx",
  "http://www.vpngate.net/en/sites.aspx",
  "https://www.vpngate.net/ja/sites.aspx",
  "https://www.vpngate.net/cn/sites.aspx",
];

const DAILY_MIRROR_JSON_URLS = [
  "https://cdn.jsdelivr.net/gh/kusrabyzarc/vpngate-daily-mirrors@latest/mirrors.json",
  "https://raw.githubusercontent.com/kusrabyzarc/vpngate-daily-mirrors/main/mirrors.json",
];

const WAYBACK_MIRROR_SITES_CDX_URL =
  "https://web.archive.org/cdx/search/cdx?url=www.vpngate.net/en/sites.aspx&output=json&limit=-2&filter=statuscode:200&collapse=timestamp:8";

const WAYBACK_PORTAL_CDX_URLS = [
  "https://web.archive.org/cdx/search/cdx?url=www.vpngate.net/en/&output=json&limit=-6&filter=statuscode:200&collapse=timestamp:8",
  "https://web.archive.org/cdx/search/cdx?url=www.vpngate.net/ja/&output=json&limit=-4&filter=statuscode:200&collapse=timestamp:8",
];

const MIRROR_CSV_URLS = [
  "https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/data/vpngate.csv",
  "https://raw.githubusercontent.com/funcra/vg-mirror/main/servers.csv",
  "https://raw.githubusercontent.com/sinspired/VpngateAPI/main/servers.csv",
  "https://raw.githubusercontent.com/cjsl99/VpngateAPI/main/servers.csv",
  "https://raw.githubusercontent.com/NetLops/vpngate-mirror/main/vpngate.csv",
  "https://raw.githubusercontent.com/GeorgeXie2333/vpngate-mirror/main/data/servers.csv",
  "https://raw.githubusercontent.com/funcra/vpngate-mirror/main/api/iphone.csv",
];

const SDISE_CSV_URL = "https://raw.githubusercontent.com/sdise/vpngate/main/vpngate.csv";
const MAX_OFFICIAL_MIRROR_CSV = 12;

const SAFE_PROBE_PORTS = new Set([443, 995, 1194, 1195, 1701, 5555, 8080, 8443]);

// Canonical ISO-3166 alpha-2 lookup table (100% parity with `vpngate-core/src/country.rs`)
const ISO2_ENTRIES = [
  ["AE", "United Arab Emirates"], ["AL", "Albania"], ["AM", "Armenia"], ["AR", "Argentina"],
  ["AT", "Austria"], ["AU", "Australia"], ["AZ", "Azerbaijan"], ["BA", "Bosnia and Herzegovina"],
  ["BD", "Bangladesh"], ["BE", "Belgium"], ["BG", "Bulgaria"], ["BH", "Bahrain"],
  ["BO", "Bolivia"], ["BR", "Brazil"], ["BY", "Belarus"], ["CA", "Canada"],
  ["CH", "Switzerland"], ["CL", "Chile"], ["CN", "China"], ["CO", "Colombia"],
  ["CR", "Costa Rica"], ["CY", "Cyprus"], ["CZ", "Czech Republic"], ["DE", "Germany"],
  ["DK", "Denmark"], ["DO", "Dominican Republic"], ["DZ", "Algeria"], ["EC", "Ecuador"],
  ["EE", "Estonia"], ["EG", "Egypt"], ["ES", "Spain"], ["FI", "Finland"],
  ["FR", "France"], ["GB", "United Kingdom"], ["GE", "Georgia"], ["GH", "Ghana"],
  ["GR", "Greece"], ["GT", "Guatemala"], ["HK", "Hong Kong"], ["HN", "Honduras"],
  ["HR", "Croatia"], ["HU", "Hungary"], ["ID", "Indonesia"], ["IE", "Ireland"],
  ["IL", "Israel"], ["IN", "India"], ["IQ", "Iraq"], ["IR", "Iran"],
  ["IS", "Iceland"], ["IT", "Italy"], ["JO", "Jordan"], ["JP", "Japan"],
  ["KE", "Kenya"], ["KG", "Kyrgyzstan"], ["KH", "Cambodia"], ["KR", "Korea Republic of"],
  ["KW", "Kuwait"], ["KZ", "Kazakhstan"], ["LA", "Laos"], ["LB", "Lebanon"],
  ["LK", "Sri Lanka"], ["LT", "Lithuania"], ["LU", "Luxembourg"], ["LV", "Latvia"],
  ["MA", "Morocco"], ["MD", "Moldova"], ["MK", "North Macedonia"], ["MM", "Myanmar"],
  ["MN", "Mongolia"], ["MT", "Malta"], ["MU", "Mauritius"], ["MX", "Mexico"],
  ["MY", "Malaysia"], ["NG", "Nigeria"], ["NI", "Nicaragua"], ["NL", "Netherlands"],
  ["NO", "Norway"], ["NP", "Nepal"], ["NZ", "New Zealand"], ["OM", "Oman"],
  ["PA", "Panama"], ["PE", "Peru"], ["PH", "Philippines"], ["PK", "Pakistan"],
  ["PL", "Poland"], ["PR", "Puerto Rico"], ["PT", "Portugal"], ["PY", "Paraguay"],
  ["QA", "Qatar"], ["RO", "Romania"], ["RS", "Serbia"], ["RU", "Russian Federation"],
  ["SA", "Saudi Arabia"], ["SE", "Sweden"], ["SG", "Singapore"], ["SI", "Slovenia"],
  ["SK", "Slovakia"], ["SN", "Senegal"], ["SV", "El Salvador"], ["TH", "Thailand"],
  ["TN", "Tunisia"], ["TR", "Turkey"], ["TW", "Taiwan"], ["TZ", "Tanzania"],
  ["UA", "Ukraine"], ["US", "United States"], ["UY", "Uruguay"], ["UZ", "Uzbekistan"],
  ["VE", "Venezuela"], ["VN", "Viet Nam"], ["ZA", "South Africa"], ["ZW", "Zimbabwe"],
];

const ISO2_TO_LONG = new Map(ISO2_ENTRIES);
const NAME_TO_ISO2 = new Map(ISO2_ENTRIES.map(([k, v]) => [v.toLowerCase(), k]));
const COUNTRY_ALIASES = new Map([
  ["south korea", "KR"],
  ["republic of korea", "KR"],
  ["korea, republic of", "KR"],
  ["korea", "KR"],
  ["vietnam", "VN"],
  ["russia", "RU"],
  ["united states of america", "US"],
  ["usa", "US"],
  ["uk", "GB"],
  ["great britain", "GB"],
  ["taiwan, province of china", "TW"],
  ["hong kong sar", "HK"],
  ["iran (islamic republic of)", "IR"],
  ["czechia", "CZ"],
  ["turkiye", "TR"],
  ["türkiye", "TR"],
  ["moldova, republic of", "MD"],
  ["venezuela, bolivarian republic of", "VE"],
]);

// =============================================================================
// 1. IP Validation, Country Normalization & Mirror URL Hygiene
// =============================================================================

export function parseIpv4Octets(raw) {
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const out = [0, 0, 0, 0];
  for (let i = 0; i < 4; i++) {
    const p = parts[i];
    if (!p || p.length > 3 || (p.length > 1 && p[0] === "0")) return null;
    for (let j = 0; j < p.length; j++) {
      const ch = p.charCodeAt(j);
      if (ch < 48 || ch > 57) return null;
    }
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    out[i] = n;
  }
  return out;
}

export function isPoisonedIpv4(raw) {
  const o = Array.isArray(raw) ? raw : parseIpv4Octets(raw);
  if (!o) return true;
  const [a, b, c] = o;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // RFC 6598 CGNAT
  if (a === 198 && (b === 18 || b === 19)) return true; // RFC 2544 benchmark
  if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
  return false;
}

export function validPublicIpv4(raw) {
  const o = parseIpv4Octets(raw);
  if (!o || isPoisonedIpv4(o)) return null;
  return `${o[0]}.${o[1]}.${o[2]}.${o[3]}`;
}

export function normalizeCountryPair(rawLong, rawShort) {
  let cl = (rawLong || "").trim();
  let cs = (rawShort || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cs)) cs = "";
  if (!cs && cl) {
    const low = cl.toLowerCase();
    cs = NAME_TO_ISO2.get(low) || COUNTRY_ALIASES.get(low) || "";
  }
  if ((!cl || cl.toUpperCase() === cs) && cs && ISO2_TO_LONG.has(cs)) {
    cl = ISO2_TO_LONG.get(cs);
  }
  return [cl || "Unknown", cs || "XX"];
}

export function normalizeMirrorBaseUrl(raw) {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim().replace(/^['".]+|['".]+$/g, "");
  if (!trimmed) return null;
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  let parsed;
  try {
    parsed = new URL(withScheme);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  if (parsed.username || parsed.password) return null;
  const host = parsed.hostname.toLowerCase();
  if (!host || host === "localhost" || host.endsWith(".local") || host.endsWith(".internal")) {
    return null;
  }
  const excludedHosts = new Set([
    "www.vpngate.net", "vpngate.net", "www.tsukuba.ac.jp", "tsukuba.ac.jp",
    "www.softether.org", "softether.org", "icondrawer.com", "www.win10pcap.org",
    "web.archive.org",
  ]);
  if (excludedHosts.has(host) || host.endsWith(".tsukuba.ac.jp") || host.endsWith(".archive.org")) {
    return null;
  }
  if (parseIpv4Octets(host) && isPoisonedIpv4(host)) {
    return null;
  }
  if (host.includes(":")) return null; // Reject IPv6 literals in mirror ports
  const portPart = parsed.port ? `:${parsed.port}` : "";
  const baseUrl = `${parsed.protocol}//${host}${portPart}`;
  return { base_url: baseUrl, portal_url: `${baseUrl}/en/` };
}

// =============================================================================
// 2. Fast CSV, HTML & Mirror Parsers (Optimized for Cloudflare 10ms CPU Budget)
// =============================================================================

function parseUintClean(s, fallback = 0) {
  if (!s) return fallback;
  let n = 0;
  let found = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s.charCodeAt(i);
    if (ch >= 48 && ch <= 57) {
      n = n * 10 + (ch - 48);
      found = true;
    }
  }
  return found ? n : fallback;
}

function splitCsvRowFast(line, maxCols = 15) {
  const cols = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === "," && !inQuotes) {
      cols.push(cur);
      cur = "";
      if (cols.length === maxCols - 1) {
        cols.push(line.slice(i + 1));
        return cols;
      }
    } else {
      cur += ch;
    }
  }
  cols.push(cur);
  return cols;
}

function extractOvpnPortsFast(b64) {
  if (!b64 || b64.length < 40) return { ok: false, tcpPort: 0, udpPort: 0 };
  try {
    let head = "";
    if (b64.length > 4800) {
      // Fast window: SoftEther .ovpn places `proto` (~1.7KB) and `remote` (~2.5KB) inside b64[2160..3800]
      head = atob(b64.slice(2160, 3800));
      if (!head.includes("remote ")) {
        head = atob(b64.slice(0, 7200));
      }
    } else {
      const alignedLen = b64.length - (b64.length % 4);
      head = atob(b64.slice(0, alignedLen));
      if (!head.includes("<ca>")) return { ok: false, tcpPort: 0, udpPort: 0 };
    }
    const protoMatch = head.match(/^proto\s+([a-z0-9-]+)/im);
    const remoteMatch = head.match(/^remote\s+\S+\s+(\d+)/im);
    let tcpPort = 0;
    let udpPort = 0;
    if (protoMatch && remoteMatch) {
      const port = Number(remoteMatch[1]) || 0;
      if (port > 0 && port <= 65535) {
        if (protoMatch[1].toLowerCase().startsWith("tcp")) tcpPort = port;
        else udpPort = port;
      }
    }
    return { ok: true, tcpPort, udpPort };
  } catch {
    return { ok: false, tcpPort: 0, udpPort: 0 };
  }
}

export function parseVpngateCsvInto(csvRaw, serversByIp) {
  if (!csvRaw) return;
  const lines = csvRaw.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed[0] === "*" || trimmed[0] === "#") continue;
    const row = splitCsvRowFast(trimmed, 15);
    if (row.length < 15) continue;
    const ip = validPublicIpv4(row[1]);
    if (!ip) continue;

    const b64 = row[14].trim();
    const { ok: ovpnOk, tcpPort, udpPort } = extractOvpnPortsFast(b64);
    const score = parseUintClean(row[2], 0);
    let pingMs = parseUintClean(row[3], 9999);
    if (pingMs === 0) pingMs = 9999;
    const speedBps = parseUintClean(row[4], 0);
    const sessions = parseUintClean(row[7], 0);
    const uptimeMs = parseUintClean(row[8], 0);
    const [countryLong, countryShort] = normalizeCountryPair(row[5], row[6]);
    const hostname = row[0].trim() || ip;
    const operator = row[12].trim() || "VPNGate Volunteer";

    const existing = serversByIp.get(ip);
    if (existing) {
      if (ovpnOk) {
        existing.openvpn = true;
        if (!existing.ovpn_b64 || score >= existing.score) existing.ovpn_b64 = b64;
      }
      if (tcpPort > 0) existing.tcp_port = tcpPort;
      if (udpPort > 0) existing.udp_port = udpPort;
      if (score > existing.score) existing.score = score;
      if (pingMs > 0 && pingMs < existing.ping_ms) existing.ping_ms = pingMs;
      if (speedBps > existing.speed_bps) existing.speed_bps = speedBps;
      if (existing.country_short === "XX" && countryShort !== "XX") {
        existing.country_short = countryShort;
        existing.country_long = countryLong;
      }
    } else {
      serversByIp.set(ip, {
        hostname,
        ip,
        score,
        ping_ms: pingMs,
        speed_bps: speedBps,
        country_long: countryLong,
        country_short: countryShort,
        sessions,
        uptime_ms: uptimeMs,
        operator,
        l2tp: false,
        openvpn: ovpnOk,
        tcp_port: tcpPort,
        udp_port: udpPort,
        ovpn_b64: ovpnOk ? b64 : "",
      });
    }
  }
}

/** Rolling `sdise/vpngate` candidate CSV (`Country,Hostname,IP,Speed_Mbps`). Protocol flags stay false until handshake. */
export function parseSdiseCsvInto(csvRaw, serversByIp) {
  if (!csvRaw) return;
  const lines = csvRaw.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed) continue;
    const row = splitCsvRowFast(trimmed, 5);
    if (row.length < 4) continue;
    if (row[0].trim().toLowerCase() === "country") continue;
    const ip = validPublicIpv4(row[2]);
    if (!ip || serversByIp.has(ip)) continue;
    const [countryLong, countryShort] = normalizeCountryPair(row[0], "");
    let host = (row[1] || "").trim().replace(/\.opengw\.net$/i, "");
    if (!host) host = ip;
    const mbps = parseFloat(String(row[3]).replace(/,/g, "")) || 0;
    const speedBps = Math.round(Math.max(0, mbps) * 1_000_000);
    serversByIp.set(ip, {
      hostname: host,
      ip,
      score: Math.max(100_000, Math.floor(speedBps / 500)),
      ping_ms: 9999,
      speed_bps: speedBps,
      country_long: countryLong,
      country_short: countryShort,
      sessions: 0,
      uptime_ms: 0,
      operator: "VPNGate Volunteer",
      l2tp: false,
      openvpn: false,
      tcp_port: 0,
      udp_port: 0,
      ovpn_b64: "",
    });
  }
}

export function parseVpngateHtmlInto(htmlRaw, serversByIp) {
  if (!htmlRaw) return;
  const chunks = htmlRaw.split("<tr>");
  for (let i = 1; i < chunks.length; i++) {
    const chunk = chunks[i];
    if (!chunk.includes("vg_table_row_") || !chunk.includes("width='32' height='32'")) continue;
    const ipMatch = chunk.match(/>(\d{1,3}(?:\.\d{1,3}){3})</);
    if (!ipMatch) continue;
    const ip = validPublicIpv4(ipMatch[1]);
    if (!ip) continue;

    const hasL2tp = chunk.includes("howto_l2tp.aspx");
    let tcpPort = 0;
    let udpPort = 0;
    let hasOvpn = false;
    const ovpnMatch = chunk.match(/do_openvpn\.aspx\?([^'"]+)/);
    if (ovpnMatch) {
      hasOvpn = true;
      const qs = ovpnMatch[1];
      const mt = qs.match(/(?:^|&)tcp=(\d+)/);
      const mu = qs.match(/(?:^|&)udp=(\d+)/);
      if (mt) tcpPort = Number(mt[1]) || 0;
      if (mu) udpPort = Number(mu[1]) || 0;
    }

    const existing = serversByIp.get(ip);
    if (existing) {
      if (hasL2tp) existing.l2tp = true;
      if (tcpPort > 0) existing.tcp_port = tcpPort;
      if (udpPort > 0) existing.udp_port = udpPort;
      if (hasOvpn) existing.openvpn = true;
      if (existing.score > 0 && existing.country_short !== "XX") continue;
    }

    const flagMatch = chunk.match(/\.\.\/images\/flags\/([A-Z]{2})\.png'\s+width='32'/);
    const cnameMatch = chunk.match(/width='32'\s+height='32'\s*\/>\s*<br>\s*([^<]+)<\/td>/i);
    const [countryLong, countryShort] = normalizeCountryPair(
      cnameMatch ? cnameMatch[1] : "",
      flagMatch ? flagMatch[1] : ""
    );

    const hostMatch = chunk.match(/<b><span[^>]*>([^<]+?)(?:\.opengw\.net)?<\/span><\/b>/);
    const hostname = (hostMatch && hostMatch[1].trim()) || ip;

    let parsedScore = 0;
    const scoreMatches = chunk.matchAll(/<b><span[^>]*>([\d,]+)<\/span><\/b><\/td>/g);
    for (const sm of scoreMatches) parsedScore = parseUintClean(sm[1], parsedScore);

    const pingMatch = chunk.match(/Ping:\s*<b>(\d+)\s*ms<\/b>/i);
    const parsedPing = pingMatch ? parseUintClean(pingMatch[1], 9999) : 9999;

    const speedMatch = chunk.match(/<b><span[^>]*>([\d,.]+)\s*Mbps<\/span><\/b>/i);
    const speedBps = speedMatch
      ? Math.round((parseFloat(speedMatch[1].replace(/,/g, "")) || 0) * 1_000_000)
      : 0;

    const sessMatch = chunk.match(/<b><span[^>]*>(\d+)\s*(?:VPN\s+)?sessions<\/span><\/b>/i);
    const sessions = sessMatch ? parseUintClean(sessMatch[1], 0) : 0;

    if (existing) {
      if (parsedScore > existing.score) existing.score = parsedScore;
      if (parsedPing > 0 && parsedPing < existing.ping_ms) existing.ping_ms = parsedPing;
      if (speedBps > existing.speed_bps) existing.speed_bps = speedBps;
      if (existing.country_short === "XX" && countryShort !== "XX") {
        existing.country_short = countryShort;
        existing.country_long = countryLong;
      }
    } else {
      serversByIp.set(ip, {
        hostname,
        ip,
        score: parsedScore,
        ping_ms: parsedPing,
        speed_bps: speedBps,
        country_long: countryLong,
        country_short: countryShort,
        sessions,
        uptime_ms: 0,
        operator: "VPNGate Volunteer",
        l2tp: hasL2tp,
        openvpn: hasOvpn,
        tcp_port: tcpPort,
        udp_port: udpPort,
        ovpn_b64: "",
      });
    }
  }
}

export function parseMirrorSitesHtml(html, sourceLabel) {
  if (!html) return [];
  const out = [];
  const seen = new Map();
  const normalized = html.replace(/<li/gi, "\n<li").replace(/<br/gi, "\n<br");
  const lines = normalized.split("\n");
  const reUrl = /(https?:\/\/[a-z0-9.-]+:\d+(?:\/en\/?|\/?))/gi;
  const reLoc = /\(\s*(?:Mirror\s+)?location:\s*([^)<\r\n]+)/i;

  for (const line of lines) {
    const locMatch = line.match(reLoc);
    let locClean = "Unknown";
    if (locMatch && locMatch[1]) {
      const s = locMatch[1].replace(/&nbsp;/gi, " ").split("(LOCAL")[0].trim().replace(/\)+$/, "").trim();
      if (s) locClean = s;
    }
    reUrl.lastIndex = 0;
    let m;
    while ((m = reUrl.exec(line)) !== null) {
      const norm = normalizeMirrorBaseUrl(m[1]);
      if (!norm) continue;
      if (seen.has(norm.base_url)) {
        const idx = seen.get(norm.base_url);
        if (out[idx].location === "Unknown" && locClean !== "Unknown") {
          out[idx].location = locClean;
        }
      } else {
        seen.set(norm.base_url, out.length);
        out.push({
          base_url: norm.base_url,
          portal_url: norm.portal_url,
          location: locClean,
          source: sourceLabel,
        });
      }
    }
  }
  return out;
}

function extractAspnetFields(html) {
  const fields = {};
  const re = /<input[^>]*type=["']hidden["'][^>]*name=["']([^"']+)["'][^>]*value=["']([^"']*)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    fields[m[1]] = m[2];
  }
  return fields;
}

function mergeMirrorLists(...lists) {
  const out = [];
  const seen = new Map();
  for (const list of lists) {
    if (!Array.isArray(list)) continue;
    for (const m of list) {
      if (!m || !m.base_url) continue;
      if (seen.has(m.base_url)) {
        const idx = seen.get(m.base_url);
        if (out[idx].location === "Unknown" && m.location && m.location !== "Unknown") {
          out[idx].location = m.location;
        }
      } else {
        seen.set(m.base_url, out.length);
        out.push({ ...m });
      }
    }
  }
  return out;
}

// =============================================================================
// 3. Profile Builders (`buildAppleL2tpMobileconfig` & `buildPatchedOvpn`)
//    100% Structural Parity with `crates/vpngate-core/src/profile.rs`
// =============================================================================

function xmlEscape(input) {
  return String(input || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function sanitizeDnsList(rawDns) {
  const parts = String(rawDns || "1.1.1.1,1.0.0.1")
    .split(/[\s,;]+/)
    .map((s) => validPublicIpv4(s))
    .filter(Boolean);
  return parts.length > 0 ? parts.slice(0, 4) : ["1.1.1.1", "1.0.0.1"];
}

export function buildAppleL2tpMobileconfig(server, dnsServers = ["1.1.1.1", "1.0.0.1"]) {
  const countryLong = server.country_long || "Relay";
  const profileName = `VPN Gate — ${xmlEscape(countryLong)} (${xmlEscape(server.ip)})`;
  const ipEsc = xmlEscape(server.ip);
  const octets = parseIpv4Octets(server.ip);
  const suffix = octets
    ? octets.map((b) => b.toString(16).padStart(2, "0")).join("")
    : "00000001";
  const payloadUuid = `56504e47-4154-4500-8001-0000${suffix}`;
  const rootUuid = `56504e47-4154-4500-8000-0000${suffix}`;
  const sharedSecretB64 = btoa("vpn");
  const dnsXml = dnsServers.map((d) => `                    <string>${xmlEscape(d)}</string>`).join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNS</key>
            <dict>
                <key>ServerAddresses</key>
                <array>
${dnsXml}
                </array>
            </dict>
            <key>IPSec</key>
            <dict>
                <key>AuthenticationMethod</key>
                <string>SharedSecret</string>
                <key>SharedSecret</key>
                <data>${sharedSecretB64}</data>
            </dict>
            <key>IPv4</key>
            <dict>
                <key>OverridePrimary</key>
                <integer>1</integer>
            </dict>
            <key>PPP</key>
            <dict>
                <key>AuthName</key>
                <string>vpn</string>
                <key>AuthPassword</key>
                <string>vpn</string>
                <key>CommRemoteAddress</key>
                <string>${ipEsc}</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Configures VPN Gate L2TP over IPsec tunnel</string>
            <key>PayloadDisplayName</key>
            <string>${profileName}</string>
            <key>PayloadIdentifier</key>
            <string>net.vpngate.connect.l2tp.${ipEsc}</string>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadUUID</key>
            <string>${payloadUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>UserDefinedName</key>
            <string>${profileName}</string>
            <key>VPNType</key>
            <string>L2TP</string>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>${profileName}</string>
    <key>PayloadIdentifier</key>
    <string>net.vpngate.connect.profile.${ipEsc}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${rootUuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
`;
}

export function patchOvpnText(rawText, server, opts = {}) {
  const wantTcp = opts.transport === "tcp";
  const compat = opts.compat || "mobile3";
  const dnsServers = Array.isArray(opts.dnsServers) && opts.dnsServers.length
    ? opts.dnsServers
    : ["1.1.1.1", "1.0.0.1"];

  const linesOut = [];
  let inXmlTag = false;
  const rawLines = String(rawText || "").replace(/\r\n/g, "\n").split("\n");

  for (const rawLn of rawLines) {
    const stripped = rawLn.trim();
    if (stripped.startsWith("<") && !stripped.startsWith("</")) {
      inXmlTag = true;
    }
    if (!inXmlTag) {
      const low = stripped.toLowerCase();
      if (
        low.startsWith("cipher ") ||
        low.startsWith("data-ciphers") ||
        low.startsWith("ncp-") ||
        low.startsWith("auth-user-pass") ||
        low.startsWith("register-dns") ||
        low.startsWith("block-outside-dns") ||
        low.startsWith("windows-driver")
      ) {
        continue;
      }
      if (/^proto\s+/i.test(stripped)) {
        linesOut.push(wantTcp ? "proto tcp-client" : "proto udp");
        continue;
      }
      const remCap = stripped.match(/^remote\s+\S+\s+(\d+)/i);
      if (remCap) {
        const fallbackPort = Number(remCap[1]) || 443;
        const chosenPort = wantTcp && server.tcp_port > 0
          ? server.tcp_port
          : !wantTcp && server.udp_port > 0
            ? server.udp_port
            : fallbackPort;
        linesOut.push(`remote ${server.ip} ${chosenPort}`);
        continue;
      }
    }
    linesOut.push(rawLn);
    if (stripped.startsWith("</")) {
      inXmlTag = false;
    }
  }

  linesOut.push("");
  linesOut.push("# --- Patched by vpngate-core ---");

  if (compat === "ovpn26") {
    linesOut.push("data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC:AES-128-CBC");
    linesOut.push("data-ciphers-fallback AES-128-CBC");
    linesOut.push("disable-dco");
    linesOut.push("tls-cert-profile insecure");
  } else if (compat === "ovpn25") {
    linesOut.push("data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC");
    linesOut.push("data-ciphers-fallback AES-128-CBC");
    linesOut.push("tls-cert-profile insecure");
  } else if (compat === "ovpn24") {
    linesOut.push("ncp-ciphers AES-256-GCM:AES-128-GCM");
    linesOut.push("cipher AES-128-CBC");
  } else {
    // MobileCore3 (`OpenVPN Connect` iOS/Android & `Partout` / `OpenVPN for Android`)
    linesOut.push("cipher AES-128-CBC");
    linesOut.push("data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC");
  }

  linesOut.push("connect-retry-max 2");
  linesOut.push("resolv-retry 10");
  linesOut.push("hand-window 20");
  linesOut.push("keepalive 10 30");

  for (const dns of dnsServers) {
    linesOut.push(`dhcp-option DNS ${dns}`);
  }

  if (opts.windowsDriver === "tap-windows6" || opts.windowsDriver === "wintun") {
    linesOut.push(`windows-driver ${opts.windowsDriver}`);
    linesOut.push("block-outside-dns");
  }

  linesOut.push("");
  return linesOut.join("\n");
}

export function buildPatchedOvpn(server, donorB64, opts = {}) {
  const b64 = (server && server.ovpn_b64) || donorB64 || "";
  if (!b64) return null;
  let decoded;
  try {
    const bytes = Uint8Array.from(atob(b64.trim()), (c) => c.charCodeAt(0));
    decoded = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
  if (!decoded.includes("<ca>")) return null;
  return patchOvpnText(decoded, server, opts);
}

// =============================================================================
// 4. Multi-Stage Upstream Discovery, Edge Caching & `cloudflare:sockets` Prober
// =============================================================================

async function fetchTextTimeout(url, timeoutMs = 3500, init = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const headers = new Headers(init.headers || {});
    if (!headers.has("User-Agent")) headers.set("User-Agent", USER_AGENT);
    const resp = await fetch(url, { ...init, headers, signal: ctrl.signal });
    if (!resp.ok) return null;
    const text = await resp.text();
    if (!text || text.length < 32) return null;
    const setCookies = typeof resp.headers.getSetCookie === "function"
      ? resp.headers.getSetCookie()
      : (resp.headers.get("set-cookie") ? [resp.headers.get("set-cookie")] : []);
    const cookie = setCookies
      .map((c) => c.split(";")[0].trim())
      .filter(Boolean)
      .join("; ");
    return { text, cookie };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function postProtocolFilter(portalUrl, aspFields, cookie, checkboxName, timeoutMs = 4500) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(aspFields)) params.set(k, v);
  params.set(checkboxName, "on");
  params.set("Button3", "Refresh Servers List");

  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    Referer: portalUrl,
  };
  if (cookie) headers.Cookie = cookie;

  const res = await fetchTextTimeout(portalUrl, timeoutMs, {
    method: "POST",
    headers,
    body: params.toString(),
  });
  return res && res.text.length > 256 ? res.text : "";
}

async function fetchFallbackMirrors() {
  const dailyTask = (async () => {
    for (const url of DAILY_MIRROR_JSON_URLS) {
      const res = await fetchTextTimeout(url, 3200);
      if (!res) continue;
      try {
        const rows = JSON.parse(res.text);
        if (!Array.isArray(rows)) continue;
        const list = [];
        for (const r of rows) {
          const ip = r.IP || r.ip;
          const port = r.PORT || r.port;
          if (!ip || !port) continue;
          const norm = normalizeMirrorBaseUrl(`http://${String(ip).trim()}:${port}/en/`);
          if (norm) {
            list.push({
              base_url: norm.base_url,
              portal_url: norm.portal_url,
              location: String(r.LOCATION || r.location || "Mirror").trim() || "Mirror",
              source: "daily-mirror-feed",
            });
          }
        }
        if (list.length > 0) return list;
      } catch {
        // try next mirror feed
      }
    }
    return [];
  })();

  const waybackTask = (async () => {
    const cdx = await fetchTextTimeout(WAYBACK_MIRROR_SITES_CDX_URL, 2800);
    if (!cdx) return [];
    try {
      const rows = JSON.parse(cdx.text);
      if (!Array.isArray(rows) || rows.length < 2) return [];
      for (let i = rows.length - 1; i >= 1; i--) {
        const r = rows[i];
        if (Array.isArray(r) && r.length >= 3) {
          const snap = await fetchTextTimeout(`https://web.archive.org/web/${r[1]}id_/${r[2]}`, 3200);
          if (snap) {
            const parsed = parseMirrorSitesHtml(snap.text, "wayback-sites");
            if (parsed.length > 0) return parsed;
          }
        }
      }
    } catch {
      // ignore CDX failure
    }
    return [];
  })();

  const [daily, wb] = await Promise.all([dailyTask, waybackTask]);
  return mergeMirrorLists(daily, wb);
}

async function fetchFromOfficialMirrorPortal(mirror) {
  const [csvRes, enRes, sitesRes] = await Promise.all([
    fetchTextTimeout(`${mirror.base_url}/api/iphone/`, 4000),
    fetchTextTimeout(mirror.portal_url, 4000),
    fetchTextTimeout(`${mirror.base_url}/en/sites.aspx`, 3200),
  ]);

  const csvBody = csvRes && (csvRes.text.includes("*vpn_servers") || csvRes.text.includes("#HostName"))
    ? csvRes.text
    : "";
  const baseHtml = enRes && enRes.text.includes("vg_table_row_") ? enRes.text : "";
  if (!csvBody && !baseHtml) return null;

  let l2tpHtml = "";
  let ovpnHtml = "";
  if (baseHtml) {
    const asp = extractAspnetFields(baseHtml);
    if (asp.__VIEWSTATE) {
      [l2tpHtml, ovpnHtml] = await Promise.all([
        postProtocolFilter(mirror.portal_url, asp, enRes.cookie, "C_L2TP", 4200),
        postProtocolFilter(mirror.portal_url, asp, enRes.cookie, "C_OpenVPN", 4200),
      ]);
    }
  }
  const extraMirrors = sitesRes ? parseMirrorSitesHtml(sitesRes.text, "mirror-sites.aspx") : [];
  return { csvBody, baseHtml, l2tpHtml, ovpnHtml, extraMirrors };
}

async function fetchMirrorCsvOnly(mirror) {
  const csvRes = await fetchTextTimeout(`${mirror.base_url}/api/iphone/`, 4000);
  if (csvRes && (csvRes.text.includes("*vpn_servers") || csvRes.text.includes("#HostName"))) {
    return csvRes.text;
  }
  return "";
}

async function fetchHttpsCsvBodies() {
  const tasks = MIRROR_CSV_URLS.map((u) => fetchTextTimeout(u, 4500));
  const sdiseTask = fetchTextTimeout(SDISE_CSV_URL, 4000);
  const [csvResults, sdise] = await Promise.all([Promise.all(tasks), sdiseTask]);
  const bodies = [];
  for (const r of csvResults) {
    if (r && (r.text.includes("*vpn_servers") || r.text.includes("#HostName"))) {
      bodies.push(r.text);
    }
  }
  return { bodies, sdiseText: sdise ? sdise.text : "" };
}

async function fetchWaybackPortalHtml() {
  for (const cdxUrl of WAYBACK_PORTAL_CDX_URLS) {
    const cdx = await fetchTextTimeout(cdxUrl, 2600);
    if (!cdx) continue;
    try {
      const rows = JSON.parse(cdx.text);
      if (!Array.isArray(rows) || rows.length < 2) continue;
      const last = rows[rows.length - 1];
      if (!Array.isArray(last) || last.length < 3) continue;
      const snap = await fetchTextTimeout(`https://web.archive.org/web/${last[1]}id_/${last[2]}`, 3500);
      if (snap && snap.text.includes("vg_table_row_")) return snap.text;
    } catch {
      // try next CDX
    }
  }
  return "";
}

function summarizeCountries(servers) {
  const map = new Map();
  for (const s of servers) {
    if (!s.l2tp && !s.openvpn) continue;
    const code = s.country_short || "XX";
    let entry = map.get(code);
    if (!entry) {
      entry = {
        country_short: code,
        country_long: s.country_long || "Unknown",
        total_servers: 0,
        l2tp_count: 0,
        openvpn_udp_count: 0,
        openvpn_tcp_count: 0,
        max_speed_bps: 0,
        best_ping_ms: 9999,
      };
      map.set(code, entry);
    }
    entry.total_servers += 1;
    if (s.l2tp) entry.l2tp_count += 1;
    if (supportsOpenvpnUdp(s)) entry.openvpn_udp_count += 1;
    if (supportsOpenvpnTcp(s)) entry.openvpn_tcp_count += 1;
    if (s.speed_bps > entry.max_speed_bps) entry.max_speed_bps = s.speed_bps;
    if (s.ping_ms > 0 && s.ping_ms < entry.best_ping_ms) entry.best_ping_ms = s.ping_ms;
  }
  return Array.from(map.values()).sort(
    (a, b) =>
      b.total_servers - a.total_servers ||
      b.l2tp_count - a.l2tp_count ||
      a.country_short.localeCompare(b.country_short)
  );
}

function hasOvpnCert(s) {
  return Boolean((s && s.has_ovpn_cert) || (s && s.ovpn_b64 && s.ovpn_b64.length > 40));
}

function supportsOpenvpnUdp(s) {
  return Boolean(s.openvpn && (s.udp_port > 0 || (hasOvpnCert(s) && s.tcp_port === 0)));
}

function supportsOpenvpnTcp(s) {
  return Boolean(s.openvpn && (s.tcp_port > 0 || (hasOvpnCert(s) && s.udp_port === 0)));
}

function autoPriorityTier(s) {
  if (s.l2tp) return 0;
  if (supportsOpenvpnUdp(s)) return 1;
  if (supportsOpenvpnTcp(s) || s.openvpn) return 2;
  return 3;
}

function effectivePing(s) {
  const n = Number(s && s.ping_ms) || 0;
  return n === 0 || n >= 9999 ? 999999 : n;
}

/** Desktop `sort_servers` parity (`Recommended` / `Speed` / `Ping` / `Score`). */
function sortServersDesktop(list, sortKey, protoFilter) {
  return list.slice().sort((a, b) => {
    let tierDiff = 0;
    if (protoFilter === "auto" || protoFilter === "all" || !protoFilter) {
      tierDiff = autoPriorityTier(a) - autoPriorityTier(b);
    } else if (protoFilter === "openvpn") {
      tierDiff = Number(supportsOpenvpnUdp(b)) - Number(supportsOpenvpnUdp(a));
    }

    const pingA = effectivePing(a);
    const pingB = effectivePing(b);
    if (sortKey === "speed") {
      return (b.speed_bps - a.speed_bps) || tierDiff || (b.score - a.score);
    }
    if (sortKey === "ping") {
      return (pingA - pingB) || tierDiff || (b.speed_bps - a.speed_bps);
    }
    if (sortKey === "score") {
      return tierDiff || (b.score - a.score) || (b.speed_bps - a.speed_bps);
    }
    return tierDiff || (b.score - a.score) || (b.speed_bps - a.speed_bps) || (pingA - pingB);
  });
}

async function discoverPoolFresh(customMirrorRaw = "") {
  const logs = [];
  const serversByIp = new Map();
  const customMirrors = [];

  if (customMirrorRaw) {
    const norm = normalizeMirrorBaseUrl(customMirrorRaw);
    if (norm) {
      customMirrors.push({
        base_url: norm.base_url,
        portal_url: norm.portal_url,
        location: "Custom Mirror",
        source: "custom",
      });
      logs.push({ level: "info", msg: `Seeding extra Official Mirror Portal (merged with all others): ${norm.portal_url}` });
    } else {
      logs.push({ level: "warn", msg: "Ignored invalid or private custom mirror URL." });
    }
  }

  let primaryCsv = "";
  let baseHtml = "";
  let l2tpHtml = "";
  let ovpnHtml = "";
  let primaryMirrors = [];

  // Stage 1: Primary vpngate.net is always queried. Extra portals are seeds, never exclusive replacements.
  {
    logs.push({ level: "info", msg: "Querying primary vpngate.net (/api/iphone/ + /en/ + sites.aspx) ..." });
    const [csvRes, htmlRes, sitesRes] = await Promise.all([
      (async () => {
        for (const u of OFFICIAL_CSV_URLS) {
          const r = await fetchTextTimeout(u, 3200);
          if (r && (r.text.includes("*vpn_servers") || r.text.includes("#HostName"))) return r.text;
        }
        return "";
      })(),
      (async () => {
        for (const u of OFFICIAL_HTML_URLS) {
          const r = await fetchTextTimeout(u, 3200);
          if (r && r.text.includes("vg_table_row_")) return { url: u, ...r };
        }
        return null;
      })(),
      (async () => {
        for (const u of OFFICIAL_MIRROR_SITES_URLS) {
          const r = await fetchTextTimeout(u, 3000);
          if (r) {
            const p = parseMirrorSitesHtml(r.text, "sites.aspx");
            if (p.length > 0) return p;
          }
        }
        return [];
      })(),
    ]);

    primaryCsv = csvRes;
    primaryMirrors = sitesRes;

    if (htmlRes) {
      baseHtml = htmlRes.text;
      const asp = extractAspnetFields(baseHtml);
      if (asp.__VIEWSTATE) {
        [l2tpHtml, ovpnHtml] = await Promise.all([
          postProtocolFilter(htmlRes.url, asp, htmlRes.cookie, "C_L2TP", 4200),
          postProtocolFilter(htmlRes.url, asp, htmlRes.cookie, "C_OpenVPN", 4200),
        ]);
      }
    }

    if (primaryCsv) parseVpngateCsvInto(primaryCsv, serversByIp);
    if (ovpnHtml || l2tpHtml) {
      if (ovpnHtml) parseVpngateHtmlInto(ovpnHtml, serversByIp);
      if (l2tpHtml) parseVpngateHtmlInto(l2tpHtml, serversByIp);
    } else if (baseHtml) {
      parseVpngateHtmlInto(baseHtml, serversByIp);
    }
    if (serversByIp.size > 0) {
      logs.push({
        level: "ok",
        msg: `Primary vpngate.net online — parsed ${serversByIp.size} live relays (${primaryMirrors.length} mirrors).`,
      });
    }
  }

  let harvestedMirrors = mergeMirrorLists(customMirrors, primaryMirrors);

  // Stage 1b: apply EVERY Official VPNGate Mirror Portal CSV (do not list without merging).
  logs.push({ level: "info", msg: "Harvesting Official VPNGate Mirror Portals for direct pool merge ..." });
  const fbMirrors = await fetchFallbackMirrors();
  harvestedMirrors = mergeMirrorLists(harvestedMirrors, fbMirrors);

  const mirrorSlice = harvestedMirrors.slice(0, MAX_OFFICIAL_MIRROR_CSV);
  if (mirrorSlice.length > 0) {
    const csvBodies = await Promise.all(mirrorSlice.map((m) => fetchMirrorCsvOnly(m)));
    let portalHits = 0;
    for (let i = 0; i < csvBodies.length; i++) {
      if (!csvBodies[i]) continue;
      parseVpngateCsvInto(csvBodies[i], serversByIp);
      portalHits += 1;
      mirrorSlice[i].reachable = true;
    }
    if (portalHits > 0) {
      logs.push({
        level: "ok",
        msg: `Merged ${portalHits}/${mirrorSlice.length} Official Mirror /api/iphone/ feed(s) directly into the pool.`,
      });
    } else {
      logs.push({ level: "warn", msg: "Official Mirror CSVs were unreachable this round — continuing with other feeds." });
    }
  }

  // Full HTML+ASP.NET tables only when L2TP listing is still missing, or a custom portal was seeded.
  if (!l2tpHtml || customMirrors.length > 0) {
    const deep = (customMirrors.length > 0 ? customMirrors : harvestedMirrors).slice(0, 2);
    for (const m of deep) {
      const res = await fetchFromOfficialMirrorPortal(m);
      if (!res) continue;
      if (res.csvBody) parseVpngateCsvInto(res.csvBody, serversByIp);
      parseVpngateHtmlInto(res.ovpnHtml, serversByIp);
      parseVpngateHtmlInto(res.l2tpHtml, serversByIp);
      parseVpngateHtmlInto(res.baseHtml, serversByIp);
      if (res.l2tpHtml && !l2tpHtml) l2tpHtml = res.l2tpHtml;
      if (res.extraMirrors.length > 0) {
        harvestedMirrors = mergeMirrorLists(harvestedMirrors, res.extraMirrors);
      }
      logs.push({
        level: "ok",
        msg: `Official Mirror ${m.portal_url} (${m.location}) HTML tables merged.`,
      });
      if (l2tpHtml) break;
    }
  }

  // Stage 2: ALL HTTPS CSV mirrors + SDISE + Wayback L2TP metadata (desktop parity, always applied)
  logs.push({ level: "info", msg: "Merging every HTTPS CSV / SDISE / archive feed into the live pool ..." });
  const [{ bodies: httpsBodies, sdiseText }, wbHtml] = await Promise.all([
    fetchHttpsCsvBodies(),
    l2tpHtml ? Promise.resolve("") : fetchWaybackPortalHtml(),
  ]);
  let hits = 0;
  for (const body of httpsBodies) {
    parseVpngateCsvInto(body, serversByIp);
    hits += 1;
  }
  if (sdiseText) parseSdiseCsvInto(sdiseText, serversByIp);
  if (wbHtml) {
    const wbMap = new Map();
    parseVpngateHtmlInto(wbHtml, wbMap);
    for (const [ip, wbSrv] of wbMap.entries()) {
      if (wbSrv.l2tp && serversByIp.has(ip)) serversByIp.get(ip).l2tp = true;
    }
  }
  if (hits > 0) {
    logs.push({
      level: "ok",
      msg: `Merged ${hits} HTTPS CSV mirror feed(s)${sdiseText ? " + SDISE" : ""} (${serversByIp.size} total relays).`,
    });
  }

  // Locate shared SoftEther public client certificate template for HTML-only OpenVPN rows
  let donorOvpnB64 = "";
  for (const s of serversByIp.values()) {
    if (s.ovpn_b64 && s.ovpn_b64.length > 400) {
      donorOvpnB64 = s.ovpn_b64;
      break;
    }
  }

  const fullServers = [];
  for (const s of serversByIp.values()) {
    if (s.openvpn && !s.ovpn_b64 && donorOvpnB64 && (s.udp_port > 0 || s.tcp_port > 0)) {
      s.ovpn_b64 = donorOvpnB64;
    }
    if (!s.l2tp && !s.openvpn) continue;
    fullServers.push(s);
  }

  const rankedServers = sortServersDesktop(fullServers, "recommended", "auto");

  const ovpnByIp = new Map();
  const lightServers = rankedServers.map((s) => {
    if (s.ovpn_b64) ovpnByIp.set(s.ip, s.ovpn_b64);
    return {
      hostname: s.hostname,
      ip: s.ip,
      score: s.score,
      ping_ms: s.ping_ms,
      speed_bps: s.speed_bps,
      country_long: s.country_long,
      country_short: s.country_short,
      sessions: s.sessions,
      uptime_ms: s.uptime_ms,
      operator: s.operator,
      l2tp: s.l2tp,
      openvpn: s.openvpn,
      tcp_port: s.tcp_port,
      udp_port: s.udp_port,
      has_ovpn_cert: Boolean(s.ovpn_b64),
    };
  });

  const countries = summarizeCountries(lightServers);
  const l2tpCount = lightServers.filter((s) => s.l2tp).length;
  const ovpnCount = lightServers.filter((s) => s.openvpn).length;
  logs.push({
    level: "ok",
    msg: `Pool ready: ${lightServers.length} relays across ${countries.length} countries (${l2tpCount} L2TP/IPsec, ${ovpnCount} OpenVPN).`,
  });

  return {
    generated_at: Date.now(),
    donor_ovpn_b64: donorOvpnB64,
    ovpn_by_ip: Object.fromEntries(ovpnByIp),
    public_payload: {
      ok: true,
      version: APP_VERSION,
      generated_at: Date.now(),
      counts: {
        total: lightServers.length,
        l2tp: l2tpCount,
        openvpn: ovpnCount,
        countries: countries.length,
        mirrors: harvestedMirrors.length,
      },
      logs,
      countries,
      servers: lightServers,
      mirrors: harvestedMirrors,
    },
  };
}

async function getPoolSnapshot(ctx, { forceRefresh = false, customMirror = "" } = {}) {
  const now = Date.now();
  if (!forceRefresh && !customMirror) {
    const mem = globalThis.__VG_POOL_CACHE;
    if (mem && now - mem.generated_at < POOL_CACHE_TTL_MS && mem.public_payload.servers.length > 0) {
      return { ...mem, cached: "memory" };
    }
    if (typeof caches !== "undefined" && caches.default) {
      try {
        const hit = await caches.default.match(POOL_CACHE_KEY_URL);
        if (hit) {
          const parsed = await hit.json();
          if (parsed && parsed.public_payload && parsed.public_payload.servers.length > 0) {
            globalThis.__VG_POOL_CACHE = parsed;
            return { ...parsed, cached: "edge" };
          }
        }
      } catch {
        // proceed to fresh discovery
      }
    }
  }

  const fresh = await discoverPoolFresh(customMirror);
  if (!customMirror && fresh.public_payload.servers.length > 0) {
    globalThis.__VG_POOL_CACHE = fresh;
    if (typeof caches !== "undefined" && caches.default) {
      const cacheResp = new Response(JSON.stringify(fresh), {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": `public, max-age=${Math.floor(POOL_CACHE_TTL_MS / 1000)}`,
        },
      });
      const writePromise = caches.default.put(POOL_CACHE_KEY_URL, cacheResp).catch(() => {});
      if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(writePromise);
    }
  }
  return { ...fresh, cached: false };
}

const VERIFY_OK_TTL_MS = 180_000;
const VERIFY_FAIL_TTL_MS = DEAD_PENALTY_MS;
const OPENVPN_HARD_RESET_CLIENT_V2 = 0x38;
const OPENVPN_HARD_RESET_SERVER_V2 = 0x40;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function matchCountryServer(srv, query) {
  if (!query || query === "ALL") return true;
  const q = String(query).trim();
  if (!q || q.toLowerCase() === "all" || q.toLowerCase() === "any") return true;
  const up = q.toUpperCase();
  if (q.length === 2 && /^[A-Za-z]{2}$/.test(q)) {
    const iso = up === "UK" ? "GB" : up;
    return (srv.country_short || "").toUpperCase() === iso;
  }
  const low = q.toLowerCase();
  return (
    (srv.country_short || "").toUpperCase() === up ||
    (srv.country_long || "").toLowerCase().includes(low)
  );
}

function matchProtoServer(srv, proto) {
  if (!proto || proto === "auto" || proto === "all") return Boolean(srv.l2tp || srv.openvpn);
  if (proto === "l2tp") return Boolean(srv.l2tp);
  if (proto === "openvpn" || proto === "ovpn") return Boolean(srv.openvpn);
  if (proto === "udp" || proto === "openvpn-udp") return supportsOpenvpnUdp(srv);
  if (proto === "tcp" || proto === "openvpn-tcp") return supportsOpenvpnTcp(srv);
  return Boolean(srv.l2tp || srv.openvpn);
}

function verifyRecordTtl(rec) {
  return rec && rec.ok ? VERIFY_OK_TTL_MS : VERIFY_FAIL_TTL_MS;
}

function waitUntilOrIgnore(ctx, promise) {
  if (!promise) return;
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(promise);
}

function persistVerifyIp(ip, rec, ctx) {
  if (typeof caches === "undefined" || !caches.default) return;
  const ttl = verifyRecordTtl(rec);
  const resp = new Response(JSON.stringify(rec), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": `public, max-age=${Math.max(1, Math.floor(ttl / 1000))}`,
    },
  });
  waitUntilOrIgnore(ctx, caches.default.put(VERIFY_IP_CACHE_PREFIX + ip, resp).catch(() => {}));
}

function persistVerifyMemory(ctx) {
  if (typeof caches === "undefined" || !caches.default) return;
  const mem = globalThis.__VG_VERIFIED;
  if (!mem) return;
  const now = Date.now();
  const entries = {};
  for (const [ip, rec] of mem.entries()) {
    if (rec && now - rec.ts <= verifyRecordTtl(rec)) entries[ip] = rec;
  }
  const resp = new Response(JSON.stringify({ entries, saved_at: now }), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": `public, max-age=${Math.floor(DEAD_PENALTY_MS / 1000)}`,
    },
  });
  waitUntilOrIgnore(ctx, caches.default.put(VERIFY_MEM_CACHE_URL, resp).catch(() => {}));
}

function rememberVerify(ip, rec, ctx) {
  if (!globalThis.__VG_VERIFIED) globalThis.__VG_VERIFIED = new Map();
  const stored = { ...rec, ts: Date.now() };
  globalThis.__VG_VERIFIED.set(ip, stored);
  persistVerifyIp(ip, stored, ctx);
  persistVerifyMemory(ctx);
  return stored;
}

function recallVerifySync(ip) {
  const mem = globalThis.__VG_VERIFIED;
  if (!mem) return null;
  const rec = mem.get(ip);
  if (!rec) return null;
  if (Date.now() - rec.ts > verifyRecordTtl(rec)) {
    mem.delete(ip);
    return null;
  }
  return rec;
}

async function recallVerify(ip) {
  const hit = recallVerifySync(ip);
  if (hit) return hit;
  try {
    if (typeof caches === "undefined" || !caches.default) return null;
    const cached = await caches.default.match(VERIFY_IP_CACHE_PREFIX + ip);
    if (!cached) return null;
    const rec = await cached.json();
    if (!rec || Date.now() - rec.ts > verifyRecordTtl(rec)) return null;
    if (!globalThis.__VG_VERIFIED) globalThis.__VG_VERIFIED = new Map();
    globalThis.__VG_VERIFIED.set(ip, rec);
    return rec;
  } catch {
    return null;
  }
}

async function ensureVerifyMemory(ctx) {
  if (globalThis.__VG_VERIFIED) return;
  globalThis.__VG_VERIFIED = new Map();
  try {
    if (typeof caches === "undefined" || !caches.default) return;
    const hit = await caches.default.match(VERIFY_MEM_CACHE_URL);
    if (!hit) return;
    const parsed = await hit.json();
    const now = Date.now();
    for (const [ip, rec] of Object.entries(parsed.entries || {})) {
      if (rec && now - rec.ts <= verifyRecordTtl(rec)) globalThis.__VG_VERIFIED.set(ip, rec);
    }
  } catch {
    // isolate starts empty; per-IP cache still consulted on probe
  }
}

function decorateServersWithVerification(servers) {
  const now = Date.now();
  const mem = globalThis.__VG_VERIFIED;
  return (servers || []).map((s) => {
    const rec = mem ? mem.get(s.ip) : null;
    if (!rec) return { ...s, verify_state: "untested", dead_until: 0, unlocked: [], locked: [] };
    const ttl = verifyRecordTtl(rec);
    if (now - rec.ts > ttl) return { ...s, verify_state: "untested", dead_until: 0, unlocked: [], locked: [] };
    const avail = profileAvailability(s, rec);
    const unlocked = rec.unlocked || avail.unlocked;
    const locked = rec.locked || avail.locked;
    const adv = advertisedProfileKinds(s);
    const fullLive = adv.length > 0 && adv.every((k) => unlocked.includes(k));
    return {
      ...s,
      verify_state: rec.ok || unlocked.length ? (fullLive ? "live" : "partial") : "dead",
      verified_port: rec.port || 0,
      verified_rtt_ms: rec.rtt_ms || null,
      unlocked,
      locked,
      dead_until: rec.ok || unlocked.length ? 0 : rec.ts + DEAD_PENALTY_MS,
    };
  });
}

function buildOpenVpnHardReset() {
  const sid = crypto.getRandomValues(new Uint8Array(8));
  const pkt = new Uint8Array(16);
  pkt[1] = 14;
  pkt[2] = OPENVPN_HARD_RESET_CLIENT_V2;
  pkt.set(sid, 3);
  pkt[11] = 0;
  return { pkt, sid };
}

function bufferContainsSid(buf, sid) {
  if (!buf || buf.length < 8) return false;
  for (let i = 0; i <= buf.length - 8; i++) {
    let ok = true;
    for (let j = 0; j < 8; j++) {
      if (buf[i + j] !== sid[j]) {
        ok = false;
        break;
      }
    }
    if (ok) return true;
  }
  return false;
}

function parseOpenVpnHardResetReply(buf, clientSid) {
  if (!buf || buf.length < 16) return false;
  const opcode = buf[2];
  if ((opcode & 0xf8) !== OPENVPN_HARD_RESET_SERVER_V2) return false;
  return bufferContainsSid(buf, clientSid);
}

async function readSocketBytes(reader, minBytes, deadline) {
  const chunks = [];
  let total = 0;
  while (total < minBytes && Date.now() < deadline) {
    const waitMs = Math.max(1, deadline - Date.now());
    let timedOut = false;
    const next = await Promise.race([
      reader.read(),
      sleep(waitMs).then(() => {
        timedOut = true;
        return null;
      }),
    ]);
    if (timedOut || !next || next.done) break;
    if (next.value && next.value.byteLength) {
      const piece = next.value instanceof Uint8Array ? next.value : new Uint8Array(next.value);
      chunks.push(piece);
      total += piece.byteLength;
    }
  }
  if (!chunks.length) return null;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

async function probeOpenVpnHandshake(ip, port, timeoutMs = HANDSHAKE_TIMEOUT_MS) {
  const t0 = Date.now();
  const deadline = t0 + timeoutMs;
  let socket;
  let tcpOpen = false;
  try {
    socket = connect({ hostname: ip, port: Number(port) });
    await Promise.race([
      socket.opened,
      sleep(timeoutMs).then(() => {
        throw new Error("TCP connect timeout");
      }),
    ]);
    tcpOpen = true;
    const { pkt, sid } = buildOpenVpnHardReset();
    const writer = socket.writable.getWriter();
    await writer.write(pkt);
    const reader = socket.readable.getReader();
    const buf = await readSocketBytes(reader, 16, deadline);
    try { await writer.close(); } catch {}
    try { reader.releaseLock(); } catch {}
    try { await socket.close(); } catch {}
    const handshake = parseOpenVpnHardResetReply(buf, sid);
    return {
      reachable: Boolean(handshake),
      tcp_open: true,
      handshake,
      rtt_ms: Math.max(1, Date.now() - t0),
      engine: "openvpn-tcp-v2",
      error: handshake ? undefined : "no OpenVPN HARD_RESET_SERVER_V2",
    };
  } catch (err) {
    try { if (socket) await socket.close(); } catch {}
    return {
      reachable: false,
      tcp_open: tcpOpen,
      handshake: false,
      rtt_ms: tcpOpen ? Math.max(1, Date.now() - t0) : null,
      engine: "openvpn-tcp-v2",
      error: err && err.message ? String(err.message) : "OpenVPN handshake unavailable",
    };
  }
}

async function probeTcpEdge(ip, port, timeoutMs = HANDSHAKE_TIMEOUT_MS) {
  const handshake = await probeOpenVpnHandshake(ip, port, timeoutMs);
  if (handshake.handshake) return handshake;
  const t0 = Date.now();
  let socket;
  try {
    socket = connect({ hostname: ip, port: Number(port) });
    await Promise.race([
      socket.opened,
      sleep(timeoutMs).then(() => {
        throw new Error("TCP connect timeout");
      }),
    ]);
    try { await socket.close(); } catch {}
    return {
      reachable: true,
      handshake: false,
      rtt_ms: Math.max(1, Date.now() - t0),
      engine: "tcp-connect",
      error: handshake.error,
    };
  } catch (err) {
    try { if (socket) await socket.close(); } catch {}
    return {
      reachable: false,
      handshake: false,
      rtt_ms: null,
      engine: handshake.engine,
      error: handshake.error || (err && err.message ? String(err.message) : "TCP probe unavailable"),
    };
  }
}

function portsToProbe(server) {
  const ports = [];
  const advertised = Number(server.tcp_port) || 0;
  if (advertised > 0 && advertised <= 65535) ports.push(advertised);
  for (const p of [443, 995, 5555]) {
    if (!ports.includes(p)) ports.push(p);
  }
  return ports.slice(0, 1);
}

async function probeTcpConnect(ip, port, timeoutMs = HANDSHAKE_TIMEOUT_MS) {
  const t0 = Date.now();
  let socket;
  try {
    socket = connect({ hostname: ip, port: Number(port) });
    await Promise.race([
      socket.opened,
      sleep(timeoutMs).then(() => {
        throw new Error("TCP connect timeout");
      }),
    ]);
    try { await socket.close(); } catch {}
    return {
      reachable: true,
      rtt_ms: Math.max(1, Date.now() - t0),
      engine: "tcp-connect",
    };
  } catch (err) {
    try { if (socket) await socket.close(); } catch {}
    return {
      reachable: false,
      rtt_ms: null,
      engine: "tcp-connect",
      error: err && err.message ? String(err.message) : "TCP connect unavailable",
    };
  }
}

function advertisedProfileKinds(server) {
  const kinds = [];
  if (server && server.l2tp) kinds.push("l2tp");
  if (supportsOpenvpnUdp(server)) kinds.push("udp");
  if (supportsOpenvpnTcp(server)) kinds.push("tcp");
  return kinds;
}

function profileAvailability(server, result) {
  const unlocked = [];
  const locked = [];
  const tcpHs = Boolean(result && (result.tcp_handshake || (result.ok && result.engine === "openvpn-tcp-v2" && result.tcp_handshake !== false)));
  const hostUp = Boolean(result && (result.host_up || result.tcp_open || tcpHs));
  const advTcp = supportsOpenvpnTcp(server);
  const advUdp = supportsOpenvpnUdp(server);
  const advL2tp = Boolean(server && server.l2tp);

  if (advTcp) {
    if (tcpHs) unlocked.push("tcp");
    else locked.push({ kind: "tcp", reason: "no OpenVPN HARD_RESET" });
  }
  if (advUdp) {
    if (tcpHs) unlocked.push("udp");
    else if (!advTcp && hostUp) unlocked.push("udp");
    else locked.push({ kind: "udp", reason: "OpenVPN not live" });
  }
  if (advL2tp) {
    if (hostUp || tcpHs) unlocked.push("l2tp");
    else locked.push({ kind: "l2tp", reason: "host unreachable" });
  }
  return { unlocked, locked };
}

function unlockedProfiles(server, result) {
  return profileAvailability(server, result).unlocked;
}

async function verifyRelay(server) {
  const advTcp = supportsOpenvpnTcp(server);
  const advUdp = supportsOpenvpnUdp(server);
  const advL2tp = Boolean(server.l2tp);
  const ports = portsToProbe(server);
  const port0 = ports[0] || 443;

  let tcpHandshake = false;
  let hostUp = false;
  let port = port0;
  let rtt_ms = null;
  let engine = "openvpn-tcp-v2";
  let error = "no probe";

  if (advTcp) {
    for (const p of ports) {
      const r = await probeOpenVpnHandshake(server.ip, p, HANDSHAKE_TIMEOUT_MS);
      port = p;
      rtt_ms = r.rtt_ms;
      engine = r.engine;
      if (r.tcp_open) hostUp = true;
      if (r.handshake) {
        tcpHandshake = true;
        hostUp = true;
        error = undefined;
        break;
      }
      error = r.error || "handshake failed";
    }
  } else if (advUdp || advL2tp) {
    const r = await probeTcpConnect(server.ip, port0, HANDSHAKE_TIMEOUT_MS);
    hostUp = Boolean(r.reachable);
    rtt_ms = r.rtt_ms;
    engine = r.engine;
    error = hostUp ? undefined : (r.error || "TCP connect failed");
  }

  const avail = profileAvailability(server, {
    tcp_handshake: tcpHandshake,
    host_up: hostUp,
    tcp_open: hostUp,
    ok: tcpHandshake,
    engine,
    port,
  });

  return {
    ok: avail.unlocked.length > 0,
    port,
    rtt_ms,
    engine: tcpHandshake ? "openvpn-tcp-v2" : engine,
    tcp_handshake: tcpHandshake,
    host_up: hostUp,
    unlocked: avail.unlocked,
    locked: avail.locked,
    error: avail.unlocked.length ? undefined : (error || "no live protocol"),
  };
}

async function verifyRelayCached(server, { force = false, ctx = null } = {}) {
  if (!force) {
    const hit = await recallVerify(server.ip);
    if (hit) return hit;
  }
  const res = await verifyRelay(server);
  return rememberVerify(server.ip, res, ctx);
}

function sortVerifyCandidates(list, sortKey = "recommended", proto = "auto") {
  return sortServersDesktop(list, sortKey, proto);
}

async function recursiveVerifyRelays({
  servers,
  country = "ALL",
  proto = "auto",
  sort = "recommended",
  exclude = [],
  ip = "",
  force = false,
  ctx = null,
} = {}) {
  const excludeSet = new Set(exclude);
  let widened = false;
  let candidates;
  if (ip) {
    const found = servers.find((s) => s.ip === ip);
    candidates = found ? [found] : [];
  } else {
    candidates = sortVerifyCandidates(
      servers.filter((s) => matchCountryServer(s, country) && matchProtoServer(s, proto) && !excludeSet.has(s.ip)),
      sort,
      proto
    );
    if (candidates.length === 0 && country && country !== "ALL") {
      widened = true;
      candidates = sortVerifyCandidates(
        servers.filter((s) => matchProtoServer(s, proto) && !excludeSet.has(s.ip)),
        sort,
        proto
      );
    }
  }

  const maxAttempts = ip ? 1 : 12;
  const batchSize = ip ? 1 : 4;
  const slice = candidates.slice(0, maxAttempts);
  const attempts = [];
  let winner = null;

  for (let i = 0; i < slice.length && !winner; i += batchSize) {
    const batch = slice.slice(i, i + batchSize);
    const results = await Promise.all(batch.map((s) => verifyRelayCached(s, { force, ctx })));
    for (let j = 0; j < batch.length; j++) {
      const srv = batch[j];
      const res = results[j];
      attempts.push({
        ip: srv.ip,
        hostname: srv.hostname,
        country_short: srv.country_short,
        port: res.port,
        ok: Boolean(res.ok),
        rtt_ms: res.rtt_ms || null,
        error: res.ok ? undefined : res.error,
        engine: res.engine,
        unlocked: res.unlocked || unlockedProfiles(srv, res),
        locked: res.locked || profileAvailability(srv, res).locked,
        tcp_handshake: Boolean(res.tcp_handshake),
        host_up: Boolean(res.host_up),
        dead_until: res.ok ? 0 : (res.ts || Date.now()) + DEAD_PENALTY_MS,
        cached: Boolean(res.ts && Date.now() - res.ts > 250 && !force),
      });
      if (res.ok && !winner) winner = { server: srv, result: res };
    }
  }

  if (!winner) {
    return {
      verified: null,
      attempts,
      scanned: attempts.length,
      widened,
      remaining: Math.max(0, candidates.length - slice.length),
    };
  }

  const srv = winner.server;
  const res = winner.result;
  const avail = profileAvailability(srv, res);
  return {
    verified: {
      ip: srv.ip,
      hostname: srv.hostname,
      country_short: srv.country_short,
      country_long: srv.country_long,
      port: res.port,
      rtt_ms: res.rtt_ms,
      handshake: res.tcp_handshake ? "openvpn-tcp-v2" : (res.engine || "tcp-connect"),
      l2tp: srv.l2tp,
      openvpn: srv.openvpn,
      tcp_port: srv.tcp_port,
      udp_port: srv.udp_port,
      has_ovpn_cert: srv.has_ovpn_cert,
      score: srv.score,
      speed_bps: srv.speed_bps,
      ping_ms: srv.ping_ms,
      sessions: srv.sessions,
      operator: srv.operator,
      tcp_handshake: Boolean(res.tcp_handshake),
      host_up: Boolean(res.host_up),
      unlocked: res.unlocked || avail.unlocked,
      locked: res.locked || avail.locked,
    },
    attempts,
    scanned: attempts.length,
    widened,
    remaining: Math.max(0, candidates.length - slice.length),
  };
}

async function assertVerifiedForProfile(ctx, ip, kind) {
  const snap = await getPoolSnapshot(ctx, { forceRefresh: false });
  const found = (snap.public_payload.servers || []).find((s) => s.ip === ip);
  if (!found) {
    return { error: "Relay is not in the active VPN Gate pool.", status: 404 };
  }
  if (kind === "l2tp" && !found.l2tp) {
    return { error: "Relay does not advertise L2TP/IPsec.", status: 409, found };
  }
  if (kind === "tcp" && !found.openvpn) {
    return { error: "Relay does not advertise OpenVPN TCP.", status: 409, found };
  }
  if (kind === "udp" && !(found.openvpn && found.udp_port > 0)) {
    return { error: "Relay does not advertise OpenVPN UDP.", status: 409, found };
  }
  const verified = await verifyRelayCached(found, { ctx });
  const avail = profileAvailability(found, verified);
  if (!avail.unlocked.includes(kind)) {
    const lock = (avail.locked || []).find((l) => l.kind === kind);
    const why = lock && lock.reason
      ? lock.reason
      : (!verified || !verified.ok
        ? "relay did not answer a live path"
        : "this protocol stayed locked on the host");
    return {
      error: `Profile locked (${kind}): ${why}. Other protocols on this relay may still be available.`,
      status: 409,
      found,
      verified,
      unlocked: avail.unlocked,
      locked: avail.locked,
    };
  }
  return { found, verified, snap };
}

const PORTAL_CSS = String.raw`
:root {
  --bg: #070B14;
  --bg-glow: radial-gradient(1200px 500px at 50% -80px, rgba(56,189,248,0.08), transparent 70%);
  --card: #101827;
  --card-alt: #0C1320;
  --border: #1E2B42;
  --cyan: #38BDF8;
  --cyan-dim: rgba(56, 189, 248, 0.14);
  --emerald: #34D399;
  --emerald-dim: rgba(52, 211, 153, 0.14);
  --amber: #FBBF24;
  --amber-dim: rgba(251, 191, 36, 0.14);
  --coral: #FB7185;
  --coral-dim: rgba(251, 113, 133, 0.14);
  --console: #060A11;
  --text: #E8EEF7;
  --muted: #8FA3BB;
  --mono: ui-monospace, "SFMono-Regular", "Cascadia Code", Consolas, "Liberation Mono", Menlo, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
  --radius: 14px;
  --shadow: 0 10px 30px rgba(0,0,0,0.28);
}
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
html { color-scheme: dark; -webkit-text-size-adjust: 100%; }
html, body {
  margin: 0; padding: 0;
  background: var(--bg); color: var(--text);
  font-family: var(--sans); font-size: 15px; line-height: 1.45;
  min-height: 100dvh;
  background-image: var(--bg-glow);
}
::selection { background: rgba(56,189,248,0.32); color: #fff; }
body { touch-action: manipulation; }
a { color: var(--cyan); text-decoration: none; }
.app-shell {
  max-width: 880px; margin: 0 auto;
  padding: calc(10px + env(safe-area-inset-top, 0px)) 12px calc(92px + env(safe-area-inset-bottom, 0px));
}
.topbar {
  display: flex; align-items: center; justify-content: space-between; gap: 10px;
  background: rgba(16,24,39,0.92); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 10px 12px; margin-bottom: 12px;
  box-shadow: var(--shadow); backdrop-filter: blur(12px);
  position: sticky; top: env(safe-area-inset-top, 0px); z-index: 20;
}
.brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
.brand-icon {
  width: 38px; height: 38px; border-radius: 11px; flex-shrink: 0;
  background: linear-gradient(160deg, rgba(56,189,248,0.28), rgba(16,185,129,0.16));
  border: 1px solid rgba(56,189,248,0.42);
  display: grid; place-items: center; font-family: var(--mono); font-weight: 800; color: var(--cyan);
  letter-spacing: -0.04em;
}
.brand-title { font-weight: 700; font-size: 15.5px; letter-spacing: -0.02em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.brand-sub { font-size: 11px; color: var(--muted); font-family: var(--mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 52vw; }
@media (max-width: 420px) { .brand-sub { display: none; } }
.topbar-right { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.status-pill {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 6px 10px; border-radius: 999px; font-size: 11px; font-family: var(--mono); font-weight: 700;
  background: var(--emerald-dim); color: var(--emerald); border: 1px solid rgba(52,211,153,0.35);
  max-width: 42vw; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
@media (max-width: 420px) {
  .status-pill { max-width: 28vw; padding: 6px 8px; }
  #status-text { overflow: hidden; text-overflow: ellipsis; }
}
.status-pill.syncing { background: var(--cyan-dim); color: var(--cyan); border-color: rgba(56,189,248,0.35); }
.status-pill.error { background: var(--coral-dim); color: var(--coral); border-color: rgba(251,113,133,0.35); }
.dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; flex-shrink: 0; }
.status-pill.syncing .dot { animation: pulse-dot 1.1s ease-in-out infinite; }
@keyframes pulse-dot { 0%,100% { opacity: 1; transform: scale(1); } 50% { opacity: .35; transform: scale(.82); } }

.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 14px; margin-bottom: 12px;
}
.card-header {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  margin-bottom: 10px;
}
.card-title { font-weight: 700; font-size: 13.5px; letter-spacing: 0.01em; color: #F8FAFC; }
.card-subtitle { font-size: 12.5px; color: var(--muted); }
.card-subtitle code { font-family: var(--mono); font-size: 11.5px; color: var(--cyan); }

.grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
@media (max-width: 640px) { .grid-2 { grid-template-columns: 1fr; } }

label.field-label {
  display: block; font-size: 11px; font-weight: 700; color: var(--muted);
  text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px; font-family: var(--mono);
}
select, input[type="text"] {
  width: 100%; background: var(--console); color: var(--text);
  border: 1px solid var(--border); border-radius: 11px;
  padding: 11px 12px; font-size: 16px; font-family: var(--sans); outline: none;
  min-height: 44px;
}
select {
  appearance: none; -webkit-appearance: none;
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'><path fill='%238FA3BB' d='M1.2 1.2L6 6l4.8-4.8'/></svg>");
  background-repeat: no-repeat; background-position: right 12px center; padding-right: 34px;
}
select:focus, input[type="text"]:focus { border-color: var(--cyan); box-shadow: 0 0 0 3px rgba(56,189,248,0.15); }
button:focus-visible, a:focus-visible, select:focus-visible, input:focus-visible {
  outline: 2px solid var(--cyan); outline-offset: 2px;
}

.pill-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.pill-row.scroll {
  flex-wrap: nowrap; overflow-x: auto; -webkit-overflow-scrolling: touch;
  scrollbar-width: none; margin-left: -2px; padding: 2px;
}
.pill-row.scroll::-webkit-scrollbar { display: none; }
.pill-row.scroll .chip { flex-shrink: 0; }
.chip {
  background: var(--card-alt); color: var(--muted);
  border: 1px solid var(--border); border-radius: 999px;
  padding: 7px 12px; font-size: 12px; font-family: var(--mono); cursor: pointer;
  transition: border-color 0.14s ease, color 0.14s ease, background 0.14s ease;
  min-height: 34px; user-select: none;
}
.chip:hover { border-color: var(--cyan); color: var(--text); }
.chip.active {
  background: var(--cyan-dim); color: var(--cyan);
  border-color: rgba(56, 189, 248, 0.55); font-weight: 700;
}

.stepper {
  display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 6px;
  margin: 0 0 12px;
}
.step {
  background: var(--card-alt); border: 1px solid var(--border); border-radius: 10px;
  padding: 8px 6px; text-align: center; font-family: var(--mono); font-size: 10.5px; color: var(--muted);
}
.step b { display: block; font-size: 11.5px; color: var(--text); font-weight: 700; margin-bottom: 2px; }
.step.on { border-color: rgba(56,189,248,0.45); color: var(--cyan); }
.step.ok { border-color: rgba(52,211,153,0.45); color: var(--emerald); }
.step.bad { border-color: rgba(251,113,133,0.4); color: var(--coral); }
@media (max-width: 520px) {
  .step { font-size: 0; line-height: 0; padding: 9px 4px; }
  .step b { font-size: 11px; line-height: 1.2; margin: 0; }
}

.hero-relay {
  background: linear-gradient(180deg, rgba(56,189,248,0.08) 0%, rgba(16,24,39,0.96) 42%);
  border: 1px solid rgba(56,189,248,0.32); border-radius: var(--radius); padding: 15px; margin-bottom: 12px;
  box-shadow: var(--shadow);
}
.hero-relay.live { border-color: rgba(52,211,153,0.5); background: linear-gradient(180deg, rgba(52,211,153,0.1) 0%, rgba(16,24,39,0.96) 46%); }
.hero-relay.testing { border-color: rgba(56,189,248,0.55); }
.hero-relay.dead { border-color: rgba(251,113,133,0.4); }
.hero-relay.partial { border-color: rgba(251,191,36,0.5); }
.relay-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }
.relay-country { font-size: 17px; font-weight: 700; color: #F8FAFC; letter-spacing: -0.02em; }
.relay-host { font-family: var(--mono); font-size: 12px; color: var(--cyan); margin-top: 3px; word-break: break-all; }
.stats-strip {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px;
  margin: 12px 0; background: var(--console); border: 1px solid var(--border);
  border-radius: 11px; padding: 10px;
}
@media (max-width: 520px) { .stats-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.stat-box { font-family: var(--mono); }
.stat-k { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
.stat-v { font-size: 13.5px; font-weight: 700; color: #F8FAFC; margin-top: 2px; }

.badges { display: flex; flex-wrap: wrap; gap: 5px; justify-content: flex-end; }
.badge {
  display: inline-flex; align-items: center; padding: 3px 8px;
  border-radius: 6px; font-family: var(--mono); font-size: 10.5px; font-weight: 700;
}
.badge-l2tp { background: var(--emerald-dim); color: var(--emerald); border: 1px solid rgba(52,211,153,0.35); }
.badge-udp { background: var(--cyan-dim); color: var(--cyan); border: 1px solid rgba(56,189,248,0.35); }
.badge-tcp { background: var(--amber-dim); color: var(--amber); border: 1px solid rgba(251,191,36,0.35); }
.badge-err { background: var(--coral-dim); color: var(--coral); border: 1px solid rgba(251,113,133,0.35); }
.badge-live { background: var(--emerald-dim); color: var(--emerald); border: 1px solid rgba(52,211,153,0.45); }
.badge-partial { background: var(--amber-dim); color: var(--amber); border: 1px solid rgba(251,191,36,0.4); }
.badge-wait { background: var(--cyan-dim); color: var(--cyan); border: 1px solid rgba(56,189,248,0.35); }

.lock-note {
  display: flex; align-items: flex-start; gap: 8px;
  background: rgba(251,191,36,0.08); border: 1px solid rgba(251,191,36,0.28);
  color: #FDE68A; border-radius: 10px; padding: 9px 11px; font-size: 12.5px; margin-top: 10px;
}
.lock-note.ok {
  background: rgba(52,211,153,0.08); border-color: rgba(52,211,153,0.3); color: #A7F3D0;
}
.lock-note.partial {
  background: rgba(251,191,36,0.08); border-color: rgba(251,191,36,0.3); color: #FDE68A;
}

.progress-track {
  height: 6px; background: #0B1220; border-radius: 99px; overflow: hidden;
  border: 1px solid var(--border); margin: 10px 0 6px;
}
.progress-fill {
  height: 100%; width: 8%;
  background: linear-gradient(90deg, #0EA5E9, #34D399);
  animation: load-slide 1.4s ease-in-out infinite;
}
@keyframes load-slide { 0% { width: 8%; margin-left: 0; } 50% { width: 55%; } 100% { width: 8%; margin-left: 92%; } }
.progress-label { font-family: var(--mono); font-size: 11.5px; color: var(--cyan); }
#verify-elapsed, #hero-hop-elapsed {
  color: var(--amber); font-variant-numeric: tabular-nums; font-weight: 700;
}

.btn-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 7px;
  padding: 12px 14px; border-radius: 11px; font-size: 13.5px; font-weight: 700;
  border: 1px solid var(--border); background: var(--card-alt); color: var(--text);
  cursor: pointer; text-decoration: none; transition: border-color 0.14s ease, transform 0.12s ease;
  min-height: 44px;
}
.btn:hover { border-color: var(--cyan); color: #fff; }
.btn:active { transform: scale(0.98); }
.btn-primary {
  background: linear-gradient(135deg, #0EA5E9, #0369A1);
  border-color: #38BDF8; color: #fff; flex: 1 1 210px;
}
.btn-emerald {
  background: linear-gradient(135deg, #10B981, #047857);
  border-color: #34D399; color: #fff; flex: 1 1 210px;
}
.btn-sm { padding: 8px 11px; font-size: 12px; border-radius: 9px; font-family: var(--mono); min-height: 38px; }
.btn.disabled, .btn[disabled] { opacity: 0.42; pointer-events: none; }
.btn-lock { opacity: 0.55; cursor: not-allowed; pointer-events: none; }

.console-box {
  background: var(--console); border: 1px solid var(--border);
  border-radius: 12px; padding: 11px 12px; font-family: var(--mono);
  font-size: 11.5px; max-height: 240px; overflow-y: auto;
  scrollbar-color: #22304A transparent;
}
.log-line { margin: 2px 0; word-break: break-word; }
.log-ok { color: var(--emerald); }
.log-info { color: var(--cyan); }
.log-warn { color: var(--amber); }
.log-err { color: var(--coral); }

.relay-list { display: flex; flex-direction: column; gap: 9px; }
.relay-item {
  background: var(--card-alt); border: 1px solid var(--border);
  border-radius: 12px; padding: 12px;
}
.relay-item:hover { border-color: rgba(56,189,248,0.45); }
.relay-item.live { border-color: rgba(52,211,153,0.4); }
.relay-item.dead { opacity: 0.72; }
.relay-item.partial { border-color: rgba(251,191,36,0.35); }

.code-copy-label {
  margin-top: 10px; font-family: var(--mono); font-size: 11px; color: var(--muted); font-weight: 700;
}
.code-copy {
  display: block; width: 100%; max-width: 100%; box-sizing: border-box; text-align: left;
  background: var(--console); border: 1px solid var(--border); border-radius: 9px;
  padding: 10px 11px; font-family: var(--mono); font-size: 12px; color: var(--cyan);
  overflow-wrap: anywhere; word-break: break-word; white-space: pre-wrap; margin-top: 6px; cursor: pointer;
}
.code-copy:hover { border-color: var(--cyan); }
.inline-row { display: flex; gap: 8px; align-items: stretch; }
@media (max-width: 520px) { .inline-row { flex-direction: column; } }

details.adv {
  margin-top: 10px; border-top: 1px solid var(--border); padding-top: 8px;
}
details.adv > summary {
  cursor: pointer; color: var(--muted); font-family: var(--mono); font-size: 12px; font-weight: 700;
  list-style: none; padding: 6px 0;
}
details.adv > summary::-webkit-details-marker { display: none; }

.skeleton {
  background: linear-gradient(90deg, #101827 0%, #1a2740 50%, #101827 100%);
  background-size: 200% 100%; animation: shimmer 1.2s linear infinite;
  border-radius: 10px; height: 14px; margin: 8px 0;
}
@keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }

.tab-panel { display: none; }
.tab-panel.active { display: block; }

.bottom-nav {
  position: fixed; left: 0; right: 0; bottom: 0; z-index: 50;
  background: rgba(7, 11, 20, 0.94); backdrop-filter: blur(16px);
  border-top: 1px solid var(--border);
  padding: 7px 10px calc(8px + env(safe-area-inset-bottom, 0px));
}
.bottom-nav-inner {
  max-width: 880px; margin: 0 auto;
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px;
}
.nav-tab {
  background: transparent; border: 1px solid transparent; border-radius: 12px;
  color: var(--muted); padding: 8px 4px; cursor: pointer;
  display: flex; flex-direction: column; align-items: center; gap: 2px;
  font-family: var(--mono); font-size: 11px; font-weight: 700;
  min-height: 48px; user-select: none;
}
.nav-tab .nav-ico { font-size: 16px; line-height: 1; }
.nav-tab.active {
  color: var(--cyan); background: var(--cyan-dim);
  border-color: rgba(56, 189, 248, 0.35);
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; }
}
`;

const PORTAL_JS = String.raw`
(function () {
  "use strict";

  var verifyGen = 0;
  var state = {
    tab: "connect",
    servers: [],
    countries: [],
    mirrors: [],
    counts: { total: 0, l2tp: 0, openvpn: 0, countries: 0, mirrors: 0 },
    country: "ALL",
    proto: "auto",
    compat: "mobile3",
    dns: "1.1.1.1,1.0.0.1",
    connectSort: "recommended",
    selectedIndex: 0,
    relaySearch: "",
    relayProto: "all",
    relaySort: "recommended",
    relayLimit: 40,
    customMirror: "",
    device: detectDevice(),
    verifying: false,
    testingIp: "",
    verifyLabel: "",
    verified: null,
    attempts: [],
    step: "pool",
    elapsedTimer: 0,
    walkStartedAt: 0,
    hopStartedAt: 0,
    walkSlot: 0,
    walkTotal: 0
  };

  function detectDevice() {
    var ua = navigator.userAgent || "";
    var isIOS = /iPad|iPhone|iPod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
    var isAndroid = /Android/i.test(ua);
    var isMac = !isIOS && /Macintosh|Mac OS X/i.test(ua);
    var isWin = /Windows/i.test(ua);
    if (isIOS) return { id: "ios", label: "iOS / iPadOS · Safari native profile", apple: true, mobile: true };
    if (isAndroid) return { id: "android", label: "Android · OpenVPN Connect / for Android", apple: false, mobile: true };
    if (isMac) return { id: "macos", label: "macOS · Native L2TP + OpenVPN 2.6", apple: true, mobile: false };
    if (isWin) return { id: "windows", label: "Windows 11 · Patched .ovpn + native CLI", apple: false, mobile: false };
    return { id: "linux", label: "Linux · Patched .ovpn + native CLI", apple: false, mobile: false };
  }

  var INSTALL_SH = "https://raw.githubusercontent.com/warmaster726/vpngate-connect/main/install-vpngate.sh";
  var INSTALL_PS1 = "https://raw.githubusercontent.com/warmaster726/vpngate-connect/main/install-vpngate.ps1";
  var INSTALL_CMDS = {
    linux: {
      hint: "Linux / macOS · POSIX sh",
      install: "curl -fsSL " + INSTALL_SH + " | sh -s --",
      uninstall: "curl -fsSL " + INSTALL_SH + " | sh -s -- --uninstall"
    },
    windows: {
      hint: "Windows 11 · Administrator PowerShell",
      install: "irm " + INSTALL_PS1 + " | iex",
      uninstall: "irm " + INSTALL_PS1 + " -OutFile $env:TEMP\\install-vpngate.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\\install-vpngate.ps1 --uninstall"
    }
  };

  function defaultInstallOs() {
    return (state.device && state.device.id === "windows") ? "windows" : "linux";
  }

  function applyInstallOs(os) {
    if (os !== "windows") os = "linux";
    state.installOs = os;
    var cmds = INSTALL_CMDS[os];
    var hint = document.getElementById("install-os-hint");
    var installBtn = document.getElementById("install-copy");
    var uninstallBtn = document.getElementById("uninstall-copy");
    if (hint) hint.textContent = cmds.hint;
    if (installBtn) {
      installBtn.textContent = cmds.install;
      installBtn.setAttribute("data-cmd", cmds.install);
      installBtn.setAttribute("title", cmds.install);
    }
    if (uninstallBtn) {
      uninstallBtn.textContent = cmds.uninstall;
      uninstallBtn.setAttribute("data-cmd", cmds.uninstall);
      uninstallBtn.setAttribute("title", cmds.uninstall);
    }
    document.querySelectorAll("#install-os-pills .chip").forEach(function (c) {
      c.classList.toggle("active", c.getAttribute("data-install-os") === os);
    });
  }

  function copyDesktopCommand(btn, okMsg) {
    var cmd = "";
    if (btn) cmd = (btn.getAttribute("data-cmd") || btn.textContent || "").trim();
    if (!cmd) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(cmd).then(function () {
        appendLog("ok", okMsg);
      }).catch(function () {
        appendLog("warn", "Copy failed — select the command manually.");
      });
    } else {
      appendLog("info", cmd);
    }
  }

  function flagEmoji(cc) {
    if (!cc || cc.length !== 2 || cc === "XX") return "🌐";
    var up = cc.toUpperCase();
    var a = up.charCodeAt(0) - 65 + 0x1F1E6;
    var b = up.charCodeAt(1) - 65 + 0x1F1E6;
    if (a < 0x1F1E6 || a > 0x1F1FF || b < 0x1F1E6 || b > 0x1F1FF) return "🌐";
    return String.fromCodePoint(a, b);
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function fmtMbps(bps) {
    return ((Number(bps) || 0) / 1000000).toFixed(1) + " Mbps";
  }

  function fmtScore(n) {
    return (Number(n) || 0).toLocaleString();
  }

  function hostLabel(srv) {
    var h = String((srv && srv.hostname) || "");
    var ip = String((srv && srv.ip) || "");
    if (!h || h === ip) return ip;
    if (/\.opengw\.net$/i.test(h)) return h;
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) return h;
    return h + ".opengw.net";
  }

  function appendLog(level, msg) {
    var box = document.getElementById("console-log");
    if (!box) return;
    var ts = new Date().toLocaleTimeString([], { hour12: false });
    var tag = level === "ok" ? "[+]" : level === "warn" ? "[!]" : level === "err" ? "[-]" : "[*]";
    var cls = level === "ok" ? "log-ok" : level === "warn" ? "log-warn" : level === "err" ? "log-err" : "log-info";
    var div = document.createElement("div");
    div.className = "log-line " + cls;
    div.textContent = ts + " " + tag + " " + msg;
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
  }

  function setStatusPill(mode, text) {
    var pill = document.getElementById("status-pill");
    var txt = document.getElementById("status-text");
    if (!pill || !txt) return;
    pill.className = "status-pill" + (mode ? " " + mode : "");
    txt.textContent = text;
  }

  function setStepper(step) {
    state.step = step;
    var nodes = document.querySelectorAll("[data-step]");
    var order = ["pool", "probe", "handshake", "profile"];
    var idx = order.indexOf(step);
    for (var i = 0; i < nodes.length; i++) {
      var id = nodes[i].getAttribute("data-step");
      var n = order.indexOf(id);
      nodes[i].classList.remove("on", "ok", "bad");
      if (step === "fail" && n >= 1) nodes[i].classList.add("bad");
      else if (n < idx) nodes[i].classList.add("ok");
      else if (n === idx) nodes[i].classList.add("on");
    }
  }

  function matchCountry(srv, query) {
    if (!query || query === "ALL") return true;
    var q = query.trim();
    if (!q || q.toLowerCase() === "all" || q.toLowerCase() === "any") return true;
    var up = q.toUpperCase();
    if (q.length === 2 && /^[A-Za-z]{2}$/.test(q)) {
      var iso = up === "UK" ? "GB" : up;
      return (srv.country_short || "").toUpperCase() === iso;
    }
    var low = q.toLowerCase();
    return (
      (srv.country_short || "").toUpperCase() === up ||
      (srv.country_long || "").toLowerCase().indexOf(low) !== -1
    );
  }

  function matchRelayQuery(srv, query) {
    if (!query) return true;
    if (matchCountry(srv, query)) return true;
    var low = query.trim().toLowerCase();
    return (
      (srv.hostname || "").toLowerCase().indexOf(low) !== -1 ||
      (srv.ip || "").indexOf(low) !== -1
    );
  }

  function supportsUdp(srv) {
    return Boolean(srv.openvpn && (srv.udp_port > 0 || (srv.has_ovpn_cert && srv.tcp_port === 0)));
  }

  function supportsTcp(srv) {
    return Boolean(srv.openvpn && (srv.tcp_port > 0 || (srv.has_ovpn_cert && srv.udp_port === 0)));
  }

  function matchProto(srv, proto) {
    if (!proto || proto === "auto" || proto === "all") return srv.l2tp || srv.openvpn;
    if (proto === "l2tp") return Boolean(srv.l2tp);
    if (proto === "openvpn" || proto === "ovpn") return Boolean(srv.openvpn);
    if (proto === "udp") return supportsUdp(srv);
    if (proto === "tcp") return supportsTcp(srv);
    return true;
  }

  function sortList(list, sortKey, protoFilter) {
    return list.slice().sort(function (a, b) {
      var tierA = a.l2tp ? 0 : (supportsUdp(a) ? 1 : 2);
      var tierB = b.l2tp ? 0 : (supportsUdp(b) ? 1 : 2);
      var tierDiff = 0;
      if (protoFilter === "auto" || protoFilter === "all" || !protoFilter) tierDiff = tierA - tierB;
      else if (protoFilter === "openvpn") tierDiff = (supportsUdp(b) ? 1 : 0) - (supportsUdp(a) ? 1 : 0);
      var pingA = (!a.ping_ms || a.ping_ms >= 9999) ? 999999 : a.ping_ms;
      var pingB = (!b.ping_ms || b.ping_ms >= 9999) ? 999999 : b.ping_ms;
      if (sortKey === "speed") return (b.speed_bps - a.speed_bps) || tierDiff || (b.score - a.score);
      if (sortKey === "ping") return (pingA - pingB) || tierDiff || (b.speed_bps - a.speed_bps);
      if (sortKey === "score") return tierDiff || (b.score - a.score) || (b.speed_bps - a.speed_bps);
      return tierDiff || (b.score - a.score) || (b.speed_bps - a.speed_bps) || (pingA - pingB);
    });
  }

  function buildMobileconfigHref(srv) {
    var cc = (srv.country_short || "XX").toUpperCase();
    var q = new URLSearchParams({
      ip: srv.ip,
      cc: cc,
      country: srv.country_long || "Relay",
      dns: state.dns
    });
    return "/profiles/vpngate-" + encodeURIComponent(cc) + "-" + encodeURIComponent(srv.ip) + ".mobileconfig?" + q.toString();
  }

  function buildOvpnHref(srv, transport) {
    var cc = (srv.country_short || "XX").toUpperCase();
    var q = new URLSearchParams({
      ip: srv.ip,
      cc: cc,
      proto: transport,
      compat: state.compat,
      dns: state.dns,
      udp: String(srv.udp_port || 0),
      tcp: String(srv.tcp_port || 0)
    });
    return "/profiles/vpngate-" + encodeURIComponent(cc) + "-" + encodeURIComponent(srv.ip) + "-" + transport + ".ovpn?" + q.toString();
  }

  function ovpnFileName(srv, transport) {
    var cc = (srv.country_short || "XX").toUpperCase();
    return "vpngate-" + cc + "-" + srv.ip + "-" + transport + ".ovpn";
  }

  function ovpnExportLabel(transport, compact) {
    var t = String(transport || "").toUpperCase();
    if (state.device && state.device.mobile) {
      return compact ? ("OpenVPN " + t) : ("Open in OpenVPN Connect · " + t);
    }
    return compact ? ("OVPN " + t) : ("Export OpenVPN " + t + " (.ovpn)");
  }

  function openVpnConnectLink(absHttps) {
    if (state.device && state.device.id === "android") {
      return "intent://import-profile/" + absHttps +
        "#Intent;scheme=openvpn;package=net.openvpn.openvpn;S.browser_fallback_url=" +
        encodeURIComponent("https://play.google.com/store/apps/details?id=net.openvpn.openvpn") +
        ";end";
    }
    return "openvpn://import-profile/" + absHttps;
  }

  function downloadOvpnBlob(buf, fileName) {
    var file;
    try {
      file = new File([buf], fileName, { type: "application/x-openvpn-profile" });
    } catch (e1) {
      file = new Blob([buf], { type: "application/x-openvpn-profile" });
    }
    if (typeof File !== "undefined" && file instanceof File && navigator.canShare && navigator.canShare({ files: [file] })) {
      return navigator.share({ files: [file], title: fileName, text: "Open in OpenVPN Connect" }).then(function () {
        appendLog("ok", "Shared " + fileName + " — choose OpenVPN Connect.");
      }).catch(function (shareErr) {
        if (shareErr && shareErr.name === "AbortError") {
          appendLog("info", "Export cancelled.");
          return;
        }
        throw shareErr;
      });
    }
    var url = URL.createObjectURL(file);
    var a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    a.rel = "noopener";
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    setTimeout(function () {
      URL.revokeObjectURL(url);
      if (a.parentNode) a.parentNode.removeChild(a);
    }, 2500);
    appendLog("ok", "Downloaded " + fileName + ". Open it with OpenVPN Connect.");
    return Promise.resolve();
  }

  async function exportOvpnFile(href, fileName) {
    if (!href || !fileName) return;
    var abs = new URL(href, window.location.href).href;
    var mobile = Boolean(state.device && state.device.mobile);
    if (mobile) {
      appendLog("info", "Opening OpenVPN Connect to import " + fileName + "…");
      var handed = false;
      function onHide() {
        if (document.hidden) handed = true;
      }
      document.addEventListener("visibilitychange", onHide);
      try {
        window.location.href = openVpnConnectLink(abs);
      } catch (e0) {}
      window.setTimeout(function () {
        document.removeEventListener("visibilitychange", onHide);
        if (handed || document.hidden) {
          appendLog("ok", "Handed " + fileName + " to OpenVPN Connect.");
          return;
        }
        appendLog("warn", "OpenVPN Connect did not open. Install it, then try again — falling back to share/download.");
        fetch(href, { headers: { Accept: "application/x-openvpn-profile" } }).then(function (resp) {
          if (!resp.ok) throw new Error("Export refused (" + resp.status + ")");
          return resp.arrayBuffer();
        }).then(function (buf) {
          return downloadOvpnBlob(buf, fileName);
        }).catch(function (e) {
          appendLog("err", "Export failed: " + (e && e.message ? e.message : String(e)));
        });
      }, 1600);
      return;
    }
    appendLog("info", "Exporting " + fileName + "…");
    try {
      var resp = await fetch(href, { headers: { Accept: "application/x-openvpn-profile" } });
      if (!resp.ok) {
        var err = "Export refused (" + resp.status + ")";
        try {
          var j = await resp.json();
          if (j && j.error) err = j.error;
        } catch (e0) {}
        appendLog("err", err);
        return;
      }
      var buf = await resp.arrayBuffer();
      await downloadOvpnBlob(buf, fileName);
    } catch (e) {
      appendLog("err", "Export failed: " + (e && e.message ? e.message : String(e)));
    }
  }

  var DEAD_PENALTY_MS = 15 * 60 * 1000;

  function prunePenalties() {
    var now = Date.now();
    for (var i = 0; i < state.servers.length; i++) {
      var s = state.servers[i];
      if (s.verify_state === "dead" && s.dead_until && now >= s.dead_until) {
        s.verify_state = "untested";
        s.dead_until = 0;
      }
    }
  }

  function protoNeeds(proto) {
    if (!proto || proto === "auto" || proto === "all") return null;
    if (proto === "l2tp") return ["l2tp"];
    if (proto === "udp") return ["udp"];
    if (proto === "tcp") return ["tcp"];
    if (proto === "openvpn" || proto === "ovpn") return ["udp", "tcp"];
    return null;
  }

  function satisfiesProto(unlocked, proto) {
    if (!unlocked || !unlocked.length) return false;
    var need = protoNeeds(proto);
    if (!need) return true;
    for (var i = 0; i < need.length; i++) {
      if (unlocked.indexOf(need[i]) !== -1) return true;
    }
    return false;
  }

  function lockReason(kind, srv) {
    var locked = [];
    if (state.verified && srv && state.verified.ip === srv.ip && Array.isArray(state.verified.locked)) {
      locked = state.verified.locked;
    } else if (srv && Array.isArray(srv.locked)) {
      locked = srv.locked;
    }
    for (var i = 0; i < locked.length; i++) {
      if (locked[i] && locked[i].kind === kind && locked[i].reason) return locked[i].reason;
    }
    return "";
  }

  function lockedLabel(kind, fallback, srv) {
    var why = lockReason(kind, srv);
    return why ? (fallback + " — " + why) : fallback;
  }

  function isPenalized(srv) {
    if (!srv || srv.verify_state !== "dead") return false;
    if (srv.dead_until && Date.now() >= srv.dead_until) {
      srv.verify_state = "untested";
      srv.dead_until = 0;
      return false;
    }
    return true;
  }

  function fmtPenaltyLeft(srv) {
    var left = Math.max(0, (srv.dead_until || 0) - Date.now());
    if (left <= 0) return "";
    var mins = Math.ceil(left / 60000);
    return mins <= 1 ? "<1m" : mins + "m";
  }

  function fmtElapsed(ms) {
    var s = Math.max(0, ms) / 1000;
    if (s < 60) return s.toFixed(1) + "s";
    var m = Math.floor(s / 60);
    var r = Math.floor(s % 60);
    return m + "m " + (r < 10 ? "0" : "") + r + "s";
  }

  function paintElapsed() {
    var hop = fmtElapsed(Date.now() - (state.hopStartedAt || Date.now()));
    var total = fmtElapsed(Date.now() - (state.walkStartedAt || Date.now()));
    var hopEl = document.getElementById("verify-elapsed");
    var hopStat = document.getElementById("hero-hop-elapsed");
    var txt = document.getElementById("status-text");
    if (hopEl) hopEl.textContent = hop + " this hop · " + total + " total";
    if (hopStat) hopStat.textContent = hop;
    if (txt && state.verifying && state.walkTotal) {
      txt.textContent = state.walkSlot + "/" + state.walkTotal + " · " + hop;
    }
  }

  function startElapsedTicker() {
    if (state.elapsedTimer) clearInterval(state.elapsedTimer);
    paintElapsed();
    state.elapsedTimer = setInterval(paintElapsed, 100);
  }

  function stopElapsedTicker() {
    if (state.elapsedTimer) {
      clearInterval(state.elapsedTimer);
      state.elapsedTimer = 0;
    }
  }

  function renderBadges(srv) {
    var out = "";
    if (state.verifying && state.testingIp === srv.ip) {
      out += '<span class="badge badge-wait">TESTING</span>';
    } else if (srv.verify_state === "live") {
      out += '<span class="badge badge-live">LIVE HANDSHAKE</span>';
    } else if (srv.verify_state === "partial") {
      out += '<span class="badge badge-partial">PARTIAL</span>';
    } else if (isPenalized(srv)) {
      var left = fmtPenaltyLeft(srv);
      out += '<span class="badge badge-err">DEAD' + (left ? " · " + left : "") + "</span>";
    } else if (srv.verify_state === "dead") {
      out += '<span class="badge badge-err">DEAD</span>';
    }
    if (srv.l2tp) out += '<span class="badge badge-l2tp">L2TP PSK=vpn</span>';
    if (srv.openvpn && srv.udp_port > 0) {
      out += '<span class="badge badge-udp">OVPN UDP:' + srv.udp_port + "</span>";
    }
    if (srv.openvpn && srv.tcp_port > 0) {
      out += '<span class="badge badge-tcp">OVPN TCP:' + srv.tcp_port + "</span>";
    }
    return out;
  }

  function renderCountryControls() {
    var sel = document.getElementById("connect-country");
    var pills = document.getElementById("quick-country-pills");
    if (!sel || !pills) return;

    var opts = '<option value="ALL">🌐 All Countries (' + state.counts.total + " relays)</option>";
    for (var i = 0; i < state.countries.length; i++) {
      var c = state.countries[i];
      var selected = state.country === c.country_short ? " selected" : "";
      opts += '<option value="' + esc(c.country_short) + '"' + selected + ">" +
        flagEmoji(c.country_short) + " " + esc(c.country_long) + " (" + esc(c.country_short) + ") — " +
        c.total_servers + " (" + c.l2tp_count + " L2TP)</option>";
    }
    sel.innerHTML = opts;
    if (state.country && state.country !== "ALL") sel.value = state.country;

    var topCodes = ["ALL"];
    var hasCurrent = state.country === "ALL";
    for (var j = 0; j < Math.min(6, state.countries.length); j++) {
      topCodes.push(state.countries[j].country_short);
      if (state.countries[j].country_short === state.country) hasCurrent = true;
    }
    if (!hasCurrent && state.country) topCodes.splice(1, 0, state.country);
    var pillHtml = "";
    for (var k = 0; k < topCodes.length; k++) {
      var code = topCodes[k];
      var act = state.country === code ? " active" : "";
      var lbl = code === "ALL" ? "🌐 ALL" : (flagEmoji(code) + " " + code);
      pillHtml += '<button type="button" class="chip' + act + '" data-cc="' + esc(code) + '">' + lbl + "</button>";
    }
    pills.innerHTML = pillHtml;
  }

  function getConnectCandidates() {
    prunePenalties();
    var filtered = state.servers.filter(function (s) {
      return matchCountry(s, state.country) && matchProto(s, state.proto);
    });
    return sortList(filtered, state.connectSort, state.proto);
  }

  function applyVerifiedToServers(verified, attempts) {
    var dead = {};
    var liveIp = verified && verified.ip;
    if (Array.isArray(attempts)) {
      for (var i = 0; i < attempts.length; i++) {
        if (!attempts[i].ok) dead[attempts[i].ip] = true;
      }
    }
    for (var j = 0; j < state.servers.length; j++) {
      var s = state.servers[j];
      if (liveIp && s.ip === liveIp) {
        s.verify_state = "live";
        s.verified_port = verified.port;
        s.verified_rtt_ms = verified.rtt_ms;
      } else if (dead[s.ip]) {
        s.verify_state = "dead";
      }
    }
  }

  function unlockedFor(srv) {
    if (state.verified && srv && state.verified.ip === srv.ip && Array.isArray(state.verified.unlocked)) {
      return state.verified.unlocked;
    }
    return (srv && srv.unlocked) || [];
  }

  function renderConnectHero() {
    var wrap = document.getElementById("hero-container");
    if (!wrap) return;
    var candidates = getConnectCandidates();
    if (candidates.length === 0) {
      wrap.innerHTML = '<div class="card"><div class="card-title">No matching relays</div>' +
        '<div class="card-subtitle">Switch country to ALL, protocol to Auto, or refresh the pool.</div></div>';
      return;
    }

    if (state.selectedIndex < 0) state.selectedIndex = 0;
    if (state.selectedIndex >= candidates.length) state.selectedIndex = candidates.length - 1;
    var srv = candidates[state.selectedIndex];

    var unlocked = unlockedFor(srv);
    var canL2tp = unlocked.indexOf("l2tp") !== -1;
    var canUdp = unlocked.indexOf("udp") !== -1;
    var canTcp = unlocked.indexOf("tcp") !== -1;
    var anyLive = canL2tp || canUdp || canTcp;
    var someLocked = (srv.l2tp && !canL2tp)
      || (srv.openvpn && srv.udp_port > 0 && !canUdp)
      || (srv.openvpn && srv.tcp_port > 0 && !canTcp);
    var heroClass = "hero-relay";
    if (state.verifying) heroClass += " testing";
    else if (anyLive && !someLocked) heroClass += " live";
    else if (anyLive) heroClass += " partial";
    else if (srv.verify_state === "dead") heroClass += " dead";

    var handshakeMs;
    if (state.verifying) handshakeMs = '<span id="hero-hop-elapsed">0.0s</span>';
    else if (state.verified && state.verified.ip === srv.ip && state.verified.rtt_ms)
      handshakeMs = state.verified.rtt_ms + " ms";
    else if (srv.verified_rtt_ms) handshakeMs = srv.verified_rtt_ms + " ms";
    else handshakeMs = "—";

    var lockHtml;
    if (state.verifying) {
      lockHtml = '<div class="progress-track"><div class="progress-fill"></div></div>' +
        '<div class="progress-label">' + esc(state.verifyLabel || "Testing live path") +
        ' · <span id="verify-elapsed">0.0s this hop · 0.0s total</span></div>';
    } else if (anyLive && !someLocked) {
      lockHtml = '<div class="lock-note ok">Live path on ' +
        esc(srv.ip) + (state.verified && state.verified.port ? (":" + esc(state.verified.port)) : "") +
        " · advertised profiles unlocked for this relay only.</div>";
    } else if (anyLive) {
      var openBits = [];
      if (canL2tp) openBits.push("Apple L2TP");
      if (canUdp) openBits.push("OpenVPN UDP");
      if (canTcp) openBits.push("OpenVPN TCP");
      var shutBits = [];
      if (srv.l2tp && !canL2tp) shutBits.push("Apple L2TP" + (lockReason("l2tp", srv) ? " (" + lockReason("l2tp", srv) + ")" : ""));
      if (srv.openvpn && srv.udp_port > 0 && !canUdp) shutBits.push("OpenVPN UDP" + (lockReason("udp", srv) ? " (" + lockReason("udp", srv) + ")" : ""));
      if (srv.openvpn && srv.tcp_port > 0 && !canTcp) shutBits.push("OpenVPN TCP" + (lockReason("tcp", srv) ? " (" + lockReason("tcp", srv) + ")" : ""));
      lockHtml = '<div class="lock-note partial">Unlocked: ' + esc(openBits.join(", ") || "none") +
        ". Locked: " + esc(shutBits.join(", ") || "none") + ".</div>";
    } else {
      lockHtml = '<div class="lock-note">Profiles stay locked until this edge proves a live path. Dead listings are never exported.</div>';
    }

    var profileBtns = "";
    if (canL2tp) {
      profileBtns += '<a class="btn btn-emerald" href="' + esc(buildMobileconfigHref(srv)) + '"> Install Apple L2TP (.mobileconfig)</a>';
    } else if (srv.l2tp) {
      profileBtns += '<span class="btn btn-lock">' + esc(lockedLabel("l2tp", "Locked · Apple L2TP", srv)) + "</span>";
    }
    if (canUdp) {
      profileBtns += '<button type="button" class="btn btn-primary" data-ovpn-href="' + esc(buildOvpnHref(srv, "udp")) +
        '" data-ovpn-name="' + esc(ovpnFileName(srv, "udp")) + '">' + esc(ovpnExportLabel("udp", false)) + "</button>";
    } else if (srv.openvpn && srv.udp_port > 0) {
      profileBtns += '<span class="btn btn-lock">' + esc(lockedLabel("udp", "Locked · OpenVPN UDP", srv)) + "</span>";
    }
    if (canTcp) {
      profileBtns += '<button type="button" class="btn" data-ovpn-href="' + esc(buildOvpnHref(srv, "tcp")) +
        '" data-ovpn-name="' + esc(ovpnFileName(srv, "tcp")) + '">' + esc(ovpnExportLabel("tcp", false)) + "</button>";
    } else if (srv.openvpn && srv.tcp_port > 0) {
      profileBtns += '<span class="btn btn-lock">' + esc(lockedLabel("tcp", "Locked · OpenVPN TCP", srv)) + "</span>";
    }
    if (!profileBtns) {
      profileBtns = '<span class="btn btn-lock">No profile until a live handshake exists</span>';
    }

    var html = '<div class="' + heroClass + '">' +
      '<div class="relay-top">' +
        "<div>" +
          '<div class="relay-country">' + flagEmoji(srv.country_short) + " " + esc(srv.country_long) +
            ' <span style="color:var(--muted);font-size:12px;font-family:var(--mono)">[' + (state.selectedIndex + 1) + "/" + candidates.length + "]</span></div>" +
          '<div class="relay-host">' + esc(hostLabel(srv)) + " · " + esc(srv.ip) + "</div>" +
        "</div>" +
        '<div class="badges">' + renderBadges(srv) + "</div>" +
      "</div>" +
      '<div class="stats-strip">' +
        '<div class="stat-box"><div class="stat-k">Throughput</div><div class="stat-v">' + fmtMbps(srv.speed_bps) + "</div></div>" +
        '<div class="stat-box"><div class="stat-k">Listed ping</div><div class="stat-v">' + (srv.ping_ms >= 9999 ? "—" : srv.ping_ms + " ms") + "</div></div>" +
        '<div class="stat-box"><div class="stat-k">Handshake</div><div class="stat-v">' + handshakeMs + "</div></div>" +
        '<div class="stat-box"><div class="stat-k">Sessions</div><div class="stat-v">' + srv.sessions + "</div></div>" +
      "</div>" +
      lockHtml +
      '<div class="btn-row">' + profileBtns + "</div>" +
      '<div class="btn-row" style="margin-top:8px">' +
        '<button type="button" class="btn btn-sm" id="btn-verify-now">' + (state.verifying ? "Verifying…" : "Verify live path") + "</button>" +
        '<button type="button" class="btn btn-sm" id="btn-next-live">Find next live relay</button>' +
        '<button type="button" class="btn btn-sm" id="btn-skip-listed">Skip listed candidate</button>' +
      "</div>" +
    "</div>";

    wrap.innerHTML = html;
    var vBtn = document.getElementById("btn-verify-now");
    if (vBtn) {
      vBtn.disabled = state.verifying;
      vBtn.addEventListener("click", function () {
        runRecursiveVerify({ ip: srv.ip, walk: true, wrap: true, forceIp: srv.ip });
      });
    }
    var nBtn = document.getElementById("btn-next-live");
    if (nBtn) {
      nBtn.disabled = state.verifying;
      nBtn.addEventListener("click", function () {
        runRecursiveVerify({
          fromIndex: state.selectedIndex + 1,
          wrap: true,
          skipIp: srv.ip
        });
      });
    }
    var sBtn = document.getElementById("btn-skip-listed");
    if (sBtn) {
      sBtn.disabled = state.verifying;
      sBtn.addEventListener("click", function () {
        if (state.verifying) return;
        state.verified = null;
        state.selectedIndex = (state.selectedIndex + 1) % candidates.length;
        renderConnectHero();
      });
    }
  }

  function renderRelaysTab() {
    var listEl = document.getElementById("relays-list");
    var metaEl = document.getElementById("relays-meta");
    if (!listEl || !metaEl) return;
    prunePenalties();

    var filtered = state.servers.filter(function (s) {
      return matchRelayQuery(s, state.relaySearch) && matchProto(s, state.relayProto);
    });
    var sorted = sortList(filtered, state.relaySort, state.relayProto);
    var liveN = sorted.filter(function (s) { return s.verify_state === "live" || s.verify_state === "partial"; }).length;
    metaEl.textContent = "Showing " + Math.min(sorted.length, state.relayLimit) + " of " + sorted.length +
      " matching relays · " + liveN + " handshake-verified";

    if (sorted.length === 0) {
      listEl.innerHTML = '<div class="card-subtitle">No relays matched your filter criteria.</div>';
      return;
    }

    var slice = sorted.slice(0, state.relayLimit);
    var out = "";
    for (var i = 0; i < slice.length; i++) {
      var s = slice[i];
      var unlocked = unlockedFor(s);
      var canL2tp = unlocked.indexOf("l2tp") !== -1;
      var canUdp = unlocked.indexOf("udp") !== -1;
      var canTcp = unlocked.indexOf("tcp") !== -1;
      var itemCls = "relay-item";
      if (s.verify_state === "live") itemCls += " live";
      if (s.verify_state === "partial") itemCls += " partial";
      if (s.verify_state === "dead") itemCls += " dead";
      out += '<div class="' + itemCls + '">' +
        '<div class="relay-top">' +
          "<div>" +
            '<div style="font-weight:700;color:#F8FAFC">' + flagEmoji(s.country_short) + " " + esc(s.country_long) +
              ' <span style="color:var(--muted);font-family:var(--mono);font-size:11.5px">(' + esc(s.country_short) + ")</span></div>" +
            '<div class="relay-host">' + esc(hostLabel(s)) + " · " + esc(s.ip) + " · " + fmtMbps(s.speed_bps) + " · " +
              (s.ping_ms >= 9999 ? "—" : s.ping_ms + " ms") + " · Score " + fmtScore(s.score) + "</div>" +
          "</div>" +
          '<div class="badges">' + renderBadges(s) + "</div>" +
        "</div>" +
        '<div class="btn-row" style="margin-top:9px">' +
          (canL2tp
            ? '<a class="btn btn-sm" style="border-color:rgba(52,211,153,0.5);color:var(--emerald)" href="' + esc(buildMobileconfigHref(s)) + '">.mobileconfig</a>'
            : (s.l2tp ? '<span class="btn btn-sm btn-lock">' + esc(lockedLabel("l2tp", "L2TP locked", s)) + "</span>" : "")) +
          (canUdp
            ? '<button type="button" class="btn btn-sm" style="border-color:rgba(56,189,248,0.5);color:var(--cyan)" data-ovpn-href="' + esc(buildOvpnHref(s, "udp")) +
              '" data-ovpn-name="' + esc(ovpnFileName(s, "udp")) + '">' + esc(ovpnExportLabel("udp", true)) + "</button>"
            : (s.openvpn && s.udp_port > 0 ? '<span class="btn btn-sm btn-lock">' + esc(lockedLabel("udp", "UDP locked", s)) + "</span>" : "")) +
          (canTcp
            ? '<button type="button" class="btn btn-sm" data-ovpn-href="' + esc(buildOvpnHref(s, "tcp")) +
              '" data-ovpn-name="' + esc(ovpnFileName(s, "tcp")) + '">' + esc(ovpnExportLabel("tcp", true)) + "</button>"
            : (s.openvpn && s.tcp_port > 0 ? '<span class="btn btn-sm btn-lock">' + esc(lockedLabel("tcp", "TCP locked", s)) + "</span>" : "")) +
          '<button type="button" class="btn btn-sm" data-verify-ip="' + esc(s.ip) + '">Verify</button>' +
        "</div>" +
      "</div>";
    }
    if (sorted.length > state.relayLimit) {
      out += '<button type="button" class="btn" id="btn-more-relays">Show more relays (' + (sorted.length - state.relayLimit) + " remaining)</button>";
    }
    listEl.innerHTML = out;
    var moreBtn = document.getElementById("btn-more-relays");
    if (moreBtn) {
      moreBtn.addEventListener("click", function () {
        state.relayLimit += 40;
        renderRelaysTab();
      });
    }
  }

  function renderMirrorsTab() {
    var listEl = document.getElementById("mirrors-list");
    var cntEl = document.getElementById("mirrors-count");
    if (!listEl || !cntEl) return;
    cntEl.textContent = state.mirrors.length + " portal(s) auto-merged into the live pool";
    if (state.mirrors.length === 0) {
      listEl.innerHTML = '<div class="card-subtitle">Directory empty this round — HTTPS CSV feeds were still merged.</div>';
      return;
    }
    var out = "";
    for (var i = 0; i < state.mirrors.length; i++) {
      var m = state.mirrors[i];
      var statusBadge = "";
      if (m.reachable === true) {
        statusBadge = '<span class="badge badge-live">ONLINE · ' + (m.rtt_ms || 1) + " ms · " + (m.servers_count || 0) + " relays</span>";
      } else if (m.reachable === false) {
        statusBadge = '<span class="badge badge-err">OFFLINE</span>';
      } else {
        statusBadge = '<span class="badge badge-udp">' + esc(m.source || "directory") + "</span>";
      }
      out += '<div class="relay-item">' +
        '<div class="relay-top">' +
          "<div>" +
            '<div style="font-weight:700;color:#F8FAFC">🪞 ' + esc(m.location || "Official Mirror") + "</div>" +
            '<div class="relay-host">' + esc(m.portal_url) + "</div>" +
          "</div>" +
          '<div class="badges">' + statusBadge + "</div>" +
        "</div>" +
        '<div class="btn-row" style="margin-top:8px">' +
          '<span class="badge badge-live">AUTO-MERGED</span>' +
          '<a class="btn btn-sm" href="' + esc(m.portal_url) + '" target="_blank" rel="noopener noreferrer">Open portal</a>' +
        "</div>" +
      "</div>";
    }
    listEl.innerHTML = out;
  }

  async function loadPool(forceRefresh, customMirror) {
    setStatusPill("syncing", "SYNCING");
    setStepper("pool");
    appendLog("info", forceRefresh ? "Refreshing live VPN Gate relay pool from Cloudflare edge…" : "Loading VPN Gate relay pool…");
    try {
      var qs = new URLSearchParams();
      if (forceRefresh) qs.set("refresh", "1");
      if (customMirror) qs.set("mirror", customMirror);
      var resp = await fetch("/api/servers?" + qs.toString());
      var data = await resp.json();
      if (!data || !data.ok) throw new Error((data && data.error) || "Upstream discovery error");

      state.servers = data.servers || [];
      state.countries = data.countries || [];
      state.mirrors = data.mirrors || [];
      state.counts = data.counts || state.counts;
      state.selectedIndex = 0;
      state.verified = null;
      state.attempts = [];

      if (Array.isArray(data.logs)) {
        for (var i = 0; i < data.logs.length; i++) {
          appendLog(data.logs[i].level || "info", data.logs[i].msg);
        }
      }
      setStatusPill("", "POOL · " + state.counts.total + " listed");
      renderCountryControls();
      renderConnectHero();
      renderRelaysTab();
      renderMirrorsTab();
      await runRecursiveVerify({});
    } catch (err) {
      setStatusPill("error", "DISCOVERY ISSUE");
      setStepper("fail");
      appendLog("err", "Failed to load relay pool: " + (err && err.message ? err.message : String(err)));
    }
  }

  function markServerState(ip, rec) {
    for (var j = 0; j < state.servers.length; j++) {
      if (state.servers[j].ip !== ip) continue;
      var unlocked = (rec && rec.unlocked) || [];
      var locked = (rec && rec.locked) || [];
      if (rec && (rec.ok || unlocked.length)) {
        var advN = 0;
        if (state.servers[j].l2tp) advN += 1;
        if (state.servers[j].openvpn && state.servers[j].udp_port > 0) advN += 1;
        if (state.servers[j].openvpn && state.servers[j].tcp_port > 0) advN += 1;
        state.servers[j].unlocked = unlocked;
        state.servers[j].locked = locked;
        state.servers[j].verify_state = (advN > 0 && unlocked.length >= advN) ? "live" : "partial";
        state.servers[j].verified_port = rec.port;
        state.servers[j].verified_rtt_ms = rec.rtt_ms;
        state.servers[j].dead_until = 0;
      } else {
        state.servers[j].verify_state = "dead";
        state.servers[j].unlocked = [];
        state.servers[j].locked = locked;
        state.servers[j].dead_until = (rec && rec.dead_until) ? rec.dead_until : (Date.now() + DEAD_PENALTY_MS);
      }
      break;
    }
  }

  async function handshakeOne(srv, force) {
    var qs = new URLSearchParams();
    qs.set("ip", srv.ip);
    if (force) qs.set("force", "1");
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, ${VERIFY_CLIENT_ABORT_MS});
    try {
      var resp = await fetch("/api/verify?" + qs.toString(), { signal: ctrl.signal });
      return await resp.json();
    } finally {
      clearTimeout(timer);
    }
  }

  function indexOfCandidate(candidates, ip) {
    for (var i = 0; i < candidates.length; i++) {
      if (candidates[i].ip === ip) return i;
    }
    return -1;
  }

  function revealIpInConnectList(ip) {
    var candidates = getConnectCandidates();
    var idx = indexOfCandidate(candidates, ip);
    if (idx >= 0) return { candidates: candidates, index: idx };
    var raw = null;
    for (var j = 0; j < state.servers.length; j++) {
      if (state.servers[j].ip === ip) { raw = state.servers[j]; break; }
    }
    if (!raw) return { candidates: candidates, index: -1 };
    var changed = false;
    if (!matchCountry(raw, state.country)) { state.country = "ALL"; changed = true; }
    if (!matchProto(raw, state.proto)) { state.proto = "auto"; changed = true; }
    if (changed) renderCountryControls();
    candidates = getConnectCandidates();
    return { candidates: candidates, index: indexOfCandidate(candidates, ip) };
  }

  async function runRecursiveVerify(opts) {
    opts = opts || {};
    var gen = ++verifyGen;
    var WALK_CAP = 24;
    var revealed = opts.ip ? revealIpInConnectList(opts.ip) : { candidates: getConnectCandidates(), index: -1 };
    var candidates = revealed.candidates;
    if (candidates.length === 0) {
      state.verifying = false;
      state.testingIp = "";
      state.verified = null;
      stopElapsedTicker();
      setStepper("fail");
      setStatusPill("error", "NO RELAYS");
      renderConnectHero();
      return;
    }

    var single = Boolean(opts.ip && !opts.walk && typeof opts.fromIndex !== "number");
    var start = 0;
    if (typeof opts.fromIndex === "number") {
      start = opts.fromIndex;
      if (start < 0) start = 0;
      if (start >= candidates.length) start = 0;
    } else if (opts.ip) {
      start = revealed.index >= 0 ? revealed.index : 0;
    } else {
      start = state.selectedIndex || 0;
      if (start < 0 || start >= candidates.length) start = 0;
    }

    var order = [];
    if (single) {
      order.push(start);
    } else {
      for (var k = start; k < candidates.length; k++) order.push(k);
      if (opts.wrap) {
        for (var k2 = 0; k2 < start; k2++) order.push(k2);
      }
    }

    state.verifying = true;
    state.verified = null;
    state.attempts = [];
    state.selectedIndex = start;
    state.testingIp = candidates[start] ? candidates[start].ip : "";
    state.walkSlot = start + 1;
    state.walkTotal = candidates.length;
    state.walkStartedAt = Date.now();
    state.hopStartedAt = Date.now();
    state.verifyLabel = "Testing [" + (start + 1) + "/" + candidates.length + "]";
    setStepper("probe");
    setStatusPill("syncing", (start + 1) + "/" + candidates.length);
    renderConnectHero();
    startElapsedTicker();
    appendLog("info", single
      ? ("Handshake on sort slot [" + (start + 1) + "/" + candidates.length + "]")
      : ("Walking sort order from [" + (start + 1) + "/" + candidates.length + "] — up to 17.6s per hop (80% of desktop 22s)."));

    var winner = null;
    var probed = 0;
    var lastIdx = start;
    for (var oi = 0; oi < order.length; oi++) {
      if (gen !== verifyGen) return;
      var i = order[oi];
      var cand = candidates[i];
      var forceThis = Boolean(opts.force) || (opts.forceIp && cand.ip === opts.forceIp);
      if (opts.skipIp && cand.ip === opts.skipIp) continue;
      if (!forceThis && isPenalized(cand)) continue;
      if (!forceThis && cand.verify_state && cand.verify_state !== "untested" && Array.isArray(cand.unlocked)
        && !satisfiesProto(cand.unlocked, state.proto)) {
        continue;
      }
      if (probed >= WALK_CAP) {
        appendLog("warn", "Walk cap (" + WALK_CAP + ") reached — remaining slots keep their listed numbers.");
        break;
      }

      lastIdx = i;
      state.selectedIndex = i;
      state.testingIp = cand.ip;
      state.walkSlot = i + 1;
      state.walkTotal = candidates.length;
      state.hopStartedAt = Date.now();
      state.verifyLabel = "Testing [" + (i + 1) + "/" + candidates.length + "] " + cand.ip;
      setStatusPill("syncing", (i + 1) + "/" + candidates.length);
      setStepper("handshake");
      renderConnectHero();
      paintElapsed();
      appendLog("info", "Handshake [" + (i + 1) + "/" + candidates.length + "] " + hostLabel(cand) + " · " + cand.ip);

      var data;
      try {
        data = await handshakeOne(cand, forceThis);
      } catch (e) {
        if (gen !== verifyGen) return;
        markServerState(cand.ip, { ok: false });
        state.attempts.push({ ip: cand.ip, ok: false, error: e && e.message ? e.message : String(e) });
        appendLog("err", "Probe error [" + (i + 1) + "/" + candidates.length + "] " + cand.ip + " · " + (e && e.message ? e.message : String(e)) + " — 15m penalty, advancing.");
        probed += 1;
        continue;
      }
      if (gen !== verifyGen) return;
      probed += 1;

      var attempt = data && Array.isArray(data.attempts) && data.attempts[0] ? data.attempts[0] : null;
      if (attempt) state.attempts.push(attempt);
      var unlocked = [];
      var locked = [];
      if (data && data.verified && Array.isArray(data.verified.unlocked)) unlocked = data.verified.unlocked;
      else if (attempt && Array.isArray(attempt.unlocked)) unlocked = attempt.unlocked;
      if (data && data.verified && Array.isArray(data.verified.locked)) locked = data.verified.locked;
      else if (attempt && Array.isArray(attempt.locked)) locked = attempt.locked;
      var rec = {
        ok: unlocked.length > 0,
        port: data && data.verified ? data.verified.port : (attempt && attempt.port),
        rtt_ms: data && data.verified ? data.verified.rtt_ms : (attempt && attempt.rtt_ms),
        unlocked: unlocked,
        locked: locked,
        dead_until: attempt && attempt.dead_until
      };
      if (satisfiesProto(unlocked, state.proto)) {
        markServerState(cand.ip, rec);
        appendLog("ok", "LIVE [" + (i + 1) + "/" + candidates.length + "] " + cand.ip +
          " · " + unlocked.join("+").toUpperCase() +
          (rec.rtt_ms ? (" · " + rec.rtt_ms + " ms") : "") +
          " · " + fmtElapsed(Date.now() - state.hopStartedAt));
        winner = { index: i, payload: (data && data.verified) || { ip: cand.ip, unlocked: unlocked, locked: locked, port: rec.port, rtt_ms: rec.rtt_ms } };
        break;
      }
      if (unlocked.length) {
        markServerState(cand.ip, rec);
        appendLog("warn", "Partial [" + (i + 1) + "/" + candidates.length + "] " + cand.ip +
          " · unlocked " + unlocked.join("+").toUpperCase() +
          " · selected protocol still locked · next slot");
        continue;
      }
      markServerState(cand.ip, { ok: false, dead_until: rec.dead_until, locked: locked });
      appendLog("warn", "Dead [" + (i + 1) + "/" + candidates.length + "] " + cand.ip +
        (attempt && attempt.error ? " · " + attempt.error : "") +
        " · 15m pool penalty · next slot");
    }

    if (gen !== verifyGen) return;
    state.verifying = false;
    state.testingIp = "";
    stopElapsedTicker();
    if (winner) {
      state.selectedIndex = winner.index;
      state.verified = winner.payload;
      setStepper("profile");
      setStatusPill("", "LIVE · #" + (winner.index + 1));
      appendLog("ok", "Profiles updated for sort slot [" + (winner.index + 1) + "/" + candidates.length + "] " + winner.payload.ip +
        " · unlocked " + ((winner.payload.unlocked || []).join("+").toUpperCase() || "none") +
        " after " + probed + " handshake(s) in " + fmtElapsed(Date.now() - state.walkStartedAt) + ".");
    } else {
      state.selectedIndex = lastIdx;
      state.verified = null;
      setStepper("fail");
      setStatusPill("error", "NO LIVE PATH");
      appendLog("err", "No live handshake along the current sort order. Dead relays stay numbered and sit out 15 minutes. Profiles remain withheld.");
    }
    renderConnectHero();
    renderRelaysTab();
  }

  async function runProbeMirrors() {
    var btn = document.getElementById("btn-probe-mirrors");
    if (btn) btn.disabled = true;
    appendLog("info", "Probing Official VPNGate Mirror Sites from Cloudflare edge…");
    try {
      var resp = await fetch("/api/mirrors?probe=1");
      var data = await resp.json();
      if (data && Array.isArray(data.mirrors)) {
        state.mirrors = data.mirrors;
        renderMirrorsTab();
        appendLog("ok", "Mirror probe complete: " + (data.online_count || 0) + "/" + data.mirrors.length + " Official Mirror(s) online.");
      }
    } catch (e) {
      appendLog("err", "Mirror probe failed: " + (e && e.message ? e.message : String(e)));
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function runDoctor() {
    var box = document.getElementById("doctor-results");
    var btn = document.getElementById("btn-run-doctor");
    if (btn) btn.disabled = true;
    if (box) box.innerHTML = '<div class="card-subtitle">Running edge, DoH, handshake & profile self-tests…</div>';
    appendLog("info", "Running edge & handshake diagnostics (/api/doctor)…");
    try {
      var resp = await fetch("/api/doctor");
      var data = await resp.json();
      var checks = (data && data.checks) || [];
      var html = "";
      for (var i = 0; i < checks.length; i++) {
        var c = checks[i];
        var bCls = c.status === "READY" ? "badge-live" : (c.status === "WARN" ? "badge-tcp" : "badge-err");
        html += '<div class="relay-item">' +
          '<div class="relay-top">' +
            '<div style="font-weight:700;color:#F8FAFC">' + esc(c.name) + "</div>" +
            '<span class="badge ' + bCls + '">' + esc(c.status) + "</span>" +
          "</div>" +
          '<div class="card-subtitle" style="margin-top:4px;font-family:var(--mono)">' + esc(c.detail) + "</div>" +
        "</div>";
      }
      if (box) box.innerHTML = html;
      appendLog("ok", "Doctor diagnostics completed (" + checks.length + " checks evaluated).");
    } catch (e) {
      if (box) box.innerHTML = '<div class="card-subtitle" style="color:var(--coral)">Diagnostics failed: ' + esc(e.message || e) + "</div>";
      appendLog("err", "Doctor check error: " + (e && e.message ? e.message : String(e)));
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function switchTab(tabId) {
    state.tab = tabId;
    var panels = document.querySelectorAll(".tab-panel");
    for (var i = 0; i < panels.length; i++) {
      panels[i].classList.toggle("active", panels[i].id === "tab-" + tabId);
    }
    var navs = document.querySelectorAll(".nav-tab");
    for (var j = 0; j < navs.length; j++) {
      navs[j].classList.toggle("active", navs[j].getAttribute("data-tab") === tabId);
    }
    if (tabId === "doctor") {
      var box = document.getElementById("doctor-results");
      if (box && !box.hasChildNodes()) runDoctor();
    }
  }

  function onFilterChange() {
    state.selectedIndex = 0;
    state.verified = null;
    renderCountryControls();
    renderConnectHero();
    runRecursiveVerify({});
  }

  function onSortChange() {
    state.selectedIndex = 0;
    renderCountryControls();
    renderConnectHero();
    renderRelaysTab();
    var top = getConnectCandidates()[0];
    if (top && state.verified && state.verified.ip === top.ip) return;
    runRecursiveVerify({});
  }

  document.addEventListener("DOMContentLoaded", function () {
    if (!state.device.mobile) {
      state.compat = "ovpn26";
      var compatSel = document.getElementById("connect-compat");
      if (compatSel) compatSel.value = "ovpn26";
    }
    var devEl = document.getElementById("detected-device");
    if (devEl) devEl.textContent = state.device.label;

    document.querySelectorAll(".nav-tab").forEach(function (btn) {
      btn.addEventListener("click", function () { switchTab(btn.getAttribute("data-tab")); });
    });

    document.getElementById("btn-refresh").addEventListener("click", function () {
      loadPool(true, state.customMirror);
    });

    document.getElementById("connect-country").addEventListener("change", function (e) {
      state.country = e.target.value;
      onFilterChange();
    });

    document.getElementById("quick-country-pills").addEventListener("click", function (e) {
      var btn = e.target.closest("[data-cc]");
      if (!btn) return;
      state.country = btn.getAttribute("data-cc");
      onFilterChange();
    });

    document.getElementById("connect-proto").addEventListener("change", function (e) {
      state.proto = e.target.value;
      onFilterChange();
    });

    document.getElementById("connect-sort-pills").addEventListener("click", function (e) {
      var btn = e.target.closest("[data-csort]");
      if (!btn) return;
      state.connectSort = btn.getAttribute("data-csort");
      document.querySelectorAll("#connect-sort-pills .chip").forEach(function (c) {
        c.classList.toggle("active", c === btn);
      });
      onSortChange();
    });

    document.getElementById("connect-compat").addEventListener("change", function (e) {
      state.compat = e.target.value;
      renderConnectHero();
      renderRelaysTab();
    });

    document.getElementById("connect-dns").addEventListener("change", function (e) {
      state.dns = e.target.value;
      renderConnectHero();
      renderRelaysTab();
    });

    document.getElementById("relay-search").addEventListener("input", function (e) {
      state.relaySearch = e.target.value;
      state.relayLimit = 40;
      renderRelaysTab();
    });

    document.getElementById("relay-proto-pills").addEventListener("click", function (e) {
      var btn = e.target.closest("[data-rproto]");
      if (!btn) return;
      state.relayProto = btn.getAttribute("data-rproto");
      document.querySelectorAll("#relay-proto-pills .chip").forEach(function (c) {
        c.classList.toggle("active", c === btn);
      });
      renderRelaysTab();
    });

    document.getElementById("relay-sort-pills").addEventListener("click", function (e) {
      var btn = e.target.closest("[data-rsort]");
      if (!btn) return;
      state.relaySort = btn.getAttribute("data-rsort");
      document.querySelectorAll("#relay-sort-pills .chip").forEach(function (c) {
        c.classList.toggle("active", c === btn);
      });
      renderRelaysTab();
    });

    document.getElementById("btn-probe-mirrors").addEventListener("click", runProbeMirrors);
    document.getElementById("btn-apply-mirror").addEventListener("click", function () {
      var val = document.getElementById("custom-mirror-input").value.trim();
      state.customMirror = val;
      loadPool(true, val);
      switchTab("connect");
    });

    document.getElementById("btn-run-doctor").addEventListener("click", runDoctor);
    document.getElementById("btn-clear-log").addEventListener("click", function () {
      document.getElementById("console-log").innerHTML = "";
      appendLog("info", "Console log cleared.");
    });

    applyInstallOs(defaultInstallOs());
    var osPills = document.getElementById("install-os-pills");
    if (osPills) {
      osPills.addEventListener("click", function (e) {
        var btn = e.target.closest("[data-install-os]");
        if (!btn) return;
        applyInstallOs(btn.getAttribute("data-install-os"));
      });
    }
    var copyBtn = document.getElementById("install-copy");
    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        copyDesktopCommand(copyBtn, "Desktop install command copied.");
      });
    }
    var uninstallBtn = document.getElementById("uninstall-copy");
    if (uninstallBtn) {
      uninstallBtn.addEventListener("click", function () {
        copyDesktopCommand(uninstallBtn, "Desktop uninstall command copied.");
      });
    }

    document.body.addEventListener("click", function (e) {
      var ovBtn = e.target.closest("[data-ovpn-href]");
      if (ovBtn) {
        e.preventDefault();
        exportOvpnFile(ovBtn.getAttribute("data-ovpn-href"), ovBtn.getAttribute("data-ovpn-name"));
        return;
      }
      var vBtn = e.target.closest("[data-verify-ip]");
      if (vBtn) {
        var vip = vBtn.getAttribute("data-verify-ip");
        switchTab("connect");
        runRecursiveVerify({ ip: vip, walk: true, wrap: true, forceIp: vip });
        return;
      }
      var mirBtn = e.target.closest("[data-use-mirror]");
      if (mirBtn) {
        var mUrl = mirBtn.getAttribute("data-use-mirror");
        state.customMirror = mUrl;
        document.getElementById("custom-mirror-input").value = mUrl;
        loadPool(true, mUrl);
        switchTab("connect");
      }
    });

    appendLog("info", "Initialized VPN Gate Web Profile Console · Device: " + state.device.label);
    appendLog("info", "Profiles stay locked until a live OpenVPN TCP handshake is proven.");
    loadPool(false, "");
  });
})();
`;

function renderPortalHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="theme-color" content="#070B14">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="color-scheme" content="dark">
  <title>VPN Gate Connect — Live Profile Console</title>
  <link rel="manifest" href="/manifest.webmanifest">
  <link rel="icon" type="image/svg+xml" href="/icon.svg">
  <style>${PORTAL_CSS}</style>
</head>
<body>
  <div class="app-shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-icon">VG</div>
        <div>
          <div class="brand-title">VPN Gate Connect</div>
          <div class="brand-sub" id="detected-device">Cloudflare Edge Profile Console</div>
        </div>
      </div>
      <div class="topbar-right">
        <div class="status-pill syncing" id="status-pill" aria-live="polite">
          <span class="dot"></span>
          <span id="status-text">BOOTING</span>
        </div>
        <button type="button" class="btn btn-sm" id="btn-refresh" title="Refresh live server pool">Sync</button>
      </div>
    </header>

    <section class="tab-panel active" id="tab-connect">
      <div class="stepper" aria-label="Connection pipeline">
        <div class="step on" data-step="pool"><b>1. Pool</b>Discover</div>
        <div class="step" data-step="probe"><b>2. Probe</b>TCP path</div>
        <div class="step" data-step="handshake"><b>3. Handshake</b>OpenVPN</div>
        <div class="step" data-step="profile"><b>4. Profile</b>Unlock</div>
      </div>

      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Target &amp; protocol</div>
            <div class="card-subtitle">Profiles are issued only after a live OpenVPN handshake succeeds on the chosen relay.</div>
          </div>
        </div>
        <div class="grid-2">
          <div>
            <label class="field-label" for="connect-country">Target country</label>
            <select id="connect-country"><option value="ALL">Loading countries...</option></select>
          </div>
          <div>
            <label class="field-label" for="connect-proto">Protocol priority</label>
            <select id="connect-proto">
              <option value="auto">Auto (L2TP → OVPN UDP → OVPN TCP)</option>
              <option value="l2tp">Apple native L2TP/IPsec</option>
              <option value="openvpn">OpenVPN (UDP + TCP)</option>
              <option value="udp">OpenVPN UDP</option>
              <option value="tcp">OpenVPN TCP</option>
            </select>
          </div>
        </div>
        <div class="pill-row scroll" id="quick-country-pills"></div>
        <label class="field-label" style="margin-top:10px">Server priority</label>
        <div class="pill-row scroll" id="connect-sort-pills" style="margin-top:4px">
          <button type="button" class="chip active" data-csort="recommended">Score</button>
          <button type="button" class="chip" data-csort="speed">Speed</button>
          <button type="button" class="chip" data-csort="ping">Ping</button>
        </div>
        <details class="adv">
          <summary>Advanced · cipher profile &amp; tunnel DNS</summary>
          <div class="grid-2" style="margin-top:10px">
            <div>
              <label class="field-label" for="connect-compat">OpenVPN cipher profile</label>
              <select id="connect-compat">
                <option value="mobile3">MobileCore3 (iOS / Android OpenVPN Connect)</option>
                <option value="ovpn26">OpenVPN 2.6 desktop</option>
                <option value="ovpn25">OpenVPN 2.5</option>
                <option value="ovpn24">OpenVPN 2.4 legacy</option>
              </select>
            </div>
            <div>
              <label class="field-label" for="connect-dns">Tunnel DNS</label>
              <select id="connect-dns">
                <option value="1.1.1.1,1.0.0.1">Cloudflare DNS (1.1.1.1, 1.0.0.1)</option>
                <option value="9.9.9.9,149.112.112.112">Quad9 (9.9.9.9)</option>
                <option value="94.140.14.14,94.140.15.15">AdGuard DNS (94.140.14.14)</option>
              </select>
            </div>
          </div>
        </details>
      </div>

      <div id="hero-container">
        <div class="hero-relay testing">
          <div class="skeleton" style="width:55%;height:18px"></div>
          <div class="skeleton" style="width:72%;height:12px"></div>
          <div class="progress-track"><div class="progress-fill"></div></div>
          <div class="progress-label">Discovering volunteer relays…</div>
        </div>
      </div>

      <div class="card">
        <details class="adv" style="margin-top:0;border-top:0;padding-top:0">
          <summary>Device setup · iOS / Android / desktop</summary>
          <div class="card-subtitle" style="margin-top:8px">
            <strong>iPhone / iPad:</strong> Safari only. Wait for <em>LIVE HANDSHAKE</em>, tap <strong>Install Apple L2TP</strong> → Allow → Settings → Profile Downloaded → Install. OpenVPN: tap <strong>Open in OpenVPN Connect</strong> (install that app first) — the profile is handed to the app, not opened as a page.<br>
            <strong>Android / OpenVPN:</strong> After handshake, tap <strong>Open in OpenVPN Connect</strong>. If the app is missing you will be offered Play Store, then share/download.<br>
            <strong>Linux &amp; Windows 11:</strong> Linux command is shown by default. Windows devices switch automatically. Tap a command to copy.
          </div>
          <div class="pill-row" id="install-os-pills" style="margin-top:8px">
            <button type="button" class="chip active" data-install-os="linux">Linux</button>
            <button type="button" class="chip" data-install-os="windows">Windows</button>
          </div>
          <div class="card-subtitle" id="install-os-hint" style="margin-top:8px">Linux / macOS · POSIX sh</div>
          <div class="code-copy-label">Install · tap to copy</div>
          <button type="button" class="code-copy" id="install-copy" title="Tap to copy">curl -fsSL https://raw.githubusercontent.com/warmaster726/vpngate-connect/main/install-vpngate.sh | sh -s --</button>
          <div class="code-copy-label">Uninstall · same one-liner + --uninstall</div>
          <button type="button" class="code-copy" id="uninstall-copy" title="Tap to copy">curl -fsSL https://raw.githubusercontent.com/warmaster726/vpngate-connect/main/install-vpngate.sh | sh -s -- --uninstall</button>
        </details>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">Live edge console</div>
          <button type="button" class="btn btn-sm" id="btn-clear-log">Clear</button>
        </div>
        <div class="console-box" id="console-log" aria-live="polite"></div>
      </div>
    </section>

    <section class="tab-panel" id="tab-relays">
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Live volunteer relay matrix</div>
            <div class="card-subtitle" id="relays-meta">Loading relays...</div>
          </div>
        </div>
        <input type="text" id="relay-search" placeholder="Filter by ISO (JP, KR, US) or country / hostname / IP" autocomplete="off" spellcheck="false">
        <div class="pill-row scroll" id="relay-proto-pills">
          <button type="button" class="chip active" data-rproto="all">All protocols</button>
          <button type="button" class="chip" data-rproto="l2tp">L2TP/IPsec</button>
          <button type="button" class="chip" data-rproto="openvpn">OpenVPN</button>
          <button type="button" class="chip" data-rproto="udp">OVPN UDP</button>
          <button type="button" class="chip" data-rproto="tcp">OVPN TCP</button>
        </div>
        <div class="pill-row scroll" id="relay-sort-pills">
          <button type="button" class="chip active" data-rsort="recommended">Recommended</button>
          <button type="button" class="chip" data-rsort="speed">Speed</button>
          <button type="button" class="chip" data-rsort="ping">Lowest ping</button>
          <button type="button" class="chip" data-rsort="score">Score</button>
        </div>
      </div>
      <div class="relay-list" id="relays-list"></div>
    </section>

    <section class="tab-panel" id="tab-mirrors">
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Official VPNGate mirror portals</div>
            <div class="card-subtitle" id="mirrors-count">All listed portals are merged into the live pool automatically</div>
          </div>
          <button type="button" class="btn btn-sm" id="btn-probe-mirrors">Re-probe reachability</button>
        </div>
        <div class="card-subtitle" style="margin-bottom:8px">Discovery already pulls <code>/api/iphone/</code> from every official portal plus all HTTPS CSV feeds. Add an extra portal only if you have a URL that is not in the directory.</div>
        <label class="field-label" for="custom-mirror-input">Extra portal to merge (optional)</label>
        <div class="inline-row">
          <input type="text" id="custom-mirror-input" placeholder="http://host:port/en/" autocomplete="off" spellcheck="false">
          <button type="button" class="btn btn-sm" id="btn-apply-mirror">Merge extra</button>
        </div>
      </div>
      <div class="relay-list" id="mirrors-list"></div>
    </section>

    <section class="tab-panel" id="tab-doctor">
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">System, DoH &amp; handshake diagnostics</div>
            <div class="card-subtitle">Verifies egress, Cloudflare DoH, relay pool, live OpenVPN HARD_RESET, and gated profile builders</div>
          </div>
          <button type="button" class="btn btn-sm" id="btn-run-doctor">Re-run checks</button>
        </div>
        <div class="relay-list" id="doctor-results"></div>
      </div>
    </section>
  </div>

  <nav class="bottom-nav" aria-label="Primary console navigation">
    <div class="bottom-nav-inner">
      <button type="button" class="nav-tab active" data-tab="connect"><span class="nav-ico">⚡</span><span>1. Connect</span></button>
      <button type="button" class="nav-tab" data-tab="relays"><span class="nav-ico">🛰️</span><span>2. Relays</span></button>
      <button type="button" class="nav-tab" data-tab="mirrors"><span class="nav-ico">🪞</span><span>3. Mirrors</span></button>
      <button type="button" class="nav-tab" data-tab="doctor"><span class="nav-ico">🩺</span><span>4. Doctor</span></button>
    </div>
  </nav>

  <script>${PORTAL_JS}</script>
</body>
</html>`;
}

function jsonResponse(payload, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

async function handleMirrorsEndpoint(url, ctx) {
  const wantProbe = url.searchParams.get("probe") === "1";
  const snap = await getPoolSnapshot(ctx, { forceRefresh: false });
  let mirrors = snap.public_payload.mirrors || [];
  if (mirrors.length === 0) {
    mirrors = await fetchFallbackMirrors();
  }
  if (!wantProbe) {
    return jsonResponse({ ok: true, mirrors });
  }

  const slice = mirrors.slice(0, 10);
  const probed = await Promise.all(
    slice.map(async (m) => {
      const t0 = Date.now();
      let reachable = false;
      let rttMs = null;
      let serversCount = 0;

      const csvRes = await fetchTextTimeout(`${m.base_url}/api/iphone/`, 3500);
      if (csvRes && (csvRes.text.includes("*vpn_servers") || csvRes.text.includes("#HostName"))) {
        const map = new Map();
        parseVpngateCsvInto(csvRes.text, map);
        reachable = true;
        serversCount = map.size;
        rttMs = Math.max(1, Date.now() - t0);
      } else {
        const enRes = await fetchTextTimeout(m.portal_url, 3500);
        if (enRes && enRes.text.includes("vg_table_row_")) {
          const map = new Map();
          parseVpngateHtmlInto(enRes.text, map);
          reachable = true;
          serversCount = map.size;
          rttMs = Math.max(1, Date.now() - t0);
        }
      }
      return { ...m, reachable, rtt_ms: rttMs, servers_count: serversCount };
    })
  );

  const rest = mirrors.slice(10);
  probed.sort((a, b) => Number(b.reachable) - Number(a.reachable) || (a.rtt_ms || 99999) - (b.rtt_ms || 99999));
  const combined = [...probed, ...rest];
  return jsonResponse({
    ok: true,
    online_count: probed.filter((m) => m.reachable).length,
    mirrors: combined,
  });
}

async function handleVerifyEndpoint(url, ctx) {
  const snap = await getPoolSnapshot(ctx, { forceRefresh: false });
  const servers = decorateServersWithVerification(snap.public_payload.servers || []);
  const ip = validPublicIpv4(url.searchParams.get("ip") || "");
  const proto = (url.searchParams.get("proto") || "auto").toLowerCase();
  const country = url.searchParams.get("country") || "ALL";
  const sortRaw = (url.searchParams.get("sort") || "recommended").toLowerCase();
  const sort = ["recommended", "speed", "ping", "score"].includes(sortRaw) ? sortRaw : "recommended";
  const force = url.searchParams.get("force") === "1";
  const exclude = (url.searchParams.get("exclude") || "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => Boolean(validPublicIpv4(s)));

  const result = await recursiveVerifyRelays({
    servers,
    country,
    proto,
    sort,
    exclude,
    ip: ip || "",
    force,
    ctx,
  });
  if (!result.verified) {
    return jsonResponse({
      ok: true,
      verified: null,
      attempts: result.attempts,
      scanned: result.scanned,
      widened: result.widened,
      remaining: result.remaining,
      error: "No candidate completed a live OpenVPN TCP handshake.",
    });
  }
  return jsonResponse({ ok: true, ...result });
}

async function handleDoctorEndpoint(request, ctx) {
  const cf = request.cf || {};
  const visitorIp = request.headers.get("CF-Connecting-IP") || "client";
  const checks = [];

  checks.push({
    name: "Visitor Egress & Cloudflare PoP",
    status: "READY",
    detail: `Client ${visitorIp} · Edge PoP ${cf.colo || "LOCAL"} (${cf.country || "XX"}) · ${cf.httpProtocol || "HTTP/2"} ${cf.tlsVersion || "TLSv1.3"}`,
  });

  const dohStart = Date.now();
  try {
    const dohRes = await fetchTextTimeout(
      "https://cloudflare-dns.com/dns-query?name=www.vpngate.net&type=A",
      3000,
      { headers: { Accept: "application/dns-json" } }
    );
    if (dohRes) {
      const parsed = JSON.parse(dohRes.text);
      const ips = (parsed.Answer || [])
        .filter((a) => a.type === 1)
        .map((a) => validPublicIpv4(a.data))
        .filter(Boolean);
      checks.push({
        name: "Cloudflare DoH (1.1.1.1) Unpoisoned DNS",
        status: ips.length > 0 ? "READY" : "WARN",
        detail: ips.length > 0
          ? `Resolved www.vpngate.net → ${ips.join(", ")} (${Date.now() - dohStart} ms, bogon-verified)`
          : "DoH responded without unpoisoned IPv4 A records",
      });
    } else {
      checks.push({ name: "Cloudflare DoH (1.1.1.1) Unpoisoned DNS", status: "WARN", detail: "DoH query timed out" });
    }
  } catch (e) {
    checks.push({ name: "Cloudflare DoH (1.1.1.1) Unpoisoned DNS", status: "WARN", detail: String(e) });
  }

  const snap = await getPoolSnapshot(ctx, { forceRefresh: false });
  const counts = snap.public_payload.counts;
  checks.push({
    name: "Multi-Source Relay & Mirror Pool",
    status: counts.total > 0 ? "READY" : "ISSUE",
    detail: `${counts.total} listed relays (${counts.l2tp} L2TP/IPsec, ${counts.openvpn} OpenVPN) · ${counts.mirrors} Official Mirrors`,
  });

  const tcpCandidate = snap.public_payload.servers.find((s) => s.tcp_port > 0);
  if (tcpCandidate) {
    const pRes = await probeOpenVpnHandshake(tcpCandidate.ip, tcpCandidate.tcp_port, HANDSHAKE_TIMEOUT_MS);
    checks.push({
      name: "Live OpenVPN TCP Handshake",
      status: pRes.handshake ? "READY" : "WARN",
      detail: pRes.handshake
        ? `HARD_RESET_SERVER_V2 from ${tcpCandidate.ip}:${tcpCandidate.tcp_port} in ${pRes.rtt_ms} ms`
        : `${pRes.engine}: ${pRes.error || "relay did not complete OpenVPN handshake"}`,
    });
  } else {
    checks.push({
      name: "Live OpenVPN TCP Handshake",
      status: "WARN",
      detail: "No TCP-advertised relay currently in the pool",
    });
  }

  const dummySrv = {
    ip: "219.100.37.10",
    country_long: "Japan",
    country_short: "JP",
    tcp_port: 443,
    udp_port: 1195,
  };
  const mcXml = buildAppleL2tpMobileconfig(dummySrv, ["1.1.1.1", "1.0.0.1"]);
  const sampleOvpn = patchOvpnText(
    "client\ndev tun\nproto udp\nremote 10.0.0.1 1194\ncipher AES-128-CBC\nauth-user-pass\n<ca>\nCERT\n</ca>\n",
    dummySrv,
    { transport: "udp", compat: "mobile3", dnsServers: ["1.1.1.1", "1.0.0.1"] }
  );
  const profileOk =
    mcXml.includes("com.apple.vpn.managed") &&
    mcXml.includes("dnBu") &&
    sampleOvpn.includes("remote 219.100.37.10 1195") &&
    !sampleOvpn.includes("auth-user-pass");

  checks.push({
    name: "Profile Engine (.mobileconfig & .ovpn Patcher)",
    status: profileOk ? "READY" : "ISSUE",
    detail: profileOk
      ? "Generators healthy — delivery remains gated on a live OpenVPN HARD_RESET for the target relay"
      : "Profile self-test mismatch",
  });

  checks.push({
    name: "Profile Gate (handshake required)",
    status: "READY",
    detail: "GET /profiles/*.mobileconfig and GET /profiles/*.ovpn refuse issuance unless the relay answers OpenVPN TCP HARD_RESET_SERVER_V2",
  });

  return jsonResponse({ ok: true, checks });
}

export default {
  async fetch(request, _env, ctx) {
    await ensureVerifyMemory(ctx);
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method !== "GET" && request.method !== "HEAD") {
      return jsonResponse({ ok: false, error: "Method Not Allowed" }, 405);
    }

    if (path === "/manifest.webmanifest") {
      return jsonResponse(
        {
          name: "VPN Gate Connect",
          short_name: "VPNGate",
          start_url: "/",
          display: "standalone",
          background_color: "#070B14",
          theme_color: "#070B14",
          icons: [{ src: "/icon.svg", sizes: "any", type: "image/svg+xml" }],
        },
        200,
        { "Content-Type": "application/manifest+json; charset=utf-8" }
      );
    }

    if (path === "/icon.svg") {
      const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
        <rect width="128" height="128" rx="28" fill="#070B14"/>
        <rect x="8" y="8" width="112" height="112" rx="22" fill="#101827" stroke="#38BDF8" stroke-width="4"/>
        <path d="M64 24L96 38V62C96 84 82 100 64 106C46 100 32 84 32 62V38L64 24Z" fill="rgba(56,189,248,0.16)" stroke="#34D399" stroke-width="5"/>
        <text x="64" y="73" text-anchor="middle" font-family="monospace" font-weight="bold" font-size="30" fill="#E8EEF7">VG</text>
      </svg>`;
      return new Response(svg, {
        headers: {
          "Content-Type": "image/svg+xml; charset=utf-8",
          "Cache-Control": "public, max-age=86400",
        },
      });
    }

    if ((path.startsWith("/profiles/") && path.endsWith(".mobileconfig")) || path === "/api/profile/mobileconfig") {
      const ip = validPublicIpv4(url.searchParams.get("ip") || "");
      if (!ip) {
        return jsonResponse({ ok: false, error: "Valid public IPv4 'ip' parameter is required." }, 400);
      }
      const gate = await assertVerifiedForProfile(ctx, ip, "l2tp");
      if (gate.error) {
        return jsonResponse(
          { ok: false, error: gate.error, ip, handshake: gate.verified || null },
          gate.status || 409
        );
      }
      const dnsList = sanitizeDnsList(url.searchParams.get("dns"));
      const xml = buildAppleL2tpMobileconfig(
        {
          ip,
          country_long: gate.found.country_long,
          country_short: gate.found.country_short,
        },
        dnsList
      );
      return new Response(xml, {
        status: 200,
        headers: {
          "Content-Type": "application/x-apple-aspen-config",
          "Cache-Control": "no-store",
        },
      });
    }

    if ((path.startsWith("/profiles/") && path.endsWith(".ovpn")) || path === "/api/profile/ovpn") {
      const ip = validPublicIpv4(url.searchParams.get("ip") || "");
      if (!ip) {
        return jsonResponse({ ok: false, error: "Valid public IPv4 'ip' parameter is required." }, 400);
      }
      const transport = url.searchParams.get("proto") === "tcp" ? "tcp" : "udp";
      const compatRaw = url.searchParams.get("compat") || "mobile3";
      const compat = ["mobile3", "ovpn26", "ovpn25", "ovpn24"].includes(compatRaw) ? compatRaw : "mobile3";
      const dnsServers = sanitizeDnsList(url.searchParams.get("dns"));
      const winDrv = url.searchParams.get("windows_driver") || "";
      const gate = await assertVerifiedForProfile(ctx, ip, transport);
      if (gate.error) {
        return jsonResponse(
          { ok: false, error: gate.error, ip, handshake: gate.verified || null },
          gate.status || 409
        );
      }

      const srv = {
        ...gate.found,
        ovpn_b64: gate.snap.ovpn_by_ip[ip] || "",
        tcp_port: gate.verified.port || gate.found.tcp_port,
      };
      const patched = buildPatchedOvpn(srv, gate.snap.donor_ovpn_b64, {
        transport,
        compat,
        dnsServers,
        windowsDriver: winDrv,
      });
      if (!patched) {
        return jsonResponse({ ok: false, error: "OpenVPN configuration certificate unavailable for this relay." }, 404);
      }
      const cc = /^[A-Z]{2}$/.test(srv.country_short || "") ? srv.country_short : "VG";
      const fileName = `vpngate-${cc}-${ip}-${transport}.ovpn`;
      const dest = request.headers.get("Sec-Fetch-Dest") || "";
      const mode = request.headers.get("Sec-Fetch-Mode") || "";
      const ua = request.headers.get("User-Agent") || "";
      const ovpnClient = /openvpn/i.test(ua);
      if (!ovpnClient && (mode === "navigate" || dest === "document")) {
        return Response.redirect(new URL("/", url).toString(), 303);
      }
      return new Response(patched, {
        status: 200,
        headers: {
          "Content-Type": "application/x-openvpn-profile",
          "Content-Disposition": `attachment; filename="${fileName}"; filename*=UTF-8''${encodeURIComponent(fileName)}`,
          "X-Content-Type-Options": "nosniff",
          "Cache-Control": "no-store",
        },
      });
    }

    if (path === "/api/servers") {
      const forceRefresh = url.searchParams.get("refresh") === "1";
      const customMirror = (url.searchParams.get("mirror") || "").trim();
      const snap = await getPoolSnapshot(ctx, { forceRefresh, customMirror });
      const servers = decorateServersWithVerification(snap.public_payload.servers || []);
      const live = servers.filter((s) => s.verify_state === "live").length;
      return jsonResponse({
        ...snap.public_payload,
        servers,
        counts: { ...snap.public_payload.counts, live },
        cached: snap.cached,
      });
    }

    if (path === "/api/mirrors") {
      return handleMirrorsEndpoint(url, ctx);
    }

    if (path === "/api/verify") {
      return handleVerifyEndpoint(url, ctx);
    }

    if (path === "/api/probe") {
      const ip = validPublicIpv4(url.searchParams.get("ip") || "");
      const port = Number(url.searchParams.get("port") || 0);
      if (!ip || !Number.isInteger(port) || port < 1 || port > 65535) {
        return jsonResponse({ ok: false, error: "Valid public IPv4 'ip' and TCP 'port' are required." }, 400);
      }
      const snap = await getPoolSnapshot(ctx, { forceRefresh: false });
      const inPool = snap.public_payload.servers.find((s) => s.ip === ip);
      if (!inPool) {
        return jsonResponse({ ok: false, error: "Target IP is not an active VPN Gate relay." }, 403);
      }
      const res = await probeOpenVpnHandshake(ip, port, HANDSHAKE_TIMEOUT_MS);
      if (res.handshake) rememberVerify(ip, { ok: true, port, rtt_ms: res.rtt_ms, engine: res.engine }, ctx);
      else rememberVerify(ip, { ok: false, port, rtt_ms: res.rtt_ms, engine: res.engine, error: res.error }, ctx);
      return jsonResponse({ ok: true, ip, port, ...res });
    }

    if (path === "/api/doctor") {
      return handleDoctorEndpoint(request, ctx);
    }

    if (path === "/" || path === "/index.html") {
      return new Response(renderPortalHtml(), {
        status: 200,
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Content-Security-Policy":
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
          "X-Content-Type-Options": "nosniff",
          "Referrer-Policy": "no-referrer",
          "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        },
      });
    }

    return jsonResponse({ ok: false, error: "Not Found" }, 404);
  },
};

