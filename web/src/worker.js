/**
 * VPN Gate Connect — Isolated Cloudflare Workers Web Profile Portal
 * =================================================================
 * Zero-dependency ES Module Worker (`no_bundle = true` in `web/wrangler.toml`).
 *
 * Capabilities:
 *  - Preserves the 4-tab Obsidian/Slate Dark Console UI (`Connect`, `Relays`, `Mirrors`, `Doctor`)
 *  - Multi-stage censorship-resilient discovery (`vpngate.net` + Official Mirror Portals + HTTPS CSV/Archive Mirrors)
 *  - Outbound live TCP socket probing via `cloudflare:sockets` (`GET /api/probe`)
 *  - Native iOS / iPadOS / macOS L2TP/IPsec `.mobileconfig` delivery (`Content-Type: application/x-apple-aspen-config`)
 *  - Zero-prompt patched `.ovpn` export (`MobileCore3`, `OpenVpn26`, `OpenVpn25`, `OpenVpn24`)
 *  - Completely isolated from root `Cargo.toml`, `Cargo.lock`, and desktop installer scripts.
 */

const APP_VERSION = "0.1.0";
const POOL_CACHE_TTL_MS = 180_000;
const POOL_CACHE_KEY_URL = "https://vpngate-edge-cache.internal/v1/pool-snapshot";
const USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) VPNGate-WebWorker/0.1";

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
];

const DAILY_MIRROR_JSON_URLS = [
  "https://cdn.jsdelivr.net/gh/kusrabyzarc/vpngate-daily-mirrors@latest/mirrors.json",
  "https://raw.githubusercontent.com/kusrabyzarc/vpngate-daily-mirrors/main/mirrors.json",
];

const WAYBACK_MIRROR_SITES_CDX_URL =
  "https://web.archive.org/cdx/search/cdx?url=www.vpngate.net/en/sites.aspx&output=json&limit=-2&filter=statuscode:200&collapse=timestamp:8";

const WAYBACK_PORTAL_CDX_URL =
  "https://web.archive.org/cdx/search/cdx?url=www.vpngate.net/en/&output=json&limit=-2&filter=statuscode:200&collapse=timestamp:8";

const MIRROR_CSV_URLS = [
  "https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/data/vpngate.csv",
  "https://raw.githubusercontent.com/funcra/vg-mirror/main/servers.csv",
  "https://raw.githubusercontent.com/sinspired/VpngateAPI/main/servers.csv",
  "https://raw.githubusercontent.com/cjsl99/VpngateAPI/main/servers.csv",
  "https://raw.githubusercontent.com/NetLops/vpngate-mirror/main/vpngate.csv",
];

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
    if (s.openvpn && (s.udp_port > 0 || (s.has_ovpn_cert && s.tcp_port === 0))) entry.openvpn_udp_count += 1;
    if (s.openvpn && (s.tcp_port > 0 || (s.has_ovpn_cert && s.udp_port === 0))) entry.openvpn_tcp_count += 1;
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

function autoPriorityTier(s) {
  if (s.l2tp) return 0;
  if (s.openvpn && s.udp_port > 0) return 1;
  if (s.openvpn) return 2;
  return 3;
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
      logs.push({ level: "info", msg: `Using custom Official Mirror Portal: ${norm.portal_url}` });
    } else {
      logs.push({ level: "warn", msg: "Ignored invalid or private custom mirror URL." });
    }
  }

  let primaryCsv = "";
  let baseHtml = "";
  let l2tpHtml = "";
  let ovpnHtml = "";
  let primaryMirrors = [];

  // Stage 1: Primary vpngate.net (skipped first only if user explicitly requested a custom mirror test)
  if (customMirrors.length === 0) {
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

  // Stage 1b: Official VPNGate Mirror Portals (automatic failover or custom mirror)
  if (serversByIp.size === 0 || !l2tpHtml || customMirrors.length > 0) {
    if (harvestedMirrors.length === 0) {
      const fb = await fetchFallbackMirrors();
      harvestedMirrors = mergeMirrorLists(harvestedMirrors, fb);
    }
    const candidates = harvestedMirrors.slice(0, 3);
    for (const m of candidates) {
      const res = await fetchFromOfficialMirrorPortal(m);
      if (res) {
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
          msg: `Official Mirror ${m.portal_url} (${m.location}) online — merged live relay tables.`,
        });
        break;
      }
    }
  }

  // Stage 2: HTTPS Multi-Mirror CSV + Wayback L2TP Metadata Enrichment
  if (serversByIp.size < 80 || (!primaryCsv && serversByIp.size < 120) || !l2tpHtml) {
    logs.push({ level: "info", msg: "Enriching relay pool via HTTPS CDN/GitHub mirrors ..." });
    const csvTasks = MIRROR_CSV_URLS.slice(0, 4).map((u) => fetchTextTimeout(u, 4500));
    const wbTask = !l2tpHtml
      ? (async () => {
          const cdx = await fetchTextTimeout(WAYBACK_PORTAL_CDX_URL, 2600);
          if (!cdx) return "";
          try {
            const rows = JSON.parse(cdx.text);
            if (Array.isArray(rows) && rows.length >= 2) {
              const last = rows[rows.length - 1];
              const snap = await fetchTextTimeout(`https://web.archive.org/web/${last[1]}id_/${last[2]}`, 3500);
              return snap ? snap.text : "";
            }
          } catch {
            return "";
          }
          return "";
        })()
      : Promise.resolve("");

    const [csvResults, wbHtml] = await Promise.all([Promise.all(csvTasks), wbTask]);
    let hits = 0;
    for (const r of csvResults) {
      if (r && (r.text.includes("*vpn_servers") || r.text.includes("#HostName"))) {
        parseVpngateCsvInto(r.text, serversByIp);
        hits++;
      }
    }
    if (wbHtml) {
      const wbMap = new Map();
      parseVpngateHtmlInto(wbHtml, wbMap);
      for (const [ip, wbSrv] of wbMap.entries()) {
        if (wbSrv.l2tp && serversByIp.has(ip)) {
          serversByIp.get(ip).l2tp = true;
        }
      }
    }
    if (hits > 0) {
      logs.push({ level: "ok", msg: `Merged ${hits} HTTPS CSV mirror feed(s) (${serversByIp.size} total relays).` });
    }
  }

  if (harvestedMirrors.length === 0) {
    harvestedMirrors = await fetchFallbackMirrors();
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

  fullServers.sort((a, b) => {
    const tierDiff = autoPriorityTier(a) - autoPriorityTier(b);
    if (tierDiff !== 0) return tierDiff;
    if (b.score !== a.score) return b.score - a.score;
    if (b.speed_bps !== a.speed_bps) return b.speed_bps - a.speed_bps;
    return (a.ping_ms || 9999) - (b.ping_ms || 9999);
  });

  const ovpnByIp = new Map();
  const lightServers = fullServers.map((s) => {
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

async function probeTcpEdge(ip, port, timeoutMs = 2200) {
  const t0 = Date.now();
  try {
    const socketsMod = await import("cloudflare:sockets");
    const socket = socketsMod.connect({ hostname: ip, port });
    let timer;
    try {
      await Promise.race([
        socket.opened,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("TCP connect timeout")), timeoutMs);
        }),
      ]);
      const rttMs = Math.max(1, Date.now() - t0);
      try { await socket.close(); } catch {}
      return { reachable: true, rtt_ms: rttMs, engine: "cloudflare:sockets" };
    } finally {
      clearTimeout(timer);
      try { socket.close(); } catch {}
    }
  } catch (err) {
    return {
      reachable: false,
      rtt_ms: null,
      engine: "cloudflare:sockets",
      error: err && err.message ? String(err.message) : "TCP probe unavailable",
    };
  }
}

// =============================================================================
// 5. Embedded 4-Tab Obsidian/Slate Dark Console UI (`Connect`, `Relays`, `Mirrors`, `Doctor`)
// =============================================================================

const PORTAL_CSS = String.raw`
:root {
  --bg: #0A0F1A;
  --card: #131C2E;
  --card-alt: #0E1625;
  --border: #22304A;
  --cyan: #38BDF8;
  --cyan-dim: rgba(56, 189, 248, 0.14);
  --emerald: #10B981;
  --emerald-dim: rgba(16, 185, 129, 0.14);
  --amber: #F59E0B;
  --amber-dim: rgba(245, 158, 11, 0.14);
  --coral: #F43F5E;
  --coral-dim: rgba(244, 63, 94, 0.14);
  --console: #070B12;
  --text: #E2E8F0;
  --muted: #94A3B8;
  --mono: "JetBrains Mono", "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
}
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
html, body {
  margin: 0; padding: 0;
  background: var(--bg); color: var(--text);
  font-family: var(--sans); font-size: 14px; line-height: 1.45;
  min-height: 100dvh;
}
a { color: var(--cyan); text-decoration: none; }
.app-shell {
  max-width: 960px; margin: 0 auto;
  padding: calc(12px + env(safe-area-inset-top, 0px)) 14px calc(86px + env(safe-area-inset-bottom, 0px));
}
.topbar {
  display: flex; align-items: center; justify-content: space-between; gap: 10px;
  background: var(--card); border: 1px solid var(--border);
  border-radius: 14px; padding: 12px 15px; margin-bottom: 14px;
}
.brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
.brand-icon {
  width: 36px; height: 36px; border-radius: 10px; flex-shrink: 0;
  background: linear-gradient(135deg, rgba(56,189,248,0.22), rgba(16,185,129,0.2));
  border: 1px solid rgba(56,189,248,0.4);
  display: grid; place-items: center; font-family: var(--mono); font-weight: 700; color: var(--cyan);
}
.brand-title { font-weight: 700; font-size: 15px; letter-spacing: -0.01em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.brand-sub { font-size: 11.5px; color: var(--muted); font-family: var(--mono); }
.topbar-right { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.status-pill {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 5px 10px; border-radius: 999px; font-size: 11.5px; font-family: var(--mono); font-weight: 600;
  background: var(--emerald-dim); color: var(--emerald); border: 1px solid rgba(16,185,129,0.35);
}
.status-pill.syncing { background: var(--cyan-dim); color: var(--cyan); border-color: rgba(56,189,248,0.35); }
.status-pill.error { background: var(--coral-dim); color: var(--coral); border-color: rgba(244,63,94,0.35); }
.dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }

.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 14px; padding: 15px; margin-bottom: 12px;
}
.card-header {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  margin-bottom: 10px;
}
.card-title { font-weight: 700; font-size: 13.5px; letter-spacing: 0.01em; color: #F8FAFC; }
.card-subtitle { font-size: 12px; color: var(--muted); }

.grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
@media (max-width: 640px) { .grid-2 { grid-template-columns: 1fr; } }

label.field-label {
  display: block; font-size: 11.5px; font-weight: 600; color: var(--muted);
  text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 5px; font-family: var(--mono);
}
select, input[type="text"] {
  width: 100%; background: var(--console); color: var(--text);
  border: 1px solid var(--border); border-radius: 10px;
  padding: 9px 11px; font-size: 13.5px; font-family: var(--sans); outline: none;
}
select:focus, input[type="text"]:focus { border-color: var(--cyan); }

.pill-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.chip {
  background: var(--card-alt); color: var(--muted);
  border: 1px solid var(--border); border-radius: 999px;
  padding: 5px 11px; font-size: 12px; font-family: var(--mono); cursor: pointer;
  transition: all 0.14s ease;
}
.chip:hover { border-color: var(--cyan); color: var(--text); }
.chip.active {
  background: var(--cyan-dim); color: var(--cyan);
  border-color: rgba(56, 189, 248, 0.55); font-weight: 600;
}

.hero-relay {
  background: linear-gradient(180deg, rgba(56,189,248,0.07) 0%, rgba(19,28,46,0.95) 100%);
  border: 1px solid rgba(56,189,248,0.38); border-radius: 14px; padding: 15px; margin-bottom: 12px;
}
.relay-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }
.relay-country { font-size: 16px; font-weight: 700; color: #F8FAFC; }
.relay-host { font-family: var(--mono); font-size: 12px; color: var(--cyan); margin-top: 2px; word-break: break-all; }
.stats-strip {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px;
  margin: 12px 0; background: var(--console); border: 1px solid var(--border);
  border-radius: 10px; padding: 9px 10px;
}
@media (max-width: 480px) { .stats-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.stat-box { font-family: var(--mono); }
.stat-k { font-size: 10.5px; color: var(--muted); text-transform: uppercase; }
.stat-v { font-size: 13px; font-weight: 700; color: #F8FAFC; margin-top: 1px; }

.badges { display: flex; flex-wrap: wrap; gap: 5px; }
.badge {
  display: inline-flex; align-items: center; padding: 2.5px 8px;
  border-radius: 6px; font-family: var(--mono); font-size: 11px; font-weight: 600;
}
.badge-l2tp { background: var(--emerald-dim); color: var(--emerald); border: 1px solid rgba(16,185,129,0.35); }
.badge-udp { background: var(--cyan-dim); color: var(--cyan); border: 1px solid rgba(56,189,248,0.35); }
.badge-tcp { background: var(--amber-dim); color: var(--amber); border: 1px solid rgba(245,158,11,0.35); }
.badge-err { background: var(--coral-dim); color: var(--coral); border: 1px solid rgba(244,63,94,0.35); }

.btn-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 7px;
  padding: 10px 14px; border-radius: 10px; font-size: 13px; font-weight: 600;
  border: 1px solid var(--border); background: var(--card-alt); color: var(--text);
  cursor: pointer; text-decoration: none; transition: all 0.14s ease;
}
.btn:hover { border-color: var(--cyan); color: #fff; }
.btn-primary {
  background: linear-gradient(135deg, #0EA5E9, #0284C7);
  border-color: #38BDF8; color: #fff; flex: 1 1 210px;
}
.btn-emerald {
  background: linear-gradient(135deg, #10B981, #059669);
  border-color: #34D399; color: #fff; flex: 1 1 210px;
}
.btn-sm { padding: 6px 10px; font-size: 12px; border-radius: 8px; font-family: var(--mono); }
.btn.disabled, .btn[disabled] { opacity: 0.42; pointer-events: none; }

.console-box {
  background: var(--console); border: 1px solid var(--border);
  border-radius: 12px; padding: 11px 12px; font-family: var(--mono);
  font-size: 11.5px; max-height: 210px; overflow-y: auto;
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

.code-copy {
  background: var(--console); border: 1px solid var(--border); border-radius: 9px;
  padding: 8px 10px; font-family: var(--mono); font-size: 11.5px; color: var(--cyan);
  overflow-x: auto; white-space: nowrap; margin-top: 6px;
}

.tab-panel { display: none; }
.tab-panel.active { display: block; }

.bottom-nav {
  position: fixed; left: 0; right: 0; bottom: 0; z-index: 50;
  background: rgba(10, 15, 26, 0.94); backdrop-filter: blur(12px);
  border-top: 1px solid var(--border);
  padding: 6px 10px calc(6px + env(safe-area-inset-bottom, 0px));
}
.bottom-nav-inner {
  max-width: 960px; margin: 0 auto;
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px;
}
.nav-tab {
  background: transparent; border: 1px solid transparent; border-radius: 10px;
  color: var(--muted); padding: 7px 4px; cursor: pointer;
  display: flex; flex-direction: column; align-items: center; gap: 2px;
  font-family: var(--mono); font-size: 11px; font-weight: 600;
}
.nav-tab .nav-ico { font-size: 15px; line-height: 1; }
.nav-tab.active {
  color: var(--cyan); background: var(--cyan-dim);
  border-color: rgba(56, 189, 248, 0.35);
}
`;

const PORTAL_JS = String.raw`
(function () {
  "use strict";

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
    selectedIndex: 0,
    relaySearch: "",
    relayProto: "all",
    relaySort: "recommended",
    relayLimit: 40,
    customMirror: "",
    device: detectDevice()
  };

  function detectDevice() {
    var ua = navigator.userAgent || "";
    var isIOS = /iPad|iPhone|iPod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
    var isAndroid = /Android/i.test(ua);
    var isMac = !isIOS && /Macintosh|Mac OS X/i.test(ua);
    var isWin = /Windows/i.test(ua);
    if (isIOS) return { id: "ios", label: "iOS / iPadOS (Safari Native .mobileconfig + OpenVPN)", apple: true, mobile: true };
    if (isAndroid) return { id: "android", label: "Android (OpenVPN Connect / OpenVPN for Android)", apple: false, mobile: true };
    if (isMac) return { id: "macos", label: "macOS (Native .mobileconfig + OpenVPN 2.6)", apple: true, mobile: false };
    if (isWin) return { id: "windows", label: "Windows 11 (Patched .ovpn + Native CLI Suite)", apple: false, mobile: false };
    return { id: "linux", label: "Linux Desktop (Patched .ovpn + Native CLI Suite)", apple: false, mobile: false };
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
      (srv.country_long || "").toLowerCase().indexOf(low) !== -1 ||
      (srv.hostname || "").toLowerCase().indexOf(low) !== -1 ||
      (srv.ip || "").indexOf(low) !== -1
    );
  }

  function matchProto(srv, proto) {
    if (!proto || proto === "auto" || proto === "all") return srv.l2tp || srv.openvpn;
    if (proto === "l2tp") return Boolean(srv.l2tp);
    if (proto === "udp") return Boolean(srv.openvpn && (srv.udp_port > 0 || (srv.has_ovpn_cert && srv.tcp_port === 0)));
    if (proto === "tcp") return Boolean(srv.openvpn && (srv.tcp_port > 0 || (srv.has_ovpn_cert && srv.udp_port === 0)));
    return true;
  }

  function sortList(list, sortKey, protoFilter) {
    return list.slice().sort(function (a, b) {
      var tierA = a.l2tp ? 0 : (a.openvpn && a.udp_port > 0 ? 1 : 2);
      var tierB = b.l2tp ? 0 : (b.openvpn && b.udp_port > 0 ? 1 : 2);
      var tierDiff = (protoFilter === "auto" || protoFilter === "all") ? (tierA - tierB) : 0;
      var pingA = a.ping_ms > 0 ? a.ping_ms : 99999;
      var pingB = b.ping_ms > 0 ? b.ping_ms : 99999;
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

  function renderBadges(srv) {
    var out = "";
    if (srv.l2tp) out += '<span class="badge badge-l2tp">L2TP PSK=vpn</span>';
    if (srv.openvpn && (srv.udp_port > 0 || (srv.has_ovpn_cert && srv.tcp_port === 0))) {
      out += '<span class="badge badge-udp">OVPN UDP' + (srv.udp_port ? ":" + srv.udp_port : "") + "</span>";
    }
    if (srv.openvpn && (srv.tcp_port > 0 || (srv.has_ovpn_cert && srv.udp_port === 0))) {
      out += '<span class="badge badge-tcp">OVPN TCP' + (srv.tcp_port ? ":" + srv.tcp_port : "") + "</span>";
    }
    return out;
  }

  function renderCountryControls() {
    var sel = document.getElementById("connect-country");
    var pills = document.getElementById("quick-country-pills");
    if (!sel || !pills) return;

    var opts = '<option value="ALL">🌐 All Countries (' + state.counts.total + ' relays)</option>';
    for (var i = 0; i < state.countries.length; i++) {
      var c = state.countries[i];
      var selected = state.country === c.country_short ? " selected" : "";
      opts += '<option value="' + esc(c.country_short) + '"' + selected + ">" +
        flagEmoji(c.country_short) + " " + esc(c.country_long) + " (" + esc(c.country_short) + ") — " +
        c.total_servers + " (" + c.l2tp_count + " L2TP)</option>";
    }
    sel.innerHTML = opts;

    var topCodes = ["ALL"];
    for (var j = 0; j < Math.min(7, state.countries.length); j++) {
      topCodes.push(state.countries[j].country_short);
    }
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
    var filtered = state.servers.filter(function (s) {
      return matchCountry(s, state.country) && matchProto(s, state.proto);
    });
    return sortList(filtered, "recommended", state.proto);
  }

  function renderConnectHero() {
    var wrap = document.getElementById("hero-container");
    if (!wrap) return;
    var candidates = getConnectCandidates();
    if (candidates.length === 0) {
      wrap.innerHTML = '<div class="card"><div class="card-title">No Matching Relays</div>' +
        '<div class="card-subtitle">Try switching Country to ALL or Protocol to Auto Recommended, or refresh the pool.</div></div>';
      return;
    }
    if (state.selectedIndex >= candidates.length) state.selectedIndex = 0;
    var srv = candidates[state.selectedIndex];
    var canUdp = srv.openvpn && (srv.udp_port > 0 || (srv.has_ovpn_cert && srv.tcp_port === 0));
    var canTcp = srv.openvpn && (srv.tcp_port > 0 || (srv.has_ovpn_cert && srv.udp_port === 0));
    var probePort = srv.tcp_port || 443;

    var html = '<div class="hero-relay">' +
      '<div class="relay-top">' +
        '<div>' +
          '<div class="relay-country">' + flagEmoji(srv.country_short) + " " + esc(srv.country_long) +
            ' <span style="color:var(--muted);font-size:12px;font-family:var(--mono)">[' + (state.selectedIndex + 1) + "/" + candidates.length + "]</span></div>" +
          '<div class="relay-host">' + esc(srv.hostname) + ".opengw.net · " + esc(srv.ip) + "</div>" +
        '</div>' +
        '<div class="badges">' + renderBadges(srv) + "</div>" +
      '</div>' +
      '<div class="stats-strip">' +
        '<div class="stat-box"><div class="stat-k">Throughput</div><div class="stat-v">' + fmtMbps(srv.speed_bps) + "</div></div>" +
        '<div class="stat-box"><div class="stat-k">Ping RTT</div><div class="stat-v">' + (srv.ping_ms >= 9999 ? "—" : srv.ping_ms + " ms") + "</div></div>" +
        '<div class="stat-box"><div class="stat-k">Quality Score</div><div class="stat-v">' + fmtScore(srv.score) + "</div></div>" +
        '<div class="stat-box"><div class="stat-k">Sessions</div><div class="stat-v">' + srv.sessions + "</div></div>" +
      '</div>' +
      '<div class="btn-row">' +
        (srv.l2tp
          ? '<a class="btn btn-emerald" href="' + esc(buildMobileconfigHref(srv)) + '"> Install Apple L2TP (.mobileconfig)</a>'
          : '<span class="btn disabled" title="Selected relay does not advertise L2TP/IPsec"> L2TP Unavailable on Relay</span>') +
        (canUdp
          ? '<a class="btn btn-primary" href="' + esc(buildOvpnHref(srv, "udp")) + '">⬇ Export OpenVPN UDP (.ovpn)</a>'
          : "") +
        (canTcp
          ? '<a class="btn" href="' + esc(buildOvpnHref(srv, "tcp")) + '">⬇ Export OpenVPN TCP (.ovpn)</a>'
          : "") +
      '</div>' +
      '<div class="btn-row" style="margin-top:8px">' +
        '<button type="button" class="btn btn-sm" id="btn-next-relay">↻ Next Best Candidate (' + candidates.length + ')</button>' +
        '<button type="button" class="btn btn-sm" data-probe-ip="' + esc(srv.ip) + '" data-probe-port="' + probePort + '">⚡ Edge TCP Probe (' + esc(srv.ip) + ':' + probePort + ')</button>' +
      '</div>' +
    '</div>';

    wrap.innerHTML = html;
    var nextBtn = document.getElementById("btn-next-relay");
    if (nextBtn) {
      nextBtn.addEventListener("click", function () {
        state.selectedIndex = (state.selectedIndex + 1) % candidates.length;
        renderConnectHero();
      });
    }
  }

  function renderRelaysTab() {
    var listEl = document.getElementById("relays-list");
    var metaEl = document.getElementById("relays-meta");
    if (!listEl || !metaEl) return;

    var filtered = state.servers.filter(function (s) {
      return matchCountry(s, state.relaySearch) && matchProto(s, state.relayProto);
    });
    var sorted = sortList(filtered, state.relaySort, state.relayProto);
    metaEl.textContent = "Showing " + Math.min(sorted.length, state.relayLimit) + " of " + sorted.length + " matching relays";

    if (sorted.length === 0) {
      listEl.innerHTML = '<div class="card-subtitle">No relays matched your filter criteria.</div>';
      return;
    }

    var slice = sorted.slice(0, state.relayLimit);
    var out = "";
    for (var i = 0; i < slice.length; i++) {
      var s = slice[i];
      var canUdp = s.openvpn && (s.udp_port > 0 || (s.has_ovpn_cert && s.tcp_port === 0));
      var canTcp = s.openvpn && (s.tcp_port > 0 || (s.has_ovpn_cert && s.udp_port === 0));
      var pPort = s.tcp_port || 443;
      out += '<div class="relay-item">' +
        '<div class="relay-top">' +
          '<div>' +
            '<div style="font-weight:700;color:#F8FAFC">' + flagEmoji(s.country_short) + " " + esc(s.country_long) + ' <span style="color:var(--muted);font-family:var(--mono);font-size:11.5px">(' + esc(s.country_short) + ')</span></div>' +
            '<div class="relay-host">' + esc(s.hostname) + " · " + esc(s.ip) + " · " + fmtMbps(s.speed_bps) + " · " + (s.ping_ms >= 9999 ? "—" : s.ping_ms + " ms") + " · Score " + fmtScore(s.score) + "</div>" +
          '</div>' +
          '<div class="badges">' + renderBadges(s) + "</div>" +
        '</div>' +
        '<div class="btn-row" style="margin-top:9px">' +
          (s.l2tp ? '<a class="btn btn-sm" style="border-color:rgba(16,185,129,0.5);color:var(--emerald)" href="' + esc(buildMobileconfigHref(s)) + '"> .mobileconfig</a>' : "") +
          (canUdp ? '<a class="btn btn-sm" style="border-color:rgba(56,189,248,0.5);color:var(--cyan)" href="' + esc(buildOvpnHref(s, "udp")) + '">⬇ OVPN UDP</a>' : "") +
          (canTcp ? '<a class="btn btn-sm" href="' + esc(buildOvpnHref(s, "tcp")) + '">⬇ OVPN TCP</a>' : "") +
          '<button type="button" class="btn btn-sm" data-probe-ip="' + esc(s.ip) + '" data-probe-port="' + pPort + '">⚡ Probe :' + pPort + '</button>' +
        '</div>' +
      '</div>';
    }
    if (sorted.length > state.relayLimit) {
      out += '<button type="button" class="btn" id="btn-more-relays">Show More Relays (' + (sorted.length - state.relayLimit) + ' remaining)</button>';
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
    cntEl.textContent = state.mirrors.length + " Official Mirror Portal(s)";
    if (state.mirrors.length === 0) {
      listEl.innerHTML = '<div class="card-subtitle">No mirrors loaded yet. Tap "Probe Official Mirrors" above.</div>';
      return;
    }
    var out = "";
    for (var i = 0; i < state.mirrors.length; i++) {
      var m = state.mirrors[i];
      var statusBadge = "";
      if (m.reachable === true) {
        statusBadge = '<span class="badge badge-l2tp">ONLINE · ' + (m.rtt_ms || 1) + " ms · " + (m.servers_count || 0) + " relays</span>";
      } else if (m.reachable === false) {
        statusBadge = '<span class="badge badge-err">OFFLINE</span>';
      } else {
        statusBadge = '<span class="badge badge-udp">' + esc(m.source || "directory") + "</span>";
      }
      out += '<div class="relay-item">' +
        '<div class="relay-top">' +
          '<div>' +
            '<div style="font-weight:700;color:#F8FAFC">🪞 ' + esc(m.location || "Official Mirror") + "</div>" +
            '<div class="relay-host">' + esc(m.portal_url) + "</div>" +
          '</div>' +
          '<div class="badges">' + statusBadge + "</div>" +
        '</div>' +
        '<div class="btn-row" style="margin-top:8px">' +
          '<button type="button" class="btn btn-sm" data-use-mirror="' + esc(m.portal_url) + '">Sync Relay Pool via This Mirror</button>' +
          '<a class="btn btn-sm" href="' + esc(m.portal_url) + '" target="_blank" rel="noopener noreferrer">Open Portal ↗</a>' +
        '</div>' +
      '</div>';
    }
    listEl.innerHTML = out;
  }

  async function loadPool(forceRefresh, customMirror) {
    setStatusPill("syncing", "SYNCING...");
    appendLog("info", forceRefresh ? "Refreshing live VPN Gate relay pool from Cloudflare edge ..." : "Loading VPN Gate relay pool ...");
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

      if (Array.isArray(data.logs)) {
        for (var i = 0; i < data.logs.length; i++) {
          appendLog(data.logs[i].level || "info", data.logs[i].msg);
        }
      }
      setStatusPill("", "ONLINE · " + state.counts.total + " Relays");
      renderCountryControls();
      renderConnectHero();
      renderRelaysTab();
      renderMirrorsTab();
    } catch (err) {
      setStatusPill("error", "DISCOVERY ISSUE");
      appendLog("err", "Failed to load relay pool: " + (err && err.message ? err.message : String(err)));
    }
  }

  async function runProbeMirrors() {
    var btn = document.getElementById("btn-probe-mirrors");
    if (btn) btn.disabled = true;
    appendLog("info", "Probing Official VPNGate Mirror Sites from Cloudflare edge ...");
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
    if (box) box.innerHTML = '<div class="card-subtitle">Running edge, DoH, TCP socket & profile self-tests ...</div>';
    appendLog("info", "Running edge & profile readiness diagnostics (/api/doctor) ...");
    try {
      var resp = await fetch("/api/doctor");
      var data = await resp.json();
      var checks = (data && data.checks) || [];
      var html = "";
      for (var i = 0; i < checks.length; i++) {
        var c = checks[i];
        var bCls = c.status === "READY" ? "badge-l2tp" : (c.status === "WARN" ? "badge-tcp" : "badge-err");
        html += '<div class="relay-item">' +
          '<div class="relay-top">' +
            '<div style="font-weight:700;color:#F8FAFC">' + esc(c.name) + "</div>" +
            '<span class="badge ' + bCls + '">' + esc(c.status) + "</span>" +
          '</div>' +
          '<div class="card-subtitle" style="margin-top:4px;font-family:var(--mono)">' + esc(c.detail) + "</div>" +
        '</div>';
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
    if (tabId === "doctor" && !document.getElementById("doctor-results").hasChildNodes()) {
      runDoctor();
    }
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
      state.selectedIndex = 0;
      renderCountryControls();
      renderConnectHero();
    });

    document.getElementById("quick-country-pills").addEventListener("click", function (e) {
      var btn = e.target.closest("[data-cc]");
      if (!btn) return;
      state.country = btn.getAttribute("data-cc");
      state.selectedIndex = 0;
      renderCountryControls();
      renderConnectHero();
    });

    document.getElementById("connect-proto").addEventListener("change", function (e) {
      state.proto = e.target.value;
      state.selectedIndex = 0;
      renderConnectHero();
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

    document.body.addEventListener("click", async function (e) {
      var probeBtn = e.target.closest("[data-probe-ip]");
      if (probeBtn) {
        var ip = probeBtn.getAttribute("data-probe-ip");
        var port = probeBtn.getAttribute("data-probe-port");
        var origText = probeBtn.textContent;
        probeBtn.disabled = true;
        probeBtn.textContent = "Probing...";
        appendLog("info", "Opening edge TCP socket to " + ip + ":" + port + " ...");
        try {
          var r = await fetch("/api/probe?ip=" + encodeURIComponent(ip) + "&port=" + encodeURIComponent(port));
          var d = await r.json();
          if (d && d.reachable) {
            probeBtn.textContent = "✓ " + d.rtt_ms + " ms";
            appendLog("ok", "TCP handshake succeeded on " + ip + ":" + port + " (" + d.rtt_ms + " ms via " + d.engine + ").");
          } else {
            probeBtn.textContent = "✗ Offline";
            appendLog("warn", "TCP probe did not connect to " + ip + ":" + port + (d && d.error ? " (" + d.error + ")" : ""));
          }
        } catch (err) {
          probeBtn.textContent = "✗ Error";
          appendLog("err", "Probe request failed: " + (err && err.message ? err.message : String(err)));
        } finally {
          setTimeout(function () {
            probeBtn.disabled = false;
            probeBtn.textContent = origText;
          }, 3000);
        }
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
  <meta name="theme-color" content="#0A0F1A">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <title>VPN Gate Connect — Profile &amp; Relay Console</title>
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
        <div class="status-pill syncing" id="status-pill">
          <span class="dot"></span>
          <span id="status-text">BOOTING</span>
        </div>
        <button type="button" class="btn btn-sm" id="btn-refresh" title="Refresh live server pool">↻ Sync</button>
      </div>
    </header>

    <!-- TAB 1: CONNECT -->
    <section class="tab-panel active" id="tab-connect">
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Provisioning &amp; Filter Profile</div>
            <div class="card-subtitle">One-tap Apple L2TP/IPsec (<code>.mobileconfig</code>) &amp; zero-prompt patched OpenVPN (<code>.ovpn</code>)</div>
          </div>
        </div>
        <div class="grid-2">
          <div>
            <label class="field-label" for="connect-country">Target Country</label>
            <select id="connect-country"><option value="ALL">Loading countries...</option></select>
          </div>
          <div>
            <label class="field-label" for="connect-proto">Protocol Priority</label>
            <select id="connect-proto">
              <option value="auto">Auto (L2TP/IPsec → OVPN UDP → OVPN TCP)</option>
              <option value="l2tp">Apple Native L2TP/IPsec (.mobileconfig)</option>
              <option value="udp">OpenVPN UDP (.ovpn)</option>
              <option value="tcp">OpenVPN TCP (.ovpn)</option>
            </select>
          </div>
          <div>
            <label class="field-label" for="connect-compat">OpenVPN Cipher Profile</label>
            <select id="connect-compat">
              <option value="mobile3">MobileCore3 (iOS / Android OpenVPN Connect &amp; Partout)</option>
              <option value="ovpn26">OpenVPN 2.6 Desktop (data-ciphers + disable-dco)</option>
              <option value="ovpn25">OpenVPN 2.5 (data-ciphers)</option>
              <option value="ovpn24">OpenVPN 2.4 Legacy (ncp-ciphers)</option>
            </select>
          </div>
          <div>
            <label class="field-label" for="connect-dns">Tunnel DNS Enforcement</label>
            <select id="connect-dns">
              <option value="1.1.1.1,1.0.0.1">Cloudflare DNS (1.1.1.1, 1.0.0.1)</option>
              <option value="9.9.9.9,149.112.112.112">Quad9 Malware-Blocking (9.9.9.9)</option>
              <option value="94.140.14.14,94.140.15.15">AdGuard DNS (94.140.14.14)</option>
            </select>
          </div>
        </div>
        <div class="pill-row" id="quick-country-pills"></div>
      </div>

      <div id="hero-container"></div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">Quick Device Setup</div>
        </div>
        <div class="card-subtitle">
          <strong>iPhone / iPad (Zero App Store Install):</strong> Open this portal in <strong>Safari</strong>, tap <strong>Install Apple L2TP (.mobileconfig)</strong> → tap <em>Allow</em> → open <strong>Settings → Profile Downloaded → Install</strong>, then toggle VPN on.<br>
          <strong>Android / iOS OpenVPN:</strong> Install <em>OpenVPN Connect</em> (or <em>OpenVPN for Android</em>), tap <strong>Export OpenVPN UDP (.ovpn)</strong>, and import with zero username/password prompts.<br>
          <strong>Linux, Windows 11 &amp; macOS Native Desktop Client:</strong>
        </div>
        <div class="code-copy">curl -fsSL https://raw.githubusercontent.com/warmaster726/vpngate-connect/main/install-vpngate.sh | sh</div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">Live Edge Telemetry Console</div>
          <button type="button" class="btn btn-sm" id="btn-clear-log">Clear</button>
        </div>
        <div class="console-box" id="console-log"></div>
      </div>
    </section>

    <!-- TAB 2: RELAYS -->
    <section class="tab-panel" id="tab-relays">
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Live Volunteer Relay Matrix</div>
            <div class="card-subtitle" id="relays-meta">Loading relays...</div>
          </div>
        </div>
        <input type="text" id="relay-search" placeholder="Filter by 2-letter ISO (JP, KR, US, GB) or country / hostname / IP ...">
        <div class="pill-row" id="relay-proto-pills">
          <button type="button" class="chip active" data-rproto="all">All Protocols</button>
          <button type="button" class="chip" data-rproto="l2tp">L2TP/IPsec</button>
          <button type="button" class="chip" data-rproto="udp">OVPN UDP</button>
          <button type="button" class="chip" data-rproto="tcp">OVPN TCP</button>
        </div>
        <div class="pill-row" id="relay-sort-pills">
          <button type="button" class="chip active" data-rsort="recommended">Sort: Recommended</button>
          <button type="button" class="chip" data-rsort="speed">Sort: Speed</button>
          <button type="button" class="chip" data-rsort="ping">Sort: Lowest Ping</button>
          <button type="button" class="chip" data-rsort="score">Sort: Score</button>
        </div>
      </div>
      <div class="relay-list" id="relays-list"></div>
    </section>

    <!-- TAB 3: MIRRORS -->
    <section class="tab-panel" id="tab-mirrors">
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Official VPNGate Mirror Portals</div>
            <div class="card-subtitle" id="mirrors-count">Discovering mirrors...</div>
          </div>
          <button type="button" class="btn btn-sm" id="btn-probe-mirrors">⚡ Probe Official Mirrors</button>
        </div>
        <label class="field-label" for="custom-mirror-input">Custom Daily Mirror Portal (Optional)</label>
        <div style="display:flex;gap:8px">
          <input type="text" id="custom-mirror-input" placeholder="http://host:port/en/">
          <button type="button" class="btn btn-sm" id="btn-apply-mirror">Apply</button>
        </div>
      </div>
      <div class="relay-list" id="mirrors-list"></div>
    </section>

    <!-- TAB 4: DOCTOR -->
    <section class="tab-panel" id="tab-doctor">
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">System, DoH &amp; Edge Readiness Diagnostics</div>
            <div class="card-subtitle">Verifies client egress, Cloudflare DoH, upstream feeds, outbound TCP sockets &amp; profile generators</div>
          </div>
          <button type="button" class="btn btn-sm" id="btn-run-doctor">↻ Re-run Checks</button>
        </div>
        <div class="relay-list" id="doctor-results"></div>
      </div>
    </section>
  </div>

  <nav class="bottom-nav" aria-label="Primary Console Navigation">
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

// =============================================================================
// 6. Request Router & HTTP Security / Profile MIME Headers
// =============================================================================

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

async function handleDoctorEndpoint(request, ctx) {
  const cf = request.cf || {};
  const visitorIp = request.headers.get("CF-Connecting-IP") || "client";
  const checks = [];

  checks.push({
    name: "Visitor Egress & Cloudflare PoP",
    status: "READY",
    detail: `Client ${visitorIp} · Edge PoP ${cf.colo || "LOCAL"} (${cf.country || "XX"}) · ${cf.httpProtocol || "HTTP/2"} ${cf.tlsVersion || "TLSv1.3"}`,
  });

  // 1. Cloudflare DoH check
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

  // 2. Relay pool & failover status
  const snap = await getPoolSnapshot(ctx, { forceRefresh: false });
  const counts = snap.public_payload.counts;
  checks.push({
    name: "Multi-Source Relay & Mirror Pool",
    status: counts.total > 0 ? "READY" : "ISSUE",
    detail: `${counts.total} active relays (${counts.l2tp} L2TP/IPsec, ${counts.openvpn} OpenVPN) · ${counts.mirrors} Official Mirrors`,
  });

  // 3. Outbound TCP Socket probe on top TCP-capable relay
  const tcpCandidate = snap.public_payload.servers.find((s) => s.tcp_port > 0);
  if (tcpCandidate) {
    const pRes = await probeTcpEdge(tcpCandidate.ip, tcpCandidate.tcp_port, 2000);
    checks.push({
      name: "Cloudflare Outbound TCP Socket Prober",
      status: pRes.reachable ? "READY" : "WARN",
      detail: pRes.reachable
        ? `Connected to ${tcpCandidate.ip}:${tcpCandidate.tcp_port} in ${pRes.rtt_ms} ms (${pRes.engine})`
        : `${pRes.engine}: ${pRes.error || "relay port closed"}`,
    });
  }

  // 4. Apple .mobileconfig + Patched .ovpn Self-Test
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
      ? "Verified Apple L2TP plist (application/x-apple-aspen-config, PSK='vpn') + zero-prompt MobileCore3/OpenVPN26 patcher"
      : "Profile self-test mismatch",
  });

  return jsonResponse({ ok: true, checks });
}

export default {
  async fetch(request, _env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method !== "GET" && request.method !== "HEAD") {
      return jsonResponse({ ok: false, error: "Method Not Allowed" }, 405);
    }

    // 1. PWA Manifest & Inline SVG Icon
    if (path === "/manifest.webmanifest") {
      return jsonResponse(
        {
          name: "VPN Gate Connect",
          short_name: "VPNGate",
          start_url: "/",
          display: "standalone",
          background_color: "#0A0F1A",
          theme_color: "#0A0F1A",
          icons: [{ src: "/icon.svg", sizes: "any", type: "image/svg+xml" }],
        },
        200,
        { "Content-Type": "application/manifest+json; charset=utf-8" }
      );
    }

    if (path === "/icon.svg") {
      const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
        <rect width="128" height="128" rx="28" fill="#0A0F1A"/>
        <rect x="8" y="8" width="112" height="112" rx="22" fill="#131C2E" stroke="#38BDF8" stroke-width="4"/>
        <path d="M64 24L96 38V62C96 84 82 100 64 106C46 100 32 84 32 62V38L64 24Z" fill="rgba(56,189,248,0.16)" stroke="#10B981" stroke-width="5"/>
        <text x="64" y="73" text-anchor="middle" font-family="monospace" font-weight="bold" font-size="30" fill="#E2E8F0">VG</text>
      </svg>`;
      return new Response(svg, {
        headers: {
          "Content-Type": "image/svg+xml; charset=utf-8",
          "Cache-Control": "public, max-age=86400",
        },
      });
    }

    // 2. Apple Native L2TP/IPsec `.mobileconfig` Route
    //    NOTE: Deliberately omits `Content-Disposition: attachment` and uses a `.mobileconfig`
    //    URL suffix + `Content-Type: application/x-apple-aspen-config` so iOS Safari launches
    //    native Settings -> Profile Downloaded -> Install directly instead of saving to Files!
    if ((path.startsWith("/profiles/") && path.endsWith(".mobileconfig")) || path === "/api/profile/mobileconfig") {
      const ip = validPublicIpv4(url.searchParams.get("ip") || "");
      if (!ip) {
        return jsonResponse({ ok: false, error: "Valid public IPv4 'ip' parameter is required." }, 400);
      }
      const [countryLong, countryShort] = normalizeCountryPair(
        url.searchParams.get("country") || "",
        url.searchParams.get("cc") || ""
      );
      const dnsList = sanitizeDnsList(url.searchParams.get("dns"));
      const xml = buildAppleL2tpMobileconfig(
        { ip, country_long: countryLong, country_short: countryShort },
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

    // 3. Patched Zero-Prompt OpenVPN `.ovpn` Route
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

      const snap = await getPoolSnapshot(ctx, { forceRefresh: false });
      const found = snap.public_payload.servers.find((s) => s.ip === ip);
      const srv = found
        ? { ...found, ovpn_b64: snap.ovpn_by_ip[ip] || "" }
        : {
            ip,
            country_short: (url.searchParams.get("cc") || "XX").toUpperCase(),
            udp_port: Number(url.searchParams.get("udp")) || 0,
            tcp_port: Number(url.searchParams.get("tcp")) || 0,
            ovpn_b64: snap.ovpn_by_ip[ip] || "",
          };

      const patched = buildPatchedOvpn(srv, snap.donor_ovpn_b64, {
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
      return new Response(patched, {
        status: 200,
        headers: {
          "Content-Type": "application/x-openvpn-profile; charset=utf-8",
          "Content-Disposition": `attachment; filename="${fileName}"`,
          "X-Content-Type-Options": "nosniff",
          "Cache-Control": "no-store",
        },
      });
    }

    // 4. JSON API Endpoints (`/api/servers`, `/api/mirrors`, `/api/probe`, `/api/doctor`)
    if (path === "/api/servers") {
      const forceRefresh = url.searchParams.get("refresh") === "1";
      const customMirror = (url.searchParams.get("mirror") || "").trim();
      const snap = await getPoolSnapshot(ctx, { forceRefresh, customMirror });
      return jsonResponse({ ...snap.public_payload, cached: snap.cached });
    }

    if (path === "/api/mirrors") {
      return handleMirrorsEndpoint(url, ctx);
    }

    if (path === "/api/probe") {
      const ip = validPublicIpv4(url.searchParams.get("ip") || "");
      const port = Number(url.searchParams.get("port") || 0);
      if (!ip || !Number.isInteger(port) || port < 1 || port > 65535) {
        return jsonResponse({ ok: false, error: "Valid public IPv4 'ip' and TCP 'port' are required." }, 400);
      }
      // SSRF / scanner guardrail: allow probing only relays in the active VPN Gate pool or standard VPN ports on pool IPs
      const snap = await getPoolSnapshot(ctx, { forceRefresh: false });
      const inPool = snap.public_payload.servers.find((s) => s.ip === ip);
      if (!inPool && !SAFE_PROBE_PORTS.has(port)) {
        return jsonResponse({ ok: false, error: "Target IP/port is outside verified VPN Gate relay pool." }, 403);
      }
      if (!inPool) {
        return jsonResponse({ ok: false, error: "Target IP is not an active VPN Gate relay." }, 403);
      }
      const res = await probeTcpEdge(ip, port, 2200);
      return jsonResponse({ ok: true, ip, port, ...res });
    }

    if (path === "/api/doctor") {
      return handleDoctorEndpoint(request, ctx);
    }

    // 5. Default SPA Dark Console UI
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
