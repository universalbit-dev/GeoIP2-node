#!/usr/bin/env node
/**
 * GeoIP2-node DNS & Threat Intelligence Scanner (No MMDB)
 *
 *  - simple disk-backed caching for GeoIP and Maltiverse results (TTL configurable)
 *  - Maltiverse API key support via env var MALTIVERSE_API_KEY
 *  - Maltiverse quota limiting and graceful skipping when quota reached
 *
 * Usage:
 *   export MALTIVERSE_API_KEY="your_key"            # optional, for Maltiverse
 *   export GEOIP_PROVIDER="ip-api"                  # optional, defaults to ip-api
 *   export GEOIP_CACHE_TTL_SECS=86400               # optional, default 24h
 *   node geoip.js
 *
 */

const axios = require('axios');
const fs = require('fs');
const path = require('path');

// ====== Config & Lists ======
const GEOIP_PROVIDER = process.env.GEOIP_PROVIDER || 'ip-api'; // 'ip-api' or 'ipinfo' (if token provided)
const GEOIP_PROVIDER_TOKEN = process.env.GEOIP_PROVIDER_TOKEN || process.env.IPINFO_TOKEN || '';
const GEOIP_CACHE_TTL_SECS = parseInt(process.env.GEOIP_CACHE_TTL_SECS || '86400', 10); // 24h default
const CACHE_DIR = path.join(__dirname, 'cache');

const publicDNS = [
  '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4',
  '185.222.222.222', '45.11.45.11', '76.76.2.0', '76.76.10.0',
  '193.110.81.254', '185.253.5.254', '194.242.2.2', '91.239.100.100'
];

const providerDNS = []; // provider/ISP/home DNS list (optional)

// ====== Maltiverse config ======
const MALTIVERSE_API_KEY = process.env.MALTIVERSE_API_KEY || '';
const MALTIVERSE_MAX_REQUESTS = parseInt(process.env.MALTIVERSE_QUOTA_PER_HOUR || '20', 10);
const MALTIVERSE_INTERVAL_MS = parseInt(process.env.MALTIVERSE_INTERVAL_MS || String(60 * 60 * 1000), 10); // 1h

// ====== In-memory state ======
let maltiverseRequestCount = 0;
let maltiverseQuotaExceeded = false;

// ====== Cache helpers ======
function ensureCacheDir() {
  if (!fs.existsSync(CACHE_DIR)) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
  }
}

function cacheFile(name) {
  ensureCacheDir();
  return path.join(CACHE_DIR, name + '.json');
}

function loadCache(name) {
  const file = cacheFile(name);
  try {
    if (fs.existsSync(file)) {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    }
  } catch (e) {
    // ignore parse/read errors and return empty cache
  }
  return {};
}

function saveCache(name, obj) {
  const file = cacheFile(name);
  try {
    fs.writeFileSync(file, JSON.stringify(obj, null, 2), 'utf8');
  } catch (e) {
    console.warn('[WARN] Could not save cache:', file, e.message);
  }
}

function isExpired(entry) {
  if (!entry || !entry._ts) return true;
  const age = Date.now() - entry._ts;
  return age > GEOIP_CACHE_TTL_SECS * 1000;
}

// Load caches
const geoipCache = loadCache('geoip_cache');          // { ip: { _ts: ms, data: {...} } }
const maltiverseCache = loadCache('maltiverse_cache'); // same shape

// Persist caches periodically
setInterval(() => {
  saveCache('geoip_cache', geoipCache);
  saveCache('maltiverse_cache', maltiverseCache);
}, 30 * 1000);

// Save caches on exit
process.on('exit', () => {
  saveCache('geoip_cache', geoipCache);
  saveCache('maltiverse_cache', maltiverseCache);
});
process.on('SIGINT', () => process.exit());
process.on('SIGTERM', () => process.exit());

// ====== Utility ======
function logInfo(msg) {
  console.log(`[${new Date().toISOString()}] [INFO] ${msg}`);
}
function logWarn(msg) {
  console.warn(`[${new Date().toISOString()}] [WARN] ${msg}`);
}
function logErr(msg) {
  console.error(`[${new Date().toISOString()}] [ERROR] ${msg}`);
}

// ====== GeoIP via external providers ======
async function geoipLookupExternal(ip) {
  // Check cache
  const cached = geoipCache[ip];
  if (cached && !isExpired(cached)) {
    return cached.data;
  }

  // Provider implementations
  try {
    let res;
    if (GEOIP_PROVIDER === 'ipinfo' && GEOIP_PROVIDER_TOKEN) {
      // ipinfo.io: GET https://ipinfo.io/<ip>/json?token=TOKEN
      const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json${GEOIP_PROVIDER_TOKEN ? `?token=${GEOIP_PROVIDER_TOKEN}` : ''}`;
      res = await axios.get(url, { timeout: 10_000 });
      // ipinfo returns "org": "AS15169 Google LLC"
      const org = res.data.org || '';
      const parsed = parseAsField(org);
      const out = {
        ip: ip,
        country: (res.data.country || null),
        asn: parsed.asn,
        as_org: parsed.org || res.data.org || null,
        provider: 'ipinfo'
      };
      geoipCache[ip] = { _ts: Date.now(), data: out };
      return out;
    } else {
      // default: ip-api.com (no token)
      // Using http://ip-api.com/json/<ip>?fields=status,country,countryCode,as,org,message
      const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,as,org,message`;
      res = await axios.get(url, { timeout: 10_000 });
      if (res.data && res.data.status === 'success') {
        // res.data.as example: "AS15169 Google LLC"
        const parsed = parseAsField(res.data.as || res.data.org || '');
        const out = {
          ip: ip,
          country: res.data.country || null,
          countryCode: res.data.countryCode || null,
          asn: parsed.asn,
          as_org: parsed.org || res.data.org || null,
          provider: 'ip-api'
        };
        geoipCache[ip] = { _ts: Date.now(), data: out };
        return out;
      } else {
        throw new Error(`geo provider error: ${res.data && res.data.message ? res.data.message : 'unknown'}`);
      }
    }
  } catch (e) {
    logWarn(`GeoIP lookup failed for ${ip}: ${e.message}`);
    // store a lightweight negative cache to avoid repeated failing requests (short TTL)
    geoipCache[ip] = { _ts: Date.now() - (GEOIP_CACHE_TTL_SECS * 500), data: { ip, country: null, asn: null, as_org: null, provider: GEOIP_PROVIDER } };
    return geoipCache[ip].data;
  }
}

function parseAsField(asField) {
  // Attempts to parse "AS15169 Google LLC" into { asn: 15169, org: "Google LLC" }
  if (!asField || typeof asField !== 'string') return { asn: null, org: null };
  const match = asField.match(/AS(\d+)\s*(.*)/i);
  if (match) {
    return { asn: parseInt(match[1], 10), org: match[2] ? match[2].trim() : null };
  }
  // fallback: maybe the value is only a number or only org
  const num = asField.match(/\d+/);
  return { asn: num ? parseInt(num[0], 10) : null, org: asField };
}

// ====== Maltiverse integration with caching and quota ======
function resetMaltiverseQuota() {
  maltiverseRequestCount = 0;
  maltiverseQuotaExceeded = false;
}
setInterval(resetMaltiverseQuota, MALTIVERSE_INTERVAL_MS);
resetMaltiverseQuota(); // start fresh

async function getMaltiverseInfo(ip) {
  // If no API key, skip Maltiverse but mark as skipped
  if (!MALTIVERSE_API_KEY) {
    return { reputation: "Disabled (no API key)", tags: [] };
  }

  // Check cache first
  const cached = maltiverseCache[ip];
  if (cached && !isExpired(cached)) {
    return cached.data;
  }

  if (maltiverseQuotaExceeded || maltiverseRequestCount >= MALTIVERSE_MAX_REQUESTS) {
    maltiverseQuotaExceeded = true;
    return { reputation: "Skipped (API quota limit reached)", tags: [] };
  }

  try {
    // Maltiverse API: GET https://api.maltiverse.com/ip/{ip}
    // Provide Authorization header if required. Some APIs accept Bearer token or x-api-key.
    const headers = {
      'Accept': 'application/json',
      'Authorization': `Bearer ${MALTIVERSE_API_KEY}`,
      'X-API-Key': MALTIVERSE_API_KEY
    };
    const res = await axios.get(`https://api.maltiverse.com/ip/${encodeURIComponent(ip)}`, { headers, timeout: 10_000 });
    maltiverseRequestCount++;
    if (res.status === 200 && res.data) {
      const out = {
        reputation: res.data.reputation || 'unknown',
        tags: Array.isArray(res.data.tags) ? res.data.tags : (res.data.tag ? [res.data.tag] : [])
      };
      maltiverseCache[ip] = { _ts: Date.now(), data: out };
      return out;
    } else {
      return { reputation: "Unknown", tags: [] };
    }
  } catch (e) {
    // Detect quota or 403 responses
    if (e.response && (e.response.status === 403 || e.response.status === 429)) {
      maltiverseQuotaExceeded = true;
      logWarn("[!] Maltiverse API quota or access error. Maltiverse checks will be skipped until the quota resets.");
      return { reputation: "Skipped (API quota/exhausted)", tags: [] };
    }
    if (e.response && e.response.status === 404) {
      const out = { reputation: "Unknown (not in Maltiverse)", tags: [] };
      maltiverseCache[ip] = { _ts: Date.now(), data: out };
      return out;
    }
    return { reputation: "Error", tags: [e.message] };
  }
}

// ====== Core scan & output ======
async function lookupIP(ip) {
  const geo = await geoipLookupExternal(ip);
  const maltiverse = await getMaltiverseInfo(ip);

  console.log(`\nIP: ${ip}`);
  console.log('  ASN:     ', geo.as_org || 'Not found', `(AS${geo.asn || 'N/A'})`);
  console.log('  Country: ', geo.country || 'Not found');
  console.log('  Maltiverse Reputation:', maltiverse.reputation);
  if (maltiverse.tags && maltiverse.tags.length > 0) {
    console.log('  Maltiverse Tags:', maltiverse.tags.join(', '));
  }
}

async function getMyPublicIP() {
  try {
    const res = await axios.get('https://api.ipify.org?format=json', { timeout: 10_000 });
    return res.data.ip;
  } catch (e) {
    logWarn('Could not fetch public IP: ' + e.message);
    return null;
  }
}

let lastIP = null;

async function runGeoIPScan(dnsList, label) {
  logInfo(`GeoIP/Maltiverse scan using provider: ${GEOIP_PROVIDER} (${label})`);
  const myip = await getMyPublicIP();
  if (!myip) return;

  // Only run scan if IP changed (to reduce external calls)
  if (myip !== lastIP) {
    lastIP = myip;
    const ips = Array.from(new Set([myip, ...dnsList]));
    console.log(`\nUsing DNS list: [${label}]`);

    for (const ip of ips) {
      if (maltiverseQuotaExceeded) {
        logWarn("[!] Maltiverse checks are paused due to quota. Only GeoIP lookups will be performed.");
      }
      await lookupIP(ip);
    }
  } else {
    logInfo("No IP change detected, skipping scan.");
  }
}

// ====== Main ======
async function main() {
  logInfo('Starting scanner (no MMDB)');

  // Ensure cache folder exists (persisted caches reduce API hits)
  ensureCacheDir();

  // initial scan
  await runGeoIPScan(publicDNS, 'Public DNS');

  // optional provider/home DNS
  // await runGeoIPScan(providerDNS, 'Provider/Home DNS');

  // periodic check: every hour by default (can be changed by env var)
  const intervalMs = parseInt(process.env.SCAN_INTERVAL_MS || String(60 * 60 * 1000), 10);
  setInterval(async () => {
    try {
      await runGeoIPScan(publicDNS, 'Public DNS');
    } catch (e) {
      logErr('Periodic scan failed: ' + e.message);
    }
  }, intervalMs);
}

main().catch(err => {
  logErr('Fatal error: ' + (err && err.message ? err.message : err));
  process.exit(1);
});
