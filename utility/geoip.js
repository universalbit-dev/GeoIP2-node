#!/usr/bin/env node
/**
 * GeoIP2-node DNS & Threat Intelligence Scanner (No MMDB)
 *
 *  - simple disk-backed caching for GeoIP, Maltiverse, and Spamhaus results (TTL configurable)
 *  - Maltiverse API key support via env var MALTIVERSE_API_KEY
 *  - Maltiverse quota limiting and graceful skipping when quota reached
 *  - Spamhaus DNSBL check via zen.spamhaus.org (no API key required, DNS-based)
 *  - Maltiverse and Spamhaus are ONE-SHOT per IP: results cached, never re-queried in the periodic loop
 *
 * Usage:
 *   export MALTIVERSE_API_KEY="your_key"            # optional, for Maltiverse
 *   export GEOIP_PROVIDER="ip-api"                  # optional, defaults to ip-api
 *   export GEOIP_CACHE_TTL_SECS=86400               # optional, default 24h
 *   node geoip.js                                   # continuous mode
 *   node geoip.js <ip>                              # one-shot mode
 */

const axios = require('axios');
const dns = require('dns').promises;
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, 'utility', '.env') });

// ====== Config & Lists ======
const GEOIP_PROVIDER = process.env.GEOIP_PROVIDER || 'ip-api';
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
const geoipCache      = loadCache('geoip_cache');       // { ip: { _ts: ms, data: {...} } }
const maltiverseCache = loadCache('maltiverse_cache');   // same shape
const spamhausCache   = loadCache('spamhaus_cache');     // same shape

// Persist caches periodically
setInterval(() => {
  saveCache('geoip_cache', geoipCache);
  saveCache('maltiverse_cache', maltiverseCache);
  saveCache('spamhaus_cache', spamhausCache);
}, 30 * 1000);

// Save caches on exit
process.on('exit', () => {
  saveCache('geoip_cache', geoipCache);
  saveCache('maltiverse_cache', maltiverseCache);
  saveCache('spamhaus_cache', spamhausCache);
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
  const cached = geoipCache[ip];
  if (cached && !isExpired(cached)) {
    return cached.data;
  }

  try {
    let res;
    if (GEOIP_PROVIDER === 'ipinfo' && GEOIP_PROVIDER_TOKEN) {
      const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${GEOIP_PROVIDER_TOKEN}`;
      res = await axios.get(url, { timeout: 10_000 });
      const parsed = parseAsField(res.data.org || '');
      const out = {
        ip, country: res.data.country || null,
        asn: parsed.asn, as_org: parsed.org || res.data.org || null,
        provider: 'ipinfo'
      };
      geoipCache[ip] = { _ts: Date.now(), data: out };
      return out;
    } else {
      const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,as,org,message`;
      res = await axios.get(url, { timeout: 10_000 });
      if (res.data && res.data.status === 'success') {
        const parsed = parseAsField(res.data.as || res.data.org || '');
        const out = {
          ip, country: res.data.country || null,
          countryCode: res.data.countryCode || null,
          asn: parsed.asn, as_org: parsed.org || res.data.org || null,
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
    geoipCache[ip] = { _ts: Date.now() - (GEOIP_CACHE_TTL_SECS * 500), data: { ip, country: null, asn: null, as_org: null, provider: GEOIP_PROVIDER } };
    return geoipCache[ip].data;
  }
}

function parseAsField(asField) {
  if (!asField || typeof asField !== 'string') return { asn: null, org: null };
  const match = asField.match(/AS(\d+)\s*(.*)/i);
  if (match) {
    return { asn: parseInt(match[1], 10), org: match[2] ? match[2].trim() : null };
  }
  const num = asField.match(/\d+/);
  return { asn: num ? parseInt(num[0], 10) : null, org: asField };
}

// ====== Maltiverse — ONE-SHOT per IP (result cached, never re-queried in periodic loop) ======
function resetMaltiverseQuota() {
  maltiverseRequestCount = 0;
  maltiverseQuotaExceeded = false;
}
setInterval(resetMaltiverseQuota, MALTIVERSE_INTERVAL_MS);
resetMaltiverseQuota();

async function getMaltiverseInfo(ip) {
  if (!MALTIVERSE_API_KEY) {
    return { reputation: 'Disabled (no API key)', tags: [] };
  }

  // ONE-SHOT: if cached (even expired-but-present), skip re-query in continuous mode
  const cached = maltiverseCache[ip];
  if (cached) {
    return cached.data; // always return cached result — no repeat calls
  }

  if (maltiverseQuotaExceeded || maltiverseRequestCount >= MALTIVERSE_MAX_REQUESTS) {
    maltiverseQuotaExceeded = true;
    return { reputation: 'Skipped (API quota limit reached)', tags: [] };
  }

  try {
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
    }
    return { reputation: 'Unknown', tags: [] };
  } catch (e) {
    if (e.response && (e.response.status === 403 || e.response.status === 429)) {
      maltiverseQuotaExceeded = true;
      logWarn('[!] Maltiverse API quota or access error. Skipping until quota resets.');
      return { reputation: 'Skipped (API quota/exhausted)', tags: [] };
    }
    if (e.response && e.response.status === 404) {
      const out = { reputation: 'Unknown (not in Maltiverse)', tags: [] };
      maltiverseCache[ip] = { _ts: Date.now(), data: out };
      return out;
    }
    return { reputation: 'Error', tags: [e.message] };
  }
}

// ====== Spamhaus DNSBL — ONE-SHOT per IP via zen.spamhaus.org (DNS, no API key needed) ======
// Return codes: 127.0.0.2=SBL, 127.0.0.3=SBL-CSS, 127.0.0.4-7=XBL, 127.0.0.10-11=PBL
const SPAMHAUS_CODES = {
  '127.0.0.2':  'SBL (Spamhaus Block List)',
  '127.0.0.3':  'SBL-CSS (Spamhaus CSS)',
  '127.0.0.4':  'XBL (Exploits Block List)',
  '127.0.0.5':  'XBL (Exploits Block List)',
  '127.0.0.6':  'XBL (Exploits Block List)',
  '127.0.0.7':  'XBL (Exploits Block List)',
  '127.0.0.10': 'PBL (Policy Block List - ISP)',
  '127.0.0.11': 'PBL (Policy Block List - Spamhaus)',
};

async function getSpamhausInfo(ip) {
  // Skip IPv6 — Spamhaus ZEN is IPv4 only
  if (ip.includes(':')) {
    return { listed: false, codes: [], note: 'IPv6 not supported by zen.spamhaus.org' };
  }

  // ONE-SHOT: always return cached result if present, no repeat DNS queries
  const cached = spamhausCache[ip];
  if (cached) {
    return cached.data;
  }

  const reversed = ip.split('.').reverse().join('.');
  const query = `${reversed}.zen.spamhaus.org`;

  try {
    const addresses = await dns.resolve4(query);
    const codes = addresses.map(a => SPAMHAUS_CODES[a] || `Listed (${a})`);
    const out = { listed: true, codes };
    spamhausCache[ip] = { _ts: Date.now(), data: out };
    return out;
  } catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') {
      const out = { listed: false, codes: [] };
      spamhausCache[ip] = { _ts: Date.now(), data: out };
      return out;
    }
    logWarn(`Spamhaus DNS lookup failed for ${ip}: ${e.message}`);
    return { listed: null, codes: [], note: `DNS error: ${e.message}` };
  }
}

// ====== Core scan & output ======
async function lookupIP(ip) {
  const geo        = await geoipLookupExternal(ip);
  const maltiverse = await getMaltiverseInfo(ip);
  const spamhaus   = await getSpamhausInfo(ip);

  console.log(`\nIP: ${ip}`);
  console.log('  ASN:     ', geo.as_org || 'Not found', `(AS${geo.asn || 'N/A'})`);
  console.log('  Country: ', geo.country || 'Not found');
  console.log('  Maltiverse Reputation:', maltiverse.reputation);
  if (maltiverse.tags && maltiverse.tags.length > 0) {
    console.log('  Maltiverse Tags:', maltiverse.tags.join(', '));
  }
  if (spamhaus.listed === true) {
    console.log('  Spamhaus DNSBL: LISTED -', spamhaus.codes.join(', '));
  } else if (spamhaus.listed === false) {
    console.log('  Spamhaus DNSBL: Clean');
  } else {
    console.log('  Spamhaus DNSBL:', spamhaus.note || 'Unknown');
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

  if (myip !== lastIP) {
    lastIP = myip;
    const ips = Array.from(new Set([myip, ...dnsList]));
    console.log(`\nUsing DNS list: [${label}]`);
    for (const ip of ips) {
      if (maltiverseQuotaExceeded) {
        logWarn('[!] Maltiverse checks are paused due to quota. Only GeoIP + Spamhaus lookups will be performed.');
      }
      await lookupIP(ip);
    }
  } else {
    logInfo('No IP change detected, skipping scan.');
  }
}

// ====== Main ======
async function main() {
  logInfo('Starting scanner (no MMDB)');
  ensureCacheDir();

  // Support one-shot mode: node geoip.js <ip>
  const targetIP = process.argv[2];
  if (targetIP) {
    logInfo(`One-shot lookup for: ${targetIP}`);
    await lookupIP(targetIP);
    saveCache('geoip_cache', geoipCache);
    saveCache('maltiverse_cache', maltiverseCache);
    saveCache('spamhaus_cache', spamhausCache);
    process.exit(0);
    return;
  }

  // Continuous mode: initial scan + hourly interval
  // NOTE: Maltiverse and Spamhaus are ONE-SHOT — cached results are reused, no repeat API/DNS calls
  await runGeoIPScan(publicDNS, 'Public DNS');
  // await runGeoIPScan(providerDNS, 'Provider/Home DNS');

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
