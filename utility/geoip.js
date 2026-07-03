#!/usr/bin/env node
/**
 * GeoIP2-node Full-Stack State Change Telemetry Agent (No MMDB)
 *
 * Integrated Structural Architecture:
 *  1. Continuous Stateful Daemon Loop tracking mutations over time.
 *  2. Suppressed console noise — prints ONLY baseline and immediate delta shifts.
 *  3. MxToolbox-Style Multi-RBL Blacklist Engine using native OS lookups.
 *  4. Validity SenderScore parser translating keyless return headers to numerical scores (0-100).
 *  5. Brand Reputation Guard via PhishDestroy keyless API integration.
 *  6. Domain Rank Metrics Layer auditing public identity alignments (SPF, DMARC, MX).
 *  7. Native Crypto SSL/TLS Certificate Expiration & Validity Analyzer.
 *  8. Automated Network Layer Port Scanner inspecting common boundary exposures (22, 80, 443, 3389).
 *  9. Privacy-Preserving Friendly Tracking Layer classifying user intent.
 */

const axios = require('axios');
const dns = require('dns').promises;
const fs = require('fs');
const path = require('path');
const net = require('net');
const tls = require('tls');
require('dotenv').config({ path: path.join(__dirname, 'utility', '.env') });

// ====== UI Interface: Native ANSI Escapes ======
const C_RESET = '\x1b[0m';
const C_RED = '\x1b[31m';
const C_GREEN = '\x1b[32m';
const C_YELLOW = '\x1b[33m';
const C_CYAN = '\x1b[36m';
const C_GRAY = '\x1b[90m';
const C_BOLD = '\x1b[1m';

// ====== Core Configuration Setup ======
const GEOIP_PROVIDER = process.env.GEOIP_PROVIDER || 'ip-api';
const GEOIP_PROVIDER_TOKEN = process.env.GEOIP_PROVIDER_TOKEN || process.env.IPINFO_TOKEN || '';
const GEOIP_CACHE_TTL_SECS = parseInt(process.env.GEOIP_CACHE_TTL_SECS || '86400', 10); 
const CACHE_DIR = path.join(__dirname, 'cache');

const publicDNS = [
  '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4',
  '185.222.222.222', '45.11.45.11', '76.76.2.0', '76.76.10.0',
  '193.110.81.254', '185.253.5.254', '194.242.2.2', '91.239.100.100'
];

const INFRASTRUCTURE_IPS = new Set([...publicDNS, '9.9.9.9', '149.112.112.112']);

// ====== External Threat Intel Credentials ======
const MALTIVERSE_API_KEY = process.env.MALTIVERSE_API_KEY || '';
const MALTIVERSE_MAX_REQUESTS = parseInt(process.env.MALTIVERSE_QUOTA_PER_HOUR || '20', 10);
const MALTIVERSE_INTERVAL_MS = parseInt(process.env.MALTIVERSE_INTERVAL_MS || String(60 * 60 * 1000), 10); 
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY || '';

let maltiverseRequestCount = 0;
let maltiverseQuotaExceeded = false;

// ====== Global Persistent In-Memory State Daemon Map ======
let previousNetworkState = null;

const RBL_DESCRIPTIONS = {
  'score.senderscore.com': 'Validity SenderScore Matrix',
  'zen.spamhaus.org': 'Spamhaus Unified Threat List',
  'bl.spamcop.net': 'SpamCop Dynamic Spam Tracker',
  'ix.dnsbl.manitu.net': 'Manitu NiX Spam (Europe)',
  'b.barracudacentral.org': 'Barracuda Enterprise Filter'
};

const SPAMHAUS_CODES = {
  '127.0.0.2': 'SBL (Verified Spam Origin)', 
  '127.0.0.3': 'SBL-CSS (Abusive Behavior)',
  '127.0.0.4': 'XBL (Active Botnet Node)', 
  '127.0.0.5': 'XBL (Malware Host)',
  '127.0.0.10': 'PBL (ISP Dynamic Client IP)', 
  '127.255.255.254': 'Resolver Rejected'
};

// ====== Storage Cache Drivers ======
function ensureCacheDir() {
  if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
}

function cacheFile(name) {
  ensureCacheDir();
  return path.join(CACHE_DIR, `${name}.json`);
}

function loadCache(name) {
  const file = cacheFile(name);
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {}
  return {};
}

function saveCache(name, obj) {
  const file = cacheFile(name);
  try {
    fs.writeFileSync(file, JSON.stringify(obj, null, 2), 'utf8');
  } catch (e) {}
}

function isExpired(entry) {
  if (!entry || !entry._ts) return true;
  return (Date.now() - entry._ts) > (GEOIP_CACHE_TTL_SECS * 1000);
}

const geoipCache      = loadCache('geoip_cache');       
const maltiverseCache = loadCache('maltiverse_cache');   
const blacklistCache  = loadCache('blacklist_cache');     
const abuseCache      = loadCache('abuse_cache');

setInterval(() => {
  saveCache('geoip_cache', geoipCache);
  saveCache('maltiverse_cache', maltiverseCache);
  saveCache('blacklist_cache', blacklistCache);
  saveCache('abuse_cache', abuseCache);
}, 30 * 1000);

const handleExit = () => {
  saveCache('geoip_cache', geoipCache);
  saveCache('maltiverse_cache', maltiverseCache);
  saveCache('blacklist_cache', blacklistCache);
  saveCache('abuse_cache', abuseCache);
  process.exit();
};
process.on('exit', handleExit);
process.on('SIGINT', handleExit);
process.on('SIGTERM', handleExit);

function logHeader(title) {
  console.log(`\n${C_BOLD}${C_CYAN}=== ${title} ===${C_RESET}`);
}
function logErr(msg) { console.error(`${C_RED}[ERROR] ${msg}${C_RESET}`); }

// ====== Module 1: PhishDestroy Engine ======
async function queryPhishDestroy(domain) {
  try {
    const url = `https://api.destroy.tools/v1/check?domain=${encodeURIComponent(domain)}`;
    const res = await axios.get(url, { timeout: 5000 });
    if (res.data) {
      return {
        threat: res.data.threat || false,
        riskScore: res.data.risk_score || 0,
        severity: res.data.severity || 'clean'
      };
    }
  } catch (e) {
    return { threat: false, riskScore: 0, severity: 'unlisted' };
  }
  return null;
}

// ====== Module 2: DNS Identity & Trust Record Auditor ======
async function auditDomainDNS(domain) {
  const report = { spf: null, dmarc: null, mx: [] };
  try {
    const txtRecords = await dns.resolveTxt(domain).catch(() => []);
    const spfRecord = txtRecords.flat().find(r => r.startsWith('v=spf1'));
    report.spf = spfRecord || null;
  } catch (e) {}

  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`).catch(() => []);
    const dmarcRecord = dmarcRecords.flat().find(r => r.startsWith('v=DMARC1'));
    report.dmarc = dmarcRecord || null;
  } catch (e) {}

  try {
    const mxRecords = await dns.resolveMx(domain).catch(() => []);
    report.mx = mxRecords.map(r => `${r.exchange} (Priority: ${r.priority})`);
  } catch (e) {}
  return report;
}

// ====== Module 3: Native Crypto SSL/TLS Certificate Auditor ======
function auditSSLCertificate(domain) {
  return new Promise((resolve) => {
    const options = { servername: domain, timeout: 3000, rejectUnauthorized: false };
    
    const socket = tls.connect(443, domain, options, () => {
      const cert = socket.getPeerCertificate();
      socket.destroy();
      
      if (cert && cert.valid_to) {
        const daysRemaining = Math.round((new Date(cert.valid_to) - new Date()) / (1000 * 60 * 60 * 24));
        resolve({
          issuer: cert.issuer?.O || 'Unknown Authority',
          validTo: cert.valid_to,
          daysRemaining: daysRemaining
        });
      } else {
        resolve({ error: 'No verifiable certificate handshake returned' });
      }
    });

    socket.on('error', (err) => resolve({ error: `Connection failed (${err.message})` }));
    socket.on('timeout', () => { socket.destroy(); resolve({ error: 'Connection Timed Out' }); });
  });
}

// ====== Module 4: Geographical Tracker Boundaries ======
async function geoipLookupExternal(ip) {
  const cached = geoipCache[ip];
  if (cached && !isExpired(cached)) return cached.data;

  try {
    let out;
    if (GEOIP_PROVIDER === 'ipinfo' && GEOIP_PROVIDER_TOKEN) {
      const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${GEOIP_PROVIDER_TOKEN}`;
      const res = await axios.get(url, { timeout: 10_000 });
      const parsed = parseAsField(res.data.org || '');
      out = {
        ip, country: res.data.country || null,
        asn: parsed.asn, as_org: parsed.org || res.data.org || null,
        provider: 'ipinfo'
      };
    } else {
      const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,as,org,message`;
      const res = await axios.get(url, { timeout: 10_000 });
      if (res.data && res.data.status === 'success') {
        const parsed = parseAsField(res.data.as || res.data.org || '');
        out = {
          ip, country: res.data.country || null,
          countryCode: res.data.countryCode || null,
          asn: parsed.asn, as_org: parsed.org || res.data.org || null,
          provider: 'ip-api'
        };
      } else {
        throw new Error(`Geo provider fault: ${res.data?.message || 'unknown'}`);
      }
    }
    geoipCache[ip] = { _ts: Date.now(), data: out };
    return out;
  } catch (e) {
    // Graceful degrade fallback execution (Circuit Breaker baseline)
    const fallbackData = { ip, country: 'Unknown Jurisdiction', asn: null, as_org: 'Circuit Breaker Fallback Active', provider: GEOIP_PROVIDER };
    geoipCache[ip] = { _ts: Date.now() - (GEOIP_CACHE_TTL_SECS * 500), data: fallbackData };
    return fallbackData;
  }
}

function parseAsField(asField) {
  if (!asField || typeof asField !== 'string') return { asn: null, org: null };
  const match = asField.match(/AS(\d+)\s*(.*)/i);
  if (match) return { asn: parseInt(match[1], 10), org: match[2] ? match[2].trim() : null };
  const num = asField.match(/\d+/);
  return { asn: num ? parseInt(num[0], 10) : null, org: asField };
}

// ====== Module 5: Intelligence Telemetry ======
async function getMaltiverseInfo(ip) {
  if (!MALTIVERSE_API_KEY) return { reputation: 'Disabled (No Key Configured)', tags: [] };
  const cached = maltiverseCache[ip];
  if (cached) return cached.data; 

  if (maltiverseQuotaExceeded || maltiverseRequestCount >= MALTIVERSE_MAX_REQUESTS) {
    maltiverseQuotaExceeded = true;
    return { reputation: 'Hourly API Quota Target Exhausted', tags: [] };
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
    return { reputation: 'Unclassified Asset', tags: [] };
  } catch (e) {
    if (e.response && (e.response.status === 403 || e.response.status === 429)) {
      maltiverseQuotaExceeded = true;
      return { reputation: 'API Token Quota Exhausted', tags: [] };
    }
    if (e.response && e.response.status === 404) {
      const out = { reputation: 'No active threat markers found', tags: [] };
      maltiverseCache[ip] = { _ts: Date.now(), data: out };
      return out;
    }
    return { reputation: 'Request Execution Error', tags: [e.message] };
  }
}

async function getAbuseIPDBInfo(ip) {
  if (!ABUSEIPDB_API_KEY) return { score: 'Disabled (No Key Configured)', reports: 0 };
  const cached = abuseCache[ip];
  if (cached && !isExpired(cached)) return cached.data;

  try {
    const res = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      headers: { 'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json' },
      params: { ipAddress: ip, maxAgeInDays: 90 },
      timeout: 5000
    });
    if (res.data && res.data.data) {
      const out = { score: `${res.data.data.abuseConfidenceScore}%`, reports: res.data.data.totalReports };
      abuseCache[ip] = { _ts: Date.now(), data: out };
      return out;
    }
  } catch (e) {
    return { score: 'Lookup Failed', reports: 0 };
  }
  return { score: 'Unknown', reports: 0 };
}

// ====== Module 6: Enterprise Multi-RBL Matrix (OS Native Lookups) ======
function pingSingleRBL(reversedIP, rblZone, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ zone: rblZone, listed: null, detail: 'Timeout' }), timeoutMs);
    const query = `${reversedIP}.${rblZone}`;

    dns.lookup(query)
      .then(lookupResult => {
        clearTimeout(timer);
        const resolvedAddress = lookupResult.address;
        
        if (rblZone === 'score.senderscore.com') {
          const octets = resolvedAddress.split('.');
          const score = parseInt(octets[3], 10);
          let colorCode = C_GREEN;
          if (score < 70) colorCode = C_RED;
          else if (score < 85) colorCode = C_YELLOW;
          
          resolve({ zone: rblZone, listed: true, detail: `Reputation Rank: ${colorCode}${score}/100${C_RESET}`, rawValue: score });
          return;
        }

        if (rblZone === 'zen.spamhaus.org' && SPAMHAUS_CODES[resolvedAddress]) {
          resolve({ zone: rblZone, listed: true, detail: SPAMHAUS_CODES[resolvedAddress], code: resolvedAddress, rawValue: resolvedAddress });
          return;
        }

        resolve({ zone: rblZone, listed: true, detail: `Flagged (${resolvedAddress})`, rawValue: resolvedAddress });
      })
      .catch(err => {
        clearTimeout(timer);
        const clean = (err.code === 'ENOTFOUND' || err.code === 'ENODATA');
        
        if (clean) {
          const detailString = rblZone === 'score.senderscore.com' ? 'Clean (No Negative History Profile)' : '✓ Clean';
          resolve({ zone: rblZone, listed: false, detail: detailString, rawValue: 'clean' });
        } else {
          resolve({ zone: rblZone, listed: null, detail: `Blocked/Dropped (${err.code})`, rawValue: 'error' });
        }
      });
  });
}

async function getMultiRBLMatrix(ip) {
  if (ip.includes(':')) return [];
  if (INFRASTRUCTURE_IPS.has(ip)) return [];

  const cached = blacklistCache[ip];
  if (cached && !isExpired(cached)) return cached.data;

  const reversedIP = ip.split('.').reverse().join('.');
  const targetZones = [
    'score.senderscore.com',
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'ix.dnsbl.manitu.net',
    'b.barracudacentral.org'
  ];

  const results = await Promise.all(targetZones.map(zone => pingSingleRBL(reversedIP, zone, 3000)));
  blacklistCache[ip] = { _ts: Date.now(), data: results };
  return results;
}

// ====== Module 7: Public Perimeter Port Exposure Scanner ======
function probeSinglePort(ip, port, timeoutMs = 1200) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isOpen = false;
    let state = `${C_GREEN}Closed / Secure${C_RESET}`;

    socket.setTimeout(timeoutMs);
    socket.connect(port, ip, () => {
      isOpen = true;
      state = `${C_RED}${C_BOLD}OPEN ⚠️ (Publicly Exposed)${C_RESET}`;
      socket.destroy();
    });

    socket.on('timeout', () => { socket.destroy(); });
    socket.on('error', () => { socket.destroy(); });
    socket.on('close', () => resolve({ port, state, isOpen }));
  });
}

async function auditExposedPorts(ip) {
  if (INFRASTRUCTURE_IPS.has(ip)) return [];
  const commonPorts = [22, 80, 443, 3389];
  return Promise.all(commonPorts.map(port => probeSinglePort(ip, port, 1200)));
}

// ====== Module 8: Privacy-Preserving Friendly Tracking Classifier ======
function classifyPrivacyContext(maltiverse, abuseDb, rblMatrix) {
  const abuseScore = parseInt(abuseDb.score) || 0;
  const isListedInRBL = rblMatrix.some(r => r.listed === true && r.zone !== 'score.senderscore.com');
  const tags = maltiverse.tags || [];

  // Identify privacy-conscious users instead of treating them as immediate threats
  const isVpnOrTor = tags.includes('vpn') || tags.includes('tor') || tags.includes('proxy');

  if (abuseScore > 75 || (isListedInRBL && maltiverse.reputation === 'bad')) {
    return {
      category: 'MALICIOUS_THREAT',
      action: 'MITIGATE / BLOCK',
      color: C_RED,
      description: 'Host exhibits active malicious behavior signatures.'
    };
  }

  if (isVpnOrTor || tags.includes('hosting')) {
    return {
      category: 'PRIVACY_PRESERVING_USER',
      action: 'ALLOW WITH PRIVACY MODE',
      color: C_YELLOW,
      description: 'Legitimate user safeguarding identities via VPN/Tor/Proxy networks.'
    };
  }

  return {
    category: 'STANDARD_CLEAN_TRAFFIC',
    action: 'PASS',
    color: C_GREEN,
    description: 'Verified residential or corporate operational boundary layer.'
  };
}

// ====== Programmatic Snapshot Export Handler ======
function exportTelemetrySnapshot(ip, classification, geo) {
  const telemetryPath = path.join(CACHE_DIR, 'latest_telemetry.json');
  const snapshot = {
    timestamp: new Date().toISOString(),
    target_ip: ip,
    carrier: geo.as_org,
    jurisdiction: geo.country,
    friendly_tracking: {
      category: classification.category,
      recommended_action: classification.action,
      profile: classification.description
    }
  };
  fs.writeFileSync(telemetryPath, JSON.stringify(snapshot, null, 2), 'utf8');
}

// ====== Compilation Report Matrix Output Generation ======
async function generateAuditReport(ip, phishIntel = null, dnsAudit = null, sslAudit = null, label = null, isDaemonLoop = false) {
  const [geo, maltiverse, abuseDb, rblMatrix, portScan] = await Promise.all([
    geoipLookupExternal(ip),
    getMaltiverseInfo(ip),
    getAbuseIPDBInfo(ip),
    getMultiRBLMatrix(ip),
    auditExposedPorts(ip)
  ]);

  const privacyClassification = classifyPrivacyContext(maltiverse, abuseDb, rblMatrix);
  exportTelemetrySnapshot(ip, privacyClassification, geo);

  // Build a lightweight state tracking map object for mutation evaluation[cite: 1]
  const currentScanState = {
    ip: ip,
    ports: portScan.map(p => `${p.port}:${p.isOpen}`).join('|'),
    blacklists: rblMatrix.map(r => `${r.zone}:${r.rawValue}`).join('|')
  };

  // If running in active background daemon mode, perform state mutation check[cite: 1]
  if (isDaemonLoop && previousNetworkState) {
    const ipChanged = previousNetworkState.ip !== currentScanState.ip;
    const portsChanged = previousNetworkState.ports !== currentScanState.ports;
    const rblChanged = previousNetworkState.blacklists !== currentScanState.blacklists;

    if (!ipChanged && !portsChanged && !rblChanged) {
      // Suppress logging entirely — network boundary state matches exact baseline fingerprint.[cite: 1]
      return;
    }

    // A delta shift has occurred! Issue immediate notification header.[cite: 1]
    console.log(`\n🚨 ${C_RED}${C_BOLD}[STATE MUTATION DETECTED] — Network perimeter boundaries modified at ${new Date().toISOString()}${C_RESET}`);
  }

  // Update background telemetry cache[cite: 1]
  if (isDaemonLoop) {
    previousNetworkState = currentScanState;
  }

  let buffer = `\n${C_BOLD}${C_CYAN}📍 TARGET: ${label ? `${label} (${ip})` : ip}${C_RESET}\n`;
  
  // Friendly Tracking Intercept Section
  buffer += `  ${C_BOLD}🛡️ Friendly Tracking Classification:${C_RESET}\n`;
  buffer += `    Category:        ${privacyClassification.color}${C_BOLD}${privacyClassification.category}${C_RESET}\n`;
  buffer += `    Action:          ${privacyClassification.color}${privacyClassification.action}${C_RESET}\n`;
  buffer += `    Profile Context: ${C_GRAY}${privacyClassification.description}${C_RESET}\n\n`;

  if (phishIntel) {
    buffer += `  ${C_BOLD}🛡️ Brand Asset Protection (PhishDestroy):${C_RESET}\n`;
    if (phishIntel.threat) {
      buffer += `    Status:          ${C_RED}${C_BOLD}⚠️ WARNING / PHISHING PATTERN DETECTED${C_RESET}\n`;
      buffer += `    Risk Index Score:${C_RED} ${phishIntel.riskScore} / 100${C_RESET}\n`;
      buffer += `    Threat Profile:  ${C_RED} ${phishIntel.severity.toUpperCase()}${C_RESET}\n`;
    } else {
      buffer += `    Status:          ${C_GREEN}✓ Clear / Safe Asset Entry${C_RESET}\n`;
    }
  }

  if (dnsAudit) {
    buffer += `  ${C_BOLD}🔑 DNS Trust & Identity Alignment (Domain Rank Metrics):${C_RESET}\n`;
    buffer += `    SPF Record:      ${dnsAudit.spf ? `${C_GREEN}Found (${dnsAudit.spf})${C_RESET}` : `${C_RED}Missing (Damages Domain Trust Rank)${C_RESET}`}\n`;
    buffer += `    DMARC Record:    ${dnsAudit.dmarc ? `${C_GREEN}Found (${dnsAudit.dmarc})${C_RESET}` : `${C_RED}Missing (Vulnerable to Brand Spoofing/Spam Flags)${C_RESET}`}\n`;
    buffer += `    MX Mail Exchanger: ${dnsAudit.mx.length > 0 ? dnsAudit.mx.join(', ') : `${C_GRAY}None configured${C_RESET}`}\n`;
  }

  if (sslAudit) {
    buffer += `  ${C_BOLD}🔒 SSL/TLS Security Certification Validity (SEO Rank Catalyst):${C_RESET}\n`;
    if (sslAudit.error) {
      buffer += `    Status:          ${C_RED}Failed — ${sslAudit.error}${C_RESET}\n`;
    } else {
      const dayColor = sslAudit.daysRemaining < 15 ? C_RED : (sslAudit.daysRemaining < 30 ? C_YELLOW : C_GREEN);
      buffer += `    Authority CA:    ${sslAudit.issuer}\n`;
      buffer += `    Days Remaining:  ${dayColor}${sslAudit.daysRemaining} days remaining${C_RESET} (Valid until: ${sslAudit.validTo})\n`;
    }
  }

  buffer += `  ${C_BOLD}🌐 Routing Profile & Geolocation (Privacy Boundary Audit):${C_RESET}\n`;
  buffer += `    Carrier/ISP:     ${geo.as_org || 'Not identified'} (AS${geo.asn || 'N/A'})\n`;
  buffer += `    Country:         ${geo.country || 'Not identified'}\n`;
  
  if (portScan && portScan.length > 0) {
    buffer += `  ${C_BOLD}🚪 Public Perimeter Port Exposure Probe (Privacy Leak Check):${C_RESET}\n`;
    for (const probe of portScan) {
      buffer += `    ↳ Port [${String(probe.port).padEnd(4)}] : ${probe.state}\n`;
    }
  }

  buffer += `  ${C_BOLD}🧠 Cyber Threat Intel Telemetry (Maltiverse & AbuseIPDB):${C_RESET}\n`;
  buffer += `    Maltiverse Index: ${maltiverse.reputation}\n`;
  if (maltiverse.tags?.length > 0) buffer += `    Identified Tags:  ${C_YELLOW}${maltiverse.tags.join(', ')}${C_RESET}\n`;
  const isAbused = parseInt(abuseDb.score) > 0;
  buffer += `    AbuseIPDB Score:  ${isAbused ? `${C_RED}${abuseDb.score}${C_RESET}` : `${C_GREEN}${abuseDb.score}${C_RESET}`} (${abuseDb.reports} recent reports)\n`;
  
  buffer += `  ${C_BOLD}📊 Real-time Multi-RBL Reputation Matrix (MxToolbox Style):${C_RESET}\n`;
  if (Array.isArray(rblMatrix) && rblMatrix.length > 0) {
    for (const rbl of rblMatrix) {
      const labelName = RBL_DESCRIPTIONS[rbl.zone] || rbl.zone;
      let statusString = `${C_GREEN}${rbl.detail}${C_RESET}`;
      
      if (rbl.listed === true) {
        if (rbl.zone === 'score.senderscore.com') {
          statusString = rbl.detail; 
        } else {
          const isPBL = rbl.code === '127.0.0.10' || rbl.code === '127.0.0.11';
          const color = isPBL ? C_YELLOW : `${C_RED}${C_BOLD}`;
          statusString = `${color}LISTED INDICATOR (${rbl.detail})${C_RESET}`;
        }
      } else if (rbl.listed === null) {
        statusString = `${C_GRAY}${rbl.detail}${C_RESET}`;
      }
      buffer += `    ↳ [${labelName.padEnd(30)}] : ${statusString}\n`;
    }
  } else {
    buffer += `    ${C_GRAY}Skipped or Unsupported for this destination asset type.${C_RESET}\n`;
  }

  console.log(buffer);
}

async function getMyPublicIP() {
  try {
    const res = await axios.get('https://api.ipify.org?format=json', { timeout: 10_000 });
    return res.data.ip;
  } catch (e) { return null; }
}

// ====== Loop Operational Flow Driver ======
async function main() {
  ensureCacheDir();
  const argument = process.argv[2];

  if (argument) {
    let targetIP = argument;
    let phishIntel = null;
    let dnsAudit = null;
    let sslAudit = null;
    let label = null;

    if (!net.isIP(argument)) {
      logHeader(`ASSET CORE PROTECTION AUDIT: ${argument}`);
      [phishIntel, dnsAudit, sslAudit] = await Promise.all([
        queryPhishDestroy(argument),
        auditDomainDNS(argument),
        auditSSLCertificate(argument)
      ]);
      try {
        label = argument;
        const resolvedAddresses = await dns.resolve4(argument);
        if (resolvedAddresses && resolvedAddresses.length > 0) {
          targetIP = resolvedAddresses[0];
        } else {
          throw new Error('No DNS A records populated.');
        }
      } catch (err) {
        logErr(`DNS Resolution failed for domain [${argument}]: ${err.message}`);
        process.exit(1);
      }
    } else { 
      logHeader(`IP PERIMETER AD-HOC QUOTATION SCAN`); 
    }

    await generateAuditReport(targetIP, phishIntel, dnsAudit, sslAudit, label, false);
    process.exit(0);
    return;
  }

  logHeader("LOCAL BOUNDARY PRIVACY & NETWORK REPUTATION DAEMON (STATEFUL)");
  const myip = await getMyPublicIP();
  if (myip) {
    // Run initial baseline report scan and establish baseline footprint state matrix configuration[cite: 1]
    await generateAuditReport(myip, null, null, null, "Your Current Interface Public IP", true);
  }

  const intervalMs = parseInt(process.env.SCAN_INTERVAL_MS || String(60 * 60 * 1000), 10);
  setInterval(async () => {
    const currentIP = await getMyPublicIP();
    if (currentIP) {
      // Run continuous loop monitoring — will remain entirely silent unless a state delta shift is intercepted[cite: 1]
      await generateAuditReport(currentIP, null, null, null, "Continuous Delta Monitoring Scan", true);
    }
  }, intervalMs);
}

main().catch(err => {
  logErr(`Fatal processing termination anomaly: ${err.message}`);
  process.exit(1);
});
