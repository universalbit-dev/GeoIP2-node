#!/usr/bin/env node
/**
 * GeoIP2-node DNS & Threat Intelligence Scanner
 * 
 * - Uses MaxMind GeoIP2 databases (ASN, Country)
 * - Looks up public and provider DNS IPs
 * - Integrates with Maltiverse for threat reputation (with request limiting)
 * - Requires geolite.config.js and MaxMind .mmdb files as specified by config
 * 
 * Usage: node geoip.js
 * 
 * Dependencies: maxmind, axios, path, fs
 */

const maxmind = require('maxmind');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const config = require('./geolite_nocitydb.config.js');

// ====== DNS Lists ======
const publicDNS = [
  '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4',
  '185.222.222.222', '45.11.45.11', '76.76.2.0', '76.76.10.0',
  '193.110.81.254', '185.253.5.254', '194.242.2.2', '91.239.100.100'
];
// ====== Add your Provider/ISP/Home DNS Lists ======  
const providerDNS = [];

// ====== Maltiverse Request Limiting ======
const MALTIVERSE_MAX_REQUESTS = 20;        // Max queries per interval
const MALTIVERSE_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
let maltiverseRequestCount = 0;
let maltiverseQuotaExceeded = false;
let maltiverseResetTimeout = null;

// ====== IP Change Detection ======
let lastIP = null;

// ====== Helper Functions ======
async function getMyPublicIP() {
  try {
    const res = await axios.get('https://api.ipify.org?format=json');
    return res.data.ip;
  } catch (e) {
    console.error('Could not fetch public IP:', e.message);
    return null;
  }
}

function resetMaltiverseQuota() {
  maltiverseRequestCount = 0;
  maltiverseQuotaExceeded = false;
  maltiverseResetTimeout = setTimeout(resetMaltiverseQuota, MALTIVERSE_INTERVAL_MS);
}

// ====== Maltiverse threat intelligence lookup ======
async function getMaltiverseInfo(ip) {
  if (maltiverseQuotaExceeded || maltiverseRequestCount >= MALTIVERSE_MAX_REQUESTS) {
    maltiverseQuotaExceeded = true;
    return { reputation: "Skipped (API quota limit reached)", tags: [] };
  }
  try {
    const res = await axios.get(`https://api.maltiverse.com/ip/${ip}`);
    maltiverseRequestCount++;
    if (res.status === 200 && res.data) {
      return {
        reputation: res.data.reputation,
        tags: res.data.tags || [],
      };
    }
    return { reputation: "Unknown", tags: [] };
  } catch (e) {
    if ((e.response && e.response.status === 403) ||
        (e.response && e.response.data && typeof e.response.data === 'string' && e.response.data.toLowerCase().includes('quota'))) {
      maltiverseQuotaExceeded = true;
      console.error("[!] Maltiverse API quota exceeded. Maltiverse checks will be skipped until the quota resets.");
      return { reputation: "Skipped (API quota exceeded)", tags: [] };
    }
    if (e.response && e.response.status === 404) {
      return { reputation: "Unknown (not in Maltiverse)", tags: [] };
    }
    return { reputation: "Error", tags: [e.message] };
  }
}

// ====== MaxMind Lookups ======
async function lookupIP(ip, asnLookup, countryLookup) {
  const asn = asnLookup.get(ip);
  const country = countryLookup.get(ip);
  const maltiverse = await getMaltiverseInfo(ip);

  console.log(`\nIP: ${ip}`);
  console.log('  ASN:     ', asn?.autonomous_system_organization || 'Not found', `(AS${asn?.autonomous_system_number || 'N/A'})`);
  console.log('  Country: ', country?.country?.names?.en || 'Not found');
  // City/region lookups are removed
  console.log('  Maltiverse Reputation:', maltiverse.reputation);
  if (maltiverse.tags.length > 0) {
    console.log('  Maltiverse Tags:', maltiverse.tags.join(', '));
  }
}

// ====== Database presence and preparation ======
async function prepareLookups() {
  const dbPaths = {
    asn: path.join(config.mmdbDir, config.asnDb),
    country: path.join(config.mmdbDir, config.countryDb)
  };

  for (const dbPath of Object.values(dbPaths)) {
    if (!fs.existsSync(dbPath)) {
      console.error(`Database not found: ${dbPath}`);
      process.exit(1);
    }
  }

  return Promise.all([
    maxmind.open(dbPaths.asn),
    maxmind.open(dbPaths.country)
  ]);
}

function logInfo(msg) {
  const now = new Date().toISOString();
  console.log(`[${now}] [INFO] ${msg}`);
}

// ====== Main Scan Logic ======
async function runGeoIPScan(asnLookup, countryLookup, dnsList, label) {
  logInfo(`GeoIP/Maltiverse scan using: ${label}`);
  const myip = await getMyPublicIP();
  if (!myip) return;

  // Only scan if IP changed
  if (myip !== lastIP) {
    lastIP = myip;
    const ips = Array.from(new Set([myip, ...dnsList]));
    console.log(`\nUsing DNS list: [${label}]`);

    for (const ip of ips) {
      if (maltiverseQuotaExceeded) {
        console.warn("[!] Maltiverse checks are paused due to quota. Only MaxMind lookups performed.");
      }
      await lookupIP(ip, asnLookup, countryLookup);
    }
  } else {
    logInfo("No IP change detected, skipping scan.");
  }
}

async function main() {
  const [asnLookup, countryLookup] = await prepareLookups();

  // Start/reset Maltiverse quota timer
  resetMaltiverseQuota();

  // 1. Public DNS
  await runGeoIPScan(asnLookup, countryLookup, publicDNS, 'Public DNS');

  // 2. Provider/ISP/Home DNS uncomment for use ISP DNS
  // await runGeoIPScan(asnLookup, countryLookup, providerDNS, 'Provider/Home DNS');

  // 3. Continuous Monitoring (Every hour)
  setInterval(() => {
    runGeoIPScan(asnLookup, countryLookup, publicDNS, 'Public DNS');
  }, 60 * 60 * 1000);
}

main();
