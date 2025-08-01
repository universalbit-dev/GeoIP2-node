#!/usr/bin/env node
/**
 * GeoIP2-node DNS & Threat Intelligence Scanner
 *
 * Description:
 *   - Looks up the ASN and country for your current public IP and a set of public (and optionally provider) DNS servers.
 *   - Prints results to the console.
 *   - Generates a Maltiverse batch intelligence search link for all scanned IPs for quick manual reputation review.
 *
 * Requirements:
 *   - MaxMind GeoIP2 ASN and Country .mmdb database files (see .env for paths/config)
 *   - Node.js packages: maxmind, axios, path, fs, dotenv
 *
 * Usage:
 *   node geoip.js
 *
 * Customization:
 *   - To scan your ISP/provider DNS, add them to the PROVIDER_DNS entry in your .env file.
 *
 * Output:
 *   - For each IP: ASN, ASN Number, Country
 *   - At the end: Maltiverse batch search URL for all scanned IPs
 *
 * Note:
 *   - No city or region lookup for PRIVACY.
 *   - No direct Maltiverse API queries—manual reputation check via URL.
 *   - Scans repeat every hour, but only if your public IP has changed.
 */

require('dotenv').config();

const maxmind = require('maxmind');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

// ====== OpenNIC Tier 2 DNS integration ======
const { fetchOpenNICTierServers } = require('./geoip_opennic_tier');

// ====== DNS Lists from .env ======
const publicDNS = process.env.PUBLIC_DNS ? process.env.PUBLIC_DNS.split(',').map(ip => ip.trim()) : [];
const providerDNS = process.env.PROVIDER_DNS ? process.env.PROVIDER_DNS.split(',').map(ip => ip.trim()).filter(Boolean) : [];

// ====== IP Change Detection ======
let lastIP = null;

// ====== Maltiverse API integration ======
const USE_MALTIVERSE_API = (process.env.USE_MALTIVERSE_API || 'false').toLowerCase() === 'true';
const MALTIVERSE_API_KEY = process.env.MALTIVERSE_API_KEY;
const MALTIVERSE_API_QUOTA = Number(process.env.MALTIVERSE_API_QUOTA) || 100;
let maltiverseApiCount = 0;

async function queryMaltiverse(ip) {
  if (!USE_MALTIVERSE_API || !MALTIVERSE_API_KEY) return null;
  if (maltiverseApiCount >= MALTIVERSE_API_QUOTA) {
    console.log('  Maltiverse API quota reached; skipping direct lookup.');
    return null;
  }
  try {
    const res = await axios.get(`https://api.maltiverse.com/ip/${ip}`, {
      headers: {
        Authorization: `Bearer ${MALTIVERSE_API_KEY}`
      },
      timeout: 3000
    });
    maltiverseApiCount++;
    return res.data;
  } catch (e) {
    if (e.response && e.response.status === 404) {
      console.log('  Maltiverse: Not found');
    } else {
      console.log('  Maltiverse API error:', e.message);
    }
    return null;
  }
}

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

async function lookupIP(ip, asnLookup, countryLookup) {
  const asn = asnLookup.get(ip);
  const country = countryLookup.get(ip);

  console.log(`\nIP: ${ip}`);
  console.log('  ASN:     ', asn?.autonomous_system_organization || 'Not found', `(AS${asn?.autonomous_system_number || 'N/A'})`);
  console.log('  Country: ', country?.country?.names?.en || 'Not found');
  // City/region lookups are removed for privacy/clarity

  // ====== Maltiverse API reputation lookup ======
  if (USE_MALTIVERSE_API && MALTIVERSE_API_KEY) {
    const threat = await queryMaltiverse(ip);
    if (threat && threat.classification) {
      console.log('  Maltiverse:', threat.classification, threat.tag?.length ? `(${threat.tag.join(', ')})` : '');
      if (Array.isArray(threat.blacklist) && threat.blacklist.length > 0) {
        threat.blacklist.forEach(entry => {
          console.log(`    - Blacklist: ${entry.description} [${entry.source}]`);
        });
      }
    }
  }
}

// ====== Database presence and preparation ======
async function prepareLookups() {
  const dbPaths = {
    asn: path.join(process.env.MMDB_DIR, process.env.ASN_DB),
    country: path.join(process.env.MMDB_DIR, process.env.COUNTRY_DB)
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

// ====== Maltiverse batch search URL builder ======
function getMaltiverseSearchURL(ips) {
  const ipQuery = encodeURIComponent(ips.join(' '));
  return `https://maltiverse.com/intelligence/search;query=${ipQuery};page=1;sort=creation_time_desc`;
}

// ====== Main Scan Logic ======
async function runGeoIPScan(asnLookup, countryLookup, dnsList, label) {
  logInfo(`GeoIP scan using: ${label}`);
  for (const ip of dnsList) {
    await lookupIP(ip, asnLookup, countryLookup);
  }
}

// ====== Main Entrypoint ======
async function main() {
  const [asnLookup, countryLookup] = await prepareLookups();
  const myip = await getMyPublicIP();
  if (!myip) return;

  // Fetch OpenNIC Tier 2 DNS (dynamic)
  let openNICIPs = [];
  try {
    const openNICTierServers = await fetchOpenNICTierServers();
    openNICIPs = Array.isArray(openNICTierServers) && openNICTierServers.length && typeof openNICTierServers[0] === 'object'
      ? openNICTierServers.map(s => s.ip)
      : openNICTierServers;
  } catch (err) {
    logInfo('Error fetching OpenNIC Tier 2 DNS: ' + err.message);
  }

  // Combine all IPs (public, provider, OpenNIC Tier 2) and deduplicate
  const allIPs = Array.from(new Set([myip, ...publicDNS, ...providerDNS, ...openNICIPs]));

  if (myip !== lastIP) {
    lastIP = myip;

    // Scan Public DNS
    await runGeoIPScan(asnLookup, countryLookup, [myip, ...publicDNS], 'Public DNS');

    // Scan Provider/ISP DNS (if any)
    if (providerDNS.length > 0) {
      await runGeoIPScan(asnLookup, countryLookup, providerDNS, 'Provider/Home DNS');
    }

    // Scan OpenNIC Tier 2 DNS
    if (openNICIPs.length > 0) {
      await runGeoIPScan(asnLookup, countryLookup, openNICIPs, 'OpenNIC Tier 2 DNS');
    } else {
      logInfo('No OpenNIC Tier 2 DNS servers found from API.');
    }

    // Print Maltiverse batch search URL for all scanned IPs (including Tier servers)
    console.log(
      `\nMaltiverse Intel Web Search: ${getMaltiverseSearchURL(allIPs)}\n`
    );
  } else {
    logInfo("No IP change detected, skipping scan.");
    // Still print the Maltiverse batch search URL for all IPs (helpful for review)
    console.log(
      `\nMaltiverse Intel Web Search: ${getMaltiverseSearchURL(allIPs)}\n`
    );
  }

  // Continuous Monitoring (interval from .env, default 3600 sec)
  const scanInterval = Number(process.env.SCAN_INTERVAL) || 3600;
  setInterval(async () => {
    const myip = await getMyPublicIP();
    let openNICIPs = [];
    try {
      const openNICTierServers = await fetchOpenNICTierServers();
      openNICIPs = Array.isArray(openNICTierServers) && openNICTierServers.length && typeof openNICTierServers[0] === 'object'
        ? openNICTierServers.map(s => s.ip)
        : openNICTierServers;
    } catch (err) {
      logInfo('Error fetching OpenNIC Tier 2 DNS (interval): ' + err.message);
    }

    const allIPs = Array.from(new Set([myip, ...publicDNS, ...providerDNS, ...openNICIPs]));

    if (myip !== lastIP) {
      lastIP = myip;

      await runGeoIPScan(asnLookup, countryLookup, [myip, ...publicDNS], 'Public DNS');
      if (providerDNS.length > 0) {
        await runGeoIPScan(asnLookup, countryLookup, providerDNS, 'Provider/Home DNS');
      }
      if (openNICIPs.length > 0) {
        await runGeoIPScan(asnLookup, countryLookup, openNICIPs, 'OpenNIC Tier 2 DNS');
      }
      console.log(
        `\nMaltiverse Intel Web Search: ${getMaltiverseSearchURL(allIPs)}\n`
      );
    } else {
      logInfo("No IP change detected, skipping scan.");
      console.log(
        `\nMaltiverse Intel Web Search: ${getMaltiverseSearchURL(allIPs)}\n`
      );
    }
  }, scanInterval * 1000);
}

main();
