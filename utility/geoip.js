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
 *   - MaxMind GeoIP2 ASN and Country .mmdb database files (see geolite.config.js for paths/config)
 *   - Node.js packages: maxmind, axios, path, fs
 *
 * Usage:
 *   node geoip.js
 *
 * Customization:
 *   - To scan your ISP/provider DNS, add them to the `providerDNS` array and uncomment the relevant line in main().
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

const maxmind = require('maxmind');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const config = require('./geolite.config.js');

// ====== DNS Lists ======
const publicDNS = [
  '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4',
  '185.222.222.222', '45.11.45.11', '76.76.2.0', '76.76.10.0',
  '193.110.81.254', '185.253.5.254', '194.242.2.2', '91.239.100.100'
];
// ====== Add your Provider/ISP/Home DNS Lists ======  
const providerDNS = [];

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

async function lookupIP(ip, asnLookup, countryLookup) {
  const asn = asnLookup.get(ip);
  const country = countryLookup.get(ip);

  console.log(`\nIP: ${ip}`);
  console.log('  ASN:     ', asn?.autonomous_system_organization || 'Not found', `(AS${asn?.autonomous_system_number || 'N/A'})`);
  console.log('  Country: ', country?.country?.names?.en || 'Not found');
  // City/region lookups are removed for privacy/clarity
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

// ====== Maltiverse batch search URL builder ======
function getMaltiverseSearchURL(ips) {
  const ipQuery = encodeURIComponent(ips.join(' '));
  return `https://maltiverse.com/intelligence/search;query=${ipQuery};page=1;sort=creation_time_desc`;
}

// ====== Main Scan Logic ======
async function runGeoIPScan(asnLookup, countryLookup, dnsList, label) {
  logInfo(`GeoIP scan using: ${label}`);
  const myip = await getMyPublicIP();
  if (!myip) return;

  // Only scan if IP changed
  if (myip !== lastIP) {
    lastIP = myip;
    const ips = Array.from(new Set([myip, ...dnsList]));
    console.log(`\nUsing DNS list: [${label}]`);

    for (const ip of ips) {
      await lookupIP(ip, asnLookup, countryLookup);
    }

    // Print Maltiverse batch search URL for all scanned IPs
    if (ips.length > 1) {
      console.log(
        `\nMaltiverse Intel Web Search: ${getMaltiverseSearchURL(ips)}\n`
      );
    }
  } else {
    logInfo("No IP change detected, skipping scan.");
  }
}

async function main() {
  const [asnLookup, countryLookup] = await prepareLookups();

  // 1. Public DNS
  await runGeoIPScan(asnLookup, countryLookup, publicDNS, 'Public DNS');

  // 2. Provider/ISP/Home DNS uncomment to use ISP DNS
  // await runGeoIPScan(asnLookup, countryLookup, providerDNS, 'Provider/Home DNS');

  // 3. Continuous Monitoring (Every hour)
  setInterval(() => {
    runGeoIPScan(asnLookup, countryLookup, publicDNS, 'Public DNS');
  }, 60 * 60 * 1000);
}

main();
