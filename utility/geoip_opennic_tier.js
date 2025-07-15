// geoip_opennic_tier.js
const axios = require('axios');
const OPENNIC_GEOIP_URL = 'https://api.opennicproject.org/geoip/?list&adm=3';

// Regex for IPv4 and IPv6 matching
const ipv4Regex = /^([0-9]{1,3}\.){3}[0-9]{1,3}$/;
const ipv6Regex = /^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$/;

/**
 * Fetch nearest OpenNIC Tier 2 DNS servers via GeoIP API.
 * Returns a deduplicated array of IPs.
 */
async function fetchOpenNICTierServers() {
  try {
    const response = await axios.get(OPENNIC_GEOIP_URL);

    const servers = [];
    const lines = response.data.split('\n').map(l => l.trim()).filter(Boolean);

    for (const line of lines) {
      // Example line: "94.247.43.254 ns7.de.dns.opennic.glue"
      const parts = line.split(/\s+/);
      if (parts.length < 2) continue; // Skip malformed lines

      const ip = parts[0];
      const hostname = parts.slice(1).join(' ');

      if (ipv4Regex.test(ip) || ipv6Regex.test(ip)) {
        servers.push({ ip, hostname });
      }
    }
    // Deduplicate IPs before returning
    return Array.from(new Set(servers.map(s => s.ip)));
  } catch (err) {
    console.error('Failed to fetch OpenNIC Tier servers:', err.message);
    return [];
  }
}

module.exports = { fetchOpenNICTierServers };
