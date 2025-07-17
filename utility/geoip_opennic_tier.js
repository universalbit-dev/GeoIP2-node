// geoip_opennic_tier.js
const axios = require('axios');
const net = require('net');
const OPENNIC_GEOIP_URL = 'https://api.opennicproject.org/geoip';

/**
 * Fetch nearest OpenNIC Tier 2 DNS servers via GeoIP API.
 * Returns a deduplicated array of { ip, hostname } objects.
 */
async function fetchOpenNICTierServers() {
  try {
    const response = await axios.get(OPENNIC_GEOIP_URL);
    const servers = [];
    const seen = new Set();

    // Split and process each non-empty line
    const lines = response.data.split('\n').map(l => l.trim()).filter(Boolean);

    for (const line of lines) {
      
      const parts = line.split(/\s+/);
      if (parts.length < 2) continue; // Skip malformed lines

      const ip = parts[0];
      const hostname = parts.slice(1).join(' ');

      if (net.isIP(ip) && !seen.has(ip)) {
        servers.push({ ip, hostname });
        seen.add(ip);
      }
    }

    return servers;
  } catch (err) {
    console.error('Failed to fetch OpenNIC Tier servers:', err.message);
    return [];
  }
}

module.exports = { fetchOpenNICTierServers };
