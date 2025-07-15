// geoip_opennic_tier.js
const axios = require('axios');
const OPENNIC_GEOIP_URL = 'https://api.opennicproject.org/geoip/?list&adm=3';

/**
 * Fetch nearest OpenNIC Tier 2 DNS servers via GeoIP API.
 * Returns a deduplicated array of IPs.
 */
async function fetchOpenNICTierServers() {
  try {
    const response = await axios.get(OPENNIC_GEOIP_URL);
    const servers = [];
    const lines = response.data.split('\n');
    for (const line of lines) {
      // Example line: "94.247.43.254 ns7.de.dns.opennic.glue"
      const ipMatch = line.match(/^(([0-9]{1,3}\.){3}[0-9]{1,3}|([a-fA-F0-9:]+:+)+[a-fA-F0-9]+)\s*/);
      const hostMatch = line.match(/\s([\w.-]+\.[\w.-]+)$/);
      if (ipMatch) {
        servers.push({
          ip: ipMatch[1],
          hostname: hostMatch ? hostMatch[1] : null
        });
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
