// geoip_opennic_tier.js
const { exec } = require('child_process');
const net = require('net');

const OPENNIC_GEOIP_URL = 'https://api.opennicproject.org/geoip/?json';

/**
 * Fetch nearest OpenNIC Tier 2 DNS servers via GeoIP API (JSON, via curl).
 * Returns a deduplicated array of { ip, hostname } objects.
 */
async function fetchOpenNICTierServers() {
  return new Promise((resolve, reject) => {
    exec(`curl -s "${OPENNIC_GEOIP_URL}"`, (err, stdout, stderr) => {
      if (err) {
        console.error('Failed to fetch OpenNIC Tier servers:', err);
        resolve([]); // For compatibility with old code
        return;
      }
      let data;
      try {
        data = JSON.parse(stdout);
      } catch (parseError) {
        console.error('Failed to parse JSON from API:', parseError);
        resolve([]);
        return;
      }
      const servers = [];
      const seen = new Set();
      for (const entry of data) {
        const ip = entry.ip;
        const hostname = entry.short;
        if (net.isIP(ip) && !seen.has(ip)) {
          servers.push({ ip, hostname });
          seen.add(ip);
        }
      }
      resolve(servers);
    });
  });
}

if (require.main === module) {
  (async () => {
    const servers = await fetchOpenNICTierServers();
    if (servers.length === 0) {
      console.log('No OpenNIC Tier 2 DNS servers found from API.');
    } else {
      console.log('OpenNIC Tier 2 DNS servers:', servers);
    }
  })();
}

module.exports = { fetchOpenNICTierServers };
