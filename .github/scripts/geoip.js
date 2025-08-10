// .github/scripts/geoip.js

const https = require('https');

const token = process.env.MALTIVERSE_TOKEN;

if (!token) {
  console.error('Error: MALTIVERSE_TOKEN environment variable is not set.');
  process.exit(1);
}

// Example: querying Maltiverse API for an IP address
const ip = process.argv[2] || '8.8.8.8'; // default IP if not provided

const options = {
  hostname: 'api.maltiverse.com',
  path: `/ip/${ip}`,
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/json',
    'User-Agent': 'GeoIP2-node/.github/scripts/geoip.js'
  }
};

const req = https.request(options, (res) => {
  let data = '';
  res.on('data', (chunk) => { data += chunk; });
  res.on('end', () => {
    if (res.statusCode === 200) {
      try {
        const result = JSON.parse(data);
        console.log('Maltiverse API response:', JSON.stringify(result, null, 2));
      } catch (e) {
        console.error('Failed to parse JSON response:', e.message);
      }
    } else {
      console.error(`API request failed with status ${res.statusCode}: ${data}`);
    }
  });
});

req.on('error', (e) => {
  console.error(`Request error: ${e.message}`);
});

req.end();
