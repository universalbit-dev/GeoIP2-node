# 🌐 GeoIP2-node — DNS & Threat Intelligence Scanner

A small command-line utility for sysadmins and security professionals to:
- Check public and provider DNS IPs (ASN & country via external GeoIP providers)  
- Enrich IPs with Maltiverse threat intelligence (requires API key)  
- Run periodic scans (only when your public IP changes) and extend with custom sources

This utility uses external GeoIP providers by default (e.g., `ip-api`). Optional local
MaxMind MMDB support is available if you prefer private/offline lookups.

Quick start
-----------
1. Install dependencies:
```bash
npm i
```

2. Configure environment:
```bash
# Edit the environment file
nano utility/.env
# MALTIVERSE_API_KEY=your_key_here

# Secure the file (run as the file owner)
chmod 600 utility/.env

```

3. Run the scanner (from the repository root):
```bash
# run directly
node utility/geoip.js

# alternative change into the utility folder and run
cd utility && node geoip.js
# or
npm start --prefix utility
```

Environment variables
---------------------
The scanner reads configuration from `utility/.env` (and from `process.env`):

- `MALTIVERSE_API_KEY` — REQUIRED to enable Maltiverse checks. 
- `GEOIP_PROVIDER` — GeoIP provider; default: `ip-api`. Set `ipinfo` to use ipinfo.io (requires token).  
- `GEOIP_PROVIDER_TOKEN` — Token for providers that require it (e.g., ipinfo).  
- `GEOIP_CACHE_TTL_SECS` — Cache TTL in seconds for GeoIP & Maltiverse results (default: `86400` = 24h).  
- `MALTIVERSE_QUOTA_PER_HOUR` — Number of Maltiverse calls allowed per interval (default: `20`).  
- `MALTIVERSE_INTERVAL_MS` — Quota reset interval in milliseconds (default: `3600000`).  
- `SCAN_INTERVAL_MS` — Main scan interval in ms (default: `3600000`).

Notes
-----
- If you use `utility/.env`, make sure `dotenv` is installed (`npm i dotenv`) and that `geoip.js` loads it, for example:
```js
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, 'utility', '.env') });
```
- Prefer a secrets manager (CI/service env vars) for production instead of a local `.env` file.

Files & behavior
----------------
- `utility/geoip.js` — main scanner.  
- `utility/cache/` — persistent JSON caches for GeoIP and Maltiverse lookups (reduces API usage).  
- `utility/.env` — local environment file (sensitive; ensure it is ignored by Git).  

What the scanner does
---------------------
1. Fetches your public IP (ipify).  
2. Builds the unique list of IPs to check (your IP + `publicDNS` + `providerDNS`).  
3. Performs GeoIP lookups via the configured external provider and caches results.  
4. Queries Maltiverse (if `MALTIVERSE_API_KEY` is set) with quota enforcement and caching.  
5. Prints results (ASN, country, Maltiverse reputation & tags).  
6. Repeats periodically, but only triggers a full scan when your public IP changes.

Maltiverse integration
----------------------
- Set `MALTIVERSE_API_KEY` in `utility/.env` (or export it in your environment).  
- Scanner enforces `MALTIVERSE_QUOTA_PER_HOUR`; when quota is exhausted, Maltiverse checks are skipped until reset.  
- Results are cached (default TTL 24h).
  
Troubleshooting & tips
----------------------
- If GeoIP results look odd, remember public resolvers use anycast — ASN/country may reflect the node closest to your runner.  
- Increase cache TTL or centralize calls if you hit provider rate limits.  
- If Maltiverse returns 403/429, check quota and account plan.  
- Ensure `utility/.env` is listed in `.gitignore` and secure it: `chmod 600 utility/.env`.

Happy scanning! 🚦

