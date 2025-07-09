# 🌐 GeoIP2-node DNS & Threat Intelligence Scanner (Privacy Edition)

A command-line utility for security professionals and sysadmins to:
- 🔎 Lookup DNS IP info with MaxMind GeoIP2 (ASN & Country, **privacy-focused**)
- 🛡️ Check DNS providers and your own IP
- 🌐 Instantly batch-check threat intel via Maltiverse web search
- ⚙️ Easily extend for your own DNS lists

---

## 🚀 Features

- **MaxMind Integration:**  
  Uses local GeoIP2 ASN and Country databases for fast, private lookups.
- **Maltiverse Threat Intel (Privacy Mode):**  
  *No direct API queries;* instead, a web URL is generated for batch-checking all scanned IPs in your browser.
- **DNS Awareness:**  
  Scans public DNS services, and is ready for you to add your own ISP/home DNS IPs.
- **Automated Monitoring:**  
  Periodic (hourly) re-scans, but only if your public IP changes.

---

## ⚡ Usage

```bash
node geoip.js
