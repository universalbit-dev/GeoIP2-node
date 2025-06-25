# 🌐 GeoIP2-node DNS & Threat Intelligence Scanner

A command-line utility for security professionals and sysadmins to:
- 🔎 Lookup DNS IP info with MaxMind GeoIP2 (ASN & Country)
- 🛡️ Check DNS providers and your own IP
- 🕵️ Integrate threat intelligence from Maltiverse (with quota limiting)
- ⚙️ Easily extend for your own DNS or threat sources

---

## 🚀 Features

- **MaxMind Integration:**  
  Uses local GeoIP2 ASN and Country databases for ultra-fast, private lookups.

- **Maltiverse Threat Intel:**  
  Automatically checks IPs against Maltiverse for reputation/tags (with API quota handling).

- **DNS Awareness:**  
  Scans public DNS services, and is ready for you to add your own ISP/home DNS IPs.

- **Automated Monitoring:**  
  Periodic (hourly) re-scans, but only if your public IP changes.

---

## ⚡ Usage

```bash
node geoip.js
```

> **Requires:**  
> - `geolite.config.js`
> - ASN and Country `.mmdb` files from MaxMind  
> - Node.js & dependencies (`npm install maxmind axios`)

---

## 🛠️ Configuration

1. Place your MaxMind `.mmdb` files in the directory specified by `geolite.config.js`:

   ```js
   // Example config
   module.exports = {
     mmdbDir: './mmdb',
     asnDb: 'GeoLite2-ASN.mmdb',
     countryDb: 'GeoLite2-Country.mmdb',
   }
   ```

2. Add any custom DNS IPs to the `providerDNS` array in the script if desired.

---

## 🎯 What It Does

1. **Loads MaxMind databases** for ASN and country lookups.
2. **Fetches your public IP** using ipify.
3. **Looks up each DNS IP** (public list provided, plus your own if added).
4. **Queries Maltiverse** for each IP’s threat reputation (up to 20/hour, then skips Maltiverse gracefully).
5. **Prints results** with ASN, country, Maltiverse reputation, and tags.
6. **Repeats every hour** (but only if your public IP changes).

---

## 📝 Example Output

```
IP: 8.8.8.8
  ASN:      Google LLC (AS15169)
  Country:  United States
  Maltiverse Reputation: benign
  Maltiverse Tags: search, dns, google
```

---

## 🔄 Maltiverse Quota Handling

- Limits requests to **20/hour**
- If quota is hit, outputs a warning and skips Maltiverse until reset

---

## 🧩 Extending

- **Add more DNS IPs:**  
  Edit `publicDNS` or `providerDNS` arrays.
- **Change scan interval:**  
  Edit the value in `setInterval` (default: 1 hour).

---

Install all with:

```bash
npm install maxmind axios
```

---

## ⚠️ Notes

- You must download and keep your MaxMind `.mmdb` files up to date.
- Maltiverse is a free service, but respect its API limits.
- This tool does **not** perform city/region lookups (database not included by default).

---

## 🤝 Contributing

Pull requests welcome!  
Issues? [Open one here](https://github.com/universalbit-dev/GeoIP2-node/issues).

---

## 📚 References

- [MaxMind GeoLite2 Databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
- [Maltiverse API Docs](https://app.swaggerhub.com/apis-docs/maltiverse/api/1.1.3)

---

**Happy scanning!** 🚦
