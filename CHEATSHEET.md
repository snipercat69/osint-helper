# 🕵️ OSINT Helper — Burner Identity Cheatsheet

**OSINT Helper** — passive reconnaissance for security researchers, penetration testers, and investigators.  
**Burner Identity** — hides your real IP by routing all requests through a rotating pool of 2,900+ proxies.

---

## ⚡ Quick Start

| Command | What it does |
|---------|-------------|
| `!osint username <handle>` | Find where a username exists online |
| `!osint domain <domain>` | DNS + RDAP + pivot links for a domain |
| `!osint ip <IP>` | Geo + RDAP + reverse DNS + pivot links |
| `!osint email <email>` | MX check + Gravatar + breach pivots |
| `!osint phone <number>` | Normalize + search pivots |
| `!osint asn <ASNumber>` | Routing info + related networks |
| `!osint ioc <ioc1> <ioc2> ...` | Multi-indicator enrichment + risk score |

---

## 🔥 Burner Identity Mode

**Adds `--burner` to any command** — routes your IP through rotating proxies so targets can't trace requests back to you.

```
!osint username snipercat1822 --burner
!osint domain example.com --burner
!osint email analyst@example.com --burner
!osint ioc 8.8.8.8 malicious.com --burner
```

**What burner mode protects:**
- Your real IP address (hidden behind proxy exit nodes)
- Your ISP/location (proxies are geographically distributed)
- Your organization's network (requests originate from proxy IPs, not yours)

**How it works:**
- Fetches 2,900+ free HTTP proxies on activation
- Each request uses a different proxy (random rotation)
- Failed proxies are marked and skipped automatically
- Falls back to direct connection if all proxies fail

---

## 🛡️ Legal Use Cases

✅ Scanning your own infrastructure  
✅ Bug bounty programs with written authorization  
✅ Penetration testing with client contract  
✅ OSINT research on public data  

❌ Scanning networks without explicit written permission  
❌ Using results for unauthorized access  
❌ Any activity that violates computer fraud laws  

---

## 📊 Output Formats

| Flag | Format |
|------|--------|
| (default) | Formatted Discord text |
| `--json` | Raw JSON for scripting/automation |
| `--probe` | Actively probes profile URLs (username mode only) |

---

## 🔍 Example Outputs

**Username lookup:**
```
!osint username snipercat1822 --burner
→ Found: GitHub, Twitter, Instagram, LinkedIn...
→ Gravatar hash: abc123...
→ Related domains: [expansion pivot links]
```

**IOC correlator:**
```
!osint ioc 8.8.8.8 malicious.com phishing.net
→ Enrichment: IP → ASN → Geo → DNS
→ Risk score: HIGH / MEDIUM / LOW
→ Related indicators from public feeds
```

**Domain report:**
```
!osint domain example.com --burner
→ Registrant (RDAP), NS, MX, Subdomains, related domains
→ Historical WHOIS pivots
→ SSL certificate info
```

---

## 💡 Pro Tips

**Use --burner by default for sensitive investigations** — no performance cost, full IP protection

**Combine with --json for automation:**
```
!osint ioc 8.8.8.8 1.1.1.1 --json | jq '.risk_score'
```

**Username --probe adds active checks** — only use on targets you have permission to probe

**No --burner = direct from your IP** — fine for passive OSINT, public data, non-sensitive targets

---

## 🔗 Related Tools

- **XSS Scanner:** `!xss <url>` — vulnerability scanning with `--burner` support
- **Network Scanner:** `!net <target>` — port scanning and host discovery
- **Both channels:** `#osint-helper`, `#xss-scanner`, `#net-scan`
