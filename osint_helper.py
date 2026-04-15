#!/usr/bin/env python3
"""OSINT Helper - lightweight passive reconnaissance assistant.

Features:
- Username pivot links (optionally probes public profile URLs)
- Domain quick recon (DNS + RDAP + pivot links)
- IP quick recon (reverse DNS + geo + RDAP + pivot links)
- Email quick recon (MX check + gravatar hash + pivot links)
- Phone quick pivots (normalized number + search pivots)
- ASN lookup (RDAP + routing pivots)
- IOC correlator (multi-indicator enrichment + basic risk scoring)

Default mode is passive. No active scanning.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

USER_AGENT = "osint-helper/0.1"
TIMEOUT = 8
SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "country",
    "gq",
    "tk",
    "ml",
    "cf",
    "work",
    "support",
    "help",
    "download",
}


def fetch_json(url: str, timeout: int = TIMEOUT) -> dict[str, Any] | None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


def fetch_status(url: str, timeout: int = 5) -> int | None:
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def dns_resolve_google(name: str, record_type: str) -> list[str]:
    q = urllib.parse.quote(name)
    t = urllib.parse.quote(record_type)
    url = f"https://dns.google/resolve?name={q}&type={t}"
    data = fetch_json(url)
    if not data:
        return []
    answers = data.get("Answer") or []
    out: list[str] = []
    for item in answers:
        val = str(item.get("data", "")).strip()
        if not val:
            continue
        out.append(val)
    return out


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    return domain


def normalize_phone(phone: str) -> tuple[str, str]:
    """Return normalized E.164-like form and digits-only form.

    This is a lightweight normalizer, not full libphonenumber validation.
    """
    raw = phone.strip()
    if not raw:
        raise ValueError("Phone is empty")

    cleaned = raw.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]

    digits = re.sub(r"\D", "", cleaned)
    if len(digits) < 7 or len(digits) > 15:
        raise ValueError("Phone must contain 7-15 digits")

    if cleaned.startswith("+"):
        e164 = "+" + digits
    else:
        e164 = "+" + digits

    return e164, digits


def guess_country_from_calling_code(e164: str) -> str | None:
    code_map = {
        "1": "US/Canada (NANP)",
        "7": "Russia/Kazakhstan",
        "20": "Egypt",
        "27": "South Africa",
        "30": "Greece",
        "31": "Netherlands",
        "32": "Belgium",
        "33": "France",
        "34": "Spain",
        "39": "Italy",
        "44": "United Kingdom",
        "49": "Germany",
        "52": "Mexico",
        "55": "Brazil",
        "60": "Malaysia",
        "61": "Australia",
        "62": "Indonesia",
        "63": "Philippines",
        "64": "New Zealand",
        "65": "Singapore",
        "81": "Japan",
        "82": "South Korea",
        "84": "Vietnam",
        "86": "China",
        "90": "Türkiye",
        "91": "India",
        "92": "Pakistan",
        "93": "Afghanistan",
        "94": "Sri Lanka",
        "95": "Myanmar",
        "98": "Iran",
        "212": "Morocco",
        "213": "Algeria",
        "234": "Nigeria",
        "351": "Portugal",
        "353": "Ireland",
        "358": "Finland",
        "370": "Lithuania",
        "380": "Ukraine",
        "420": "Czechia",
        "971": "United Arab Emirates",
        "972": "Israel",
        "973": "Bahrain",
        "974": "Qatar",
        "975": "Bhutan",
        "976": "Mongolia",
    }
    digits = re.sub(r"\D", "", e164)
    for width in (3, 2, 1):
        if len(digits) >= width:
            key = digits[:width]
            if key in code_map:
                return code_map[key]
    return None


def normalize_asn(asn: str) -> tuple[str, str]:
    raw = asn.strip().upper()
    if raw.startswith("AS"):
        raw = raw[2:]
    if not raw.isdigit():
        raise ValueError("ASN must be numeric or in AS12345 format")
    num = str(int(raw))
    return f"AS{num}", num


def asn_rdap_summary(asn_number: str) -> dict[str, Any]:
    rdap = fetch_json(f"https://rdap.org/autnum/{urllib.parse.quote(asn_number)}") or {}
    entities = [e.get("handle") for e in (rdap.get("entities") or []) if e.get("handle")]
    return {
        "handle": rdap.get("handle"),
        "name": rdap.get("name"),
        "type": rdap.get("type"),
        "country": rdap.get("country"),
        "status": rdap.get("status"),
        "startAutnum": rdap.get("startAutnum"),
        "endAutnum": rdap.get("endAutnum"),
        "events": rdap.get("events"),
        "entities": entities,
    }


def classify_indicator(value: str) -> tuple[str, str]:
    raw = value.strip().strip("\"'`[](){}<>,; ")
    if not raw:
        return "unknown", value.strip()

    lower = raw.lower()

    if lower.startswith("http://") or lower.startswith("https://"):
        return "url", raw

    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", lower):
        return "email", lower

    try:
        ip = ipaddress.ip_address(raw)
        return "ip", str(ip)
    except ValueError:
        pass

    if re.match(r"^(?:AS)?\d{1,10}$", raw, flags=re.IGNORECASE):
        asn_label, _ = normalize_asn(raw)
        return "asn", asn_label

    digits = re.sub(r"\D", "", raw)
    if (
        7 <= len(digits) <= 15
        and not re.search(r"[a-fA-F]", raw)
        and (raw.startswith("+") or raw.startswith("00") or any(ch in raw for ch in "-() "))
    ):
        e164, _ = normalize_phone(raw)
        return "phone", e164

    if re.fullmatch(r"[A-Fa-f0-9]{64}", raw):
        return "hash-sha256", raw.lower()
    if re.fullmatch(r"[A-Fa-f0-9]{40}", raw):
        return "hash-sha1", raw.lower()
    if re.fullmatch(r"[A-Fa-f0-9]{32}", raw):
        return "hash-md5", raw.lower()

    if re.match(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", lower):
        return "domain", normalize_domain(lower)

    return "unknown", raw


def parse_registration_date(events: list[dict[str, Any]] | None) -> dt.datetime | None:
    if not events:
        return None
    for ev in events:
        if str(ev.get("eventAction", "")).lower() in {"registration", "registered"}:
            date_str = str(ev.get("eventDate", "")).strip()
            if not date_str:
                continue
            try:
                normalized = date_str.replace("Z", "+00:00")
                when = dt.datetime.fromisoformat(normalized)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=dt.UTC)
                return when.astimezone(dt.UTC)
            except Exception:
                continue
    return None


def build_username_report(username: str, probe: bool = False) -> dict[str, Any]:
    username = username.strip().lstrip("@")
    base_profiles = {
        "X": f"https://x.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "Keybase": f"https://keybase.io/{username}",
        "Gravatar": f"https://gravatar.com/{username}",
    }

    pivots = {
        "Namechk": f"https://namechk.com/{username}",
        "WhatsMyName": "https://whatsmyname.app/",
        "Google dork": (
            "https://www.google.com/search?q="
            + urllib.parse.quote(f'"{username}" (site:x.com OR site:github.com OR site:reddit.com)')
        ),
    }

    profile_status: dict[str, Any] = {}
    if probe:
        for label, url in base_profiles.items():
            profile_status[label] = {
                "url": url,
                "status": fetch_status(url),
            }

    report = {
        "type": "username",
        "target": username,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "profiles": profile_status if probe else base_profiles,
        "probe_enabled": probe,
        "pivots": pivots,
        "notes": [
            "Profile status checks are heuristic only.",
            "A 200/302 does not prove account ownership.",
        ],
    }
    return report


def build_domain_report(domain: str) -> dict[str, Any]:
    domain = normalize_domain(domain)

    dns = {
        "A": dns_resolve_google(domain, "A"),
        "AAAA": dns_resolve_google(domain, "AAAA"),
        "MX": dns_resolve_google(domain, "MX"),
        "NS": dns_resolve_google(domain, "NS"),
        "TXT": dns_resolve_google(domain, "TXT"),
    }

    rdap = fetch_json(f"https://rdap.org/domain/{urllib.parse.quote(domain)}") or {}

    whois_like = {
        "handle": rdap.get("handle"),
        "ldhName": rdap.get("ldhName"),
        "status": rdap.get("status"),
        "events": rdap.get("events"),
        "nameservers": [ns.get("ldhName") for ns in (rdap.get("nameservers") or []) if ns.get("ldhName")],
    }

    pivots = {
        "VirusTotal": f"https://www.virustotal.com/gui/domain/{domain}",
        "SecurityTrails": f"https://securitytrails.com/domain/{domain}",
        "crt.sh": f"https://crt.sh/?q={urllib.parse.quote(domain)}",
        "Shodan": f"https://www.shodan.io/search?query=hostname:{urllib.parse.quote(domain)}",
        "Urlscan": f"https://urlscan.io/domain/{domain}",
        "Wayback": f"https://web.archive.org/web/*/{domain}",
    }

    return {
        "type": "domain",
        "target": domain,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "dns": dns,
        "rdap": whois_like,
        "pivots": pivots,
        "notes": [
            "DNS values can change quickly.",
            "RDAP fields vary by TLD registry.",
        ],
    }


def build_ip_report(ip: str) -> dict[str, Any]:
    ip = ip.strip()
    ipaddress.ip_address(ip)

    reverse_dns = None
    try:
        reverse_dns = socket.gethostbyaddr(ip)[0]
    except Exception:
        reverse_dns = None

    geo = fetch_json(f"https://ipwho.is/{urllib.parse.quote(ip)}") or {}
    rdap = fetch_json(f"https://rdap.org/ip/{urllib.parse.quote(ip)}") or {}

    pivots = {
        "Shodan": f"https://www.shodan.io/host/{ip}",
        "VirusTotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
        "AbuseIPDB": f"https://www.abuseipdb.com/check/{ip}",
        "GreyNoise": f"https://viz.greynoise.io/ip/{ip}",
        "URLhaus": f"https://urlhaus.abuse.ch/browse/host/{ip}/",
    }

    compact_geo = {
        "success": geo.get("success"),
        "country": geo.get("country"),
        "region": geo.get("region"),
        "city": geo.get("city"),
        "isp": geo.get("isp"),
        "org": geo.get("org"),
        "asn": geo.get("connection", {}).get("asn") if isinstance(geo.get("connection"), dict) else None,
    }

    asn_lookup: dict[str, Any] | None = None
    asn_raw = compact_geo.get("asn")
    if asn_raw:
        try:
            asn_label, asn_number = normalize_asn(str(asn_raw))
            asn_rdap = asn_rdap_summary(asn_number)
            asn_lookup = {
                "asn": asn_label,
                "rdap": asn_rdap,
                "pivots": {
                    "BGP.HE": f"https://bgp.he.net/{asn_label}",
                    "BGP.tools": f"https://bgp.tools/as/{asn_number}",
                    "IPinfo": f"https://ipinfo.io/{asn_label}",
                },
            }
        except ValueError:
            asn_lookup = None

    compact_rdap = {
        "handle": rdap.get("handle"),
        "name": rdap.get("name"),
        "type": rdap.get("type"),
        "country": rdap.get("country"),
        "status": rdap.get("status"),
    }

    return {
        "type": "ip",
        "target": ip,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "reverse_dns": reverse_dns,
        "geo": compact_geo,
        "rdap": compact_rdap,
        "asn_lookup": asn_lookup,
        "pivots": pivots,
        "notes": [
            "GeoIP is approximate.",
            "CDNs and VPNs can hide origin infrastructure.",
        ],
    }


def build_email_report(email: str) -> dict[str, Any]:
    email = email.strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise ValueError("Invalid email format")

    local, domain = email.split("@", 1)

    mx = dns_resolve_google(domain, "MX")
    txt = dns_resolve_google(domain, "TXT")

    gravatar_hash = hashlib.md5(email.encode("utf-8")).hexdigest()

    pivots = {
        "Google": "https://www.google.com/search?q=" + urllib.parse.quote(f'"{email}"'),
        "HIBP": f"https://haveibeenpwned.com/unifiedsearch/{urllib.parse.quote(email)}",
        "Hunter": f"https://hunter.io/email-verifier/{urllib.parse.quote(email)}",
        "DeHashed": f"https://www.dehashed.com/search?query={urllib.parse.quote(email)}",
        "Gravatar": f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404",
    }

    return {
        "type": "email",
        "target": email,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "local_part": local,
        "domain": domain,
        "mx": mx,
        "txt": txt,
        "gravatar_hash": gravatar_hash,
        "pivots": pivots,
        "notes": [
            "Presence in search results is not identity proof.",
            "Many breach tools require account/API access.",
        ],
    }


def build_phone_report(phone: str) -> dict[str, Any]:
    e164, digits = normalize_phone(phone)
    country_guess = guess_country_from_calling_code(e164)

    pivots = {
        "Google": "https://www.google.com/search?q=" + urllib.parse.quote(f'"{e164}" OR "{digits}"'),
        "Bing": "https://www.bing.com/search?q=" + urllib.parse.quote(f'"{e164}" OR "{digits}"'),
        "DuckDuckGo": "https://duckduckgo.com/?q=" + urllib.parse.quote(f'"{e164}" OR "{digits}"'),
        "Truecaller": f"https://www.truecaller.com/search/in/{digits}",
        "Sync.me": f"https://sync.me/search/?number={urllib.parse.quote(e164)}",
        "SpyDialer": f"https://www.spydialer.com/default.aspx?Phone={digits}",
        "WhatsApp": f"https://wa.me/{digits}",
    }

    return {
        "type": "phone",
        "target": e164,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "digits": digits,
        "country_guess": country_guess,
        "pivots": pivots,
        "notes": [
            "Phone intel often varies by region and data source.",
            "Search hits are leads, not proof of ownership.",
        ],
    }


def build_asn_report(asn: str) -> dict[str, Any]:
    asn_label, asn_number = normalize_asn(asn)
    rdap = asn_rdap_summary(asn_number)

    pivots = {
        "BGP.HE": f"https://bgp.he.net/{asn_label}",
        "BGP.tools": f"https://bgp.tools/as/{asn_number}",
        "Hurricane Electric Toolkit": f"https://bgp.he.net/{asn_label}#_prefixes",
        "IPinfo": f"https://ipinfo.io/{asn_label}",
        "PeeringDB": f"https://www.peeringdb.com/asn/{asn_number}",
    }

    return {
        "type": "asn",
        "target": asn_label,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "rdap": rdap,
        "pivots": pivots,
        "notes": [
            "Large networks can operate many business units and IP ranges.",
            "Use BGP/routing pivots to correlate suspicious infrastructure.",
        ],
    }


def build_ioc_report(values: list[str]) -> dict[str, Any]:
    raw_inputs: list[str] = []
    for v in values:
        for part in re.split(r"[\n,]+", v):
            item = part.strip()
            if item:
                raw_inputs.append(item)

    # de-dup while preserving order
    seen: set[str] = set()
    indicators: list[str] = []
    for i in raw_inputs:
        if i not in seen:
            seen.add(i)
            indicators.append(i)

    if not indicators:
        raise ValueError("No indicators provided")
    if len(indicators) > 30:
        raise ValueError("IOC mode supports up to 30 indicators per run")

    now = dt.datetime.now(dt.UTC)

    domain_cache: dict[str, dict[str, Any]] = {}
    ip_cache: dict[str, dict[str, Any]] = {}
    email_cache: dict[str, dict[str, Any]] = {}
    asn_cache: dict[str, dict[str, Any]] = {}

    risk_score = 0
    risk_flags: list[str] = []
    assessed_domain_risk: set[str] = set()

    domain_ips: dict[str, list[str]] = {}
    email_domains: dict[str, str] = {}
    url_hosts: dict[str, str] = {}
    ip_asn: dict[str, str | None] = {}
    asn_seen: set[str] = set()

    def add_risk(points: int, reason: str) -> None:
        nonlocal risk_score
        risk_score += points
        if reason not in risk_flags:
            risk_flags.append(reason)

    def assess_domain_risks(domain: str, report: dict[str, Any], source: str) -> None:
        if domain in assessed_domain_risk:
            return
        assessed_domain_risk.add(domain)

        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        if tld in SUSPICIOUS_TLDS:
            add_risk(10, f"{source}: suspicious TLD .{tld}")

        reg = parse_registration_date((report.get("rdap") or {}).get("events"))
        if reg is not None:
            age_days = (now - reg).days
            if age_days <= 180:
                add_risk(12, f"{source}: recently registered domain ({age_days}d old)")

        ips = (report.get("dns") or {}).get("A", []) + (report.get("dns") or {}).get("AAAA", [])
        if not ips:
            add_risk(4, f"{source}: no A/AAAA records observed")

    items: list[dict[str, Any]] = []
    type_counts: dict[str, int] = {}

    for raw in indicators:
        kind, normalized = classify_indicator(raw)
        type_counts[kind] = type_counts.get(kind, 0) + 1

        if kind == "domain":
            rep = domain_cache.get(normalized)
            if rep is None:
                rep = build_domain_report(normalized)
                domain_cache[normalized] = rep
            assess_domain_risks(normalized, rep, f"domain {normalized}")

            ips = ((rep.get("dns") or {}).get("A") or []) + ((rep.get("dns") or {}).get("AAAA") or [])
            domain_ips[normalized] = ips

            items.append(
                {
                    "input": raw,
                    "type": kind,
                    "normalized": normalized,
                    "ips": ips[:6],
                    "mx": (rep.get("dns") or {}).get("MX", []),
                }
            )
            continue

        if kind == "url":
            parsed = urllib.parse.urlparse(normalized)
            host = normalize_domain(parsed.netloc or parsed.path.split("/")[0])
            path = parsed.path or "/"

            url_hosts[normalized] = host

            rep = domain_cache.get(host)
            if rep is None and host:
                rep = build_domain_report(host)
                domain_cache[host] = rep

            if rep is not None and host:
                assess_domain_risks(host, rep, f"url host {host}")
                ips = ((rep.get("dns") or {}).get("A") or []) + ((rep.get("dns") or {}).get("AAAA") or [])
                domain_ips[host] = ips
            else:
                ips = []

            if re.search(r"login|signin|verify|update|secure|auth|account", path, re.IGNORECASE):
                add_risk(6, f"url {normalized}: sensitive/path lure keyword in URL path")

            items.append(
                {
                    "input": raw,
                    "type": kind,
                    "normalized": normalized,
                    "host": host,
                    "path": path,
                    "ips": ips[:6],
                }
            )
            continue

        if kind == "ip":
            rep = ip_cache.get(normalized)
            if rep is None:
                rep = build_ip_report(normalized)
                ip_cache[normalized] = rep

            asn_raw = (rep.get("geo") or {}).get("asn")
            asn_label = None
            if asn_raw is not None:
                try:
                    asn_label, _ = normalize_asn(str(asn_raw))
                    asn_seen.add(asn_label)
                except ValueError:
                    asn_label = None
            ip_asn[normalized] = asn_label

            ip_obj = ipaddress.ip_address(normalized)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                add_risk(5, f"ip {normalized}: non-public/private range indicator")
            if not asn_label:
                add_risk(4, f"ip {normalized}: missing ASN attribution")

            items.append(
                {
                    "input": raw,
                    "type": kind,
                    "normalized": normalized,
                    "reverse_dns": rep.get("reverse_dns"),
                    "asn": asn_label,
                    "country": (rep.get("geo") or {}).get("country"),
                }
            )
            continue

        if kind == "email":
            rep = email_cache.get(normalized)
            if rep is None:
                rep = build_email_report(normalized)
                email_cache[normalized] = rep

            domain = str(rep.get("domain") or "")
            if domain:
                email_domains[normalized] = domain
                if domain not in domain_cache:
                    domain_cache[domain] = build_domain_report(domain)
                assess_domain_risks(domain, domain_cache[domain], f"email domain {domain}")

            mx = rep.get("mx") or []
            if not mx:
                add_risk(15, f"email {normalized}: no MX records for domain")

            items.append(
                {
                    "input": raw,
                    "type": kind,
                    "normalized": normalized,
                    "domain": domain,
                    "mx_count": len(mx),
                }
            )
            continue

        if kind == "asn":
            rep = asn_cache.get(normalized)
            if rep is None:
                rep = build_asn_report(normalized)
                asn_cache[normalized] = rep
            asn_seen.add(normalized)
            items.append(
                {
                    "input": raw,
                    "type": kind,
                    "normalized": normalized,
                    "name": (rep.get("rdap") or {}).get("name"),
                    "country": (rep.get("rdap") or {}).get("country"),
                }
            )
            continue

        if kind == "phone":
            rep = build_phone_report(normalized)
            items.append(
                {
                    "input": raw,
                    "type": kind,
                    "normalized": rep.get("target"),
                    "country_guess": rep.get("country_guess"),
                }
            )
            continue

        if kind.startswith("hash-"):
            algo = kind.split("-", 1)[1]
            add_risk(5, f"hash IOC present ({algo})")
            items.append(
                {
                    "input": raw,
                    "type": kind,
                    "normalized": normalized,
                    "virustotal": f"https://www.virustotal.com/gui/search/{normalized}",
                }
            )
            continue

        items.append({"input": raw, "type": "unknown", "normalized": normalized})

    correlations: list[str] = []

    # shared infrastructure: same IP resolved by multiple domains
    ip_to_domains: dict[str, list[str]] = {}
    for d, ips in domain_ips.items():
        for ip in ips:
            ip_to_domains.setdefault(ip, []).append(d)
    for ip, ds in ip_to_domains.items():
        uniq = sorted(set(ds))
        if len(uniq) > 1:
            correlations.append(f"Shared IP {ip}: {', '.join(uniq)}")

    # URL hosts matching supplied domain indicators
    for url, host in url_hosts.items():
        if host in domain_ips:
            correlations.append(f"URL host overlaps domain IOC: {url} -> {host}")

    # Email domain overlaps supplied domain indicators
    for email, d in email_domains.items():
        if d in domain_ips:
            correlations.append(f"Email domain overlaps domain IOC: {email} -> {d}")

    # ASN overlap between IP IOCs and ASN IOCs
    for ip, asn_label in ip_asn.items():
        if asn_label and asn_label in asn_seen:
            correlations.append(f"IP/ASN overlap: {ip} belongs to {asn_label}")

    correlations = list(dict.fromkeys(correlations))[:12]

    if correlations:
        add_risk(min(20, 3 * len(correlations)), f"{len(correlations)} infrastructure correlations detected")

    risk_score = max(0, min(100, risk_score))
    if risk_score >= 60:
        risk_level = "high"
    elif risk_score >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    if not risk_flags:
        risk_flags = ["No high-signal passive flags detected in this set."]

    return {
        "type": "ioc",
        "target": f"{len(indicators)} indicators",
        "generated_at": now.isoformat(),
        "indicator_count": len(indicators),
        "type_counts": type_counts,
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "flags": risk_flags[:12],
        },
        "correlations": correlations,
        "items": items,
        "notes": [
            "Risk score is heuristic and triage-oriented, not attribution.",
            "Correlations suggest shared infrastructure, not guaranteed common ownership.",
        ],
    }


def render_text(report: dict[str, Any]) -> str:
    lines = []
    lines.append(f"[OSINT HELPER] {report.get('type', '').upper()} :: {report.get('target', '')}")
    lines.append(f"Generated: {report.get('generated_at', '')}")

    t = report.get("type")

    if t == "username":
        lines.append("\nProfiles:")
        profiles = report.get("profiles", {})
        probe_enabled = bool(report.get("probe_enabled"))
        for k, v in profiles.items():
            if probe_enabled and isinstance(v, dict):
                status = v.get("status")
                status_s = str(status) if status is not None else "n/a"
                lines.append(f"- {k}: {v.get('url')} [status {status_s}]")
            else:
                lines.append(f"- {k}: {v}")
        lines.append("\nPivots:")
        for k, v in report.get("pivots", {}).items():
            lines.append(f"- {k}: {v}")

    elif t == "domain":
        lines.append("\nDNS:")
        for rtype, vals in report.get("dns", {}).items():
            val_s = ", ".join(vals) if vals else "(none)"
            lines.append(f"- {rtype}: {val_s}")

        lines.append("\nRDAP:")
        for k, v in report.get("rdap", {}).items():
            if v in (None, [], {}):
                continue
            lines.append(f"- {k}: {v}")

        lines.append("\nPivots:")
        for k, v in report.get("pivots", {}).items():
            lines.append(f"- {k}: {v}")

    elif t == "ip":
        lines.append("\nReverse DNS:")
        lines.append(f"- {report.get('reverse_dns') or '(none)'}")

        lines.append("\nGeo:")
        for k, v in report.get("geo", {}).items():
            if v in (None, ""):
                continue
            lines.append(f"- {k}: {v}")

        lines.append("\nRDAP:")
        for k, v in report.get("rdap", {}).items():
            if v in (None, "", [], {}):
                continue
            lines.append(f"- {k}: {v}")

        asn_lookup = report.get("asn_lookup")
        if isinstance(asn_lookup, dict):
            lines.append("\nASN Lookup:")
            lines.append(f"- asn: {asn_lookup.get('asn')}")
            rdap = asn_lookup.get("rdap") or {}
            if rdap.get("name"):
                lines.append(f"- name: {rdap.get('name')}")
            if rdap.get("country"):
                lines.append(f"- country: {rdap.get('country')}")
            if rdap.get("handle"):
                lines.append(f"- handle: {rdap.get('handle')}")
            piv = asn_lookup.get("pivots") or {}
            if piv:
                lines.append("- pivots:")
                for pk, pv in piv.items():
                    lines.append(f"  - {pk}: {pv}")

        lines.append("\nPivots:")
        for k, v in report.get("pivots", {}).items():
            lines.append(f"- {k}: {v}")

    elif t == "email":
        lines.append("\nCore:")
        lines.append(f"- local_part: {report.get('local_part')}")
        lines.append(f"- domain: {report.get('domain')}")

        lines.append("\nDNS:")
        mx = report.get("mx") or []
        txt = report.get("txt") or []
        lines.append(f"- MX: {', '.join(mx) if mx else '(none)'}")
        lines.append(f"- TXT: {', '.join(txt) if txt else '(none)'}")

        lines.append("\nPivots:")
        for k, v in report.get("pivots", {}).items():
            lines.append(f"- {k}: {v}")

    elif t == "phone":
        lines.append("\nCore:")
        lines.append(f"- E164: {report.get('target')}")
        lines.append(f"- digits: {report.get('digits')}")
        if report.get("country_guess"):
            lines.append(f"- country_guess: {report.get('country_guess')}")

        lines.append("\nPivots:")
        for k, v in report.get("pivots", {}).items():
            lines.append(f"- {k}: {v}")

    elif t == "asn":
        lines.append("\nRDAP:")
        for k, v in report.get("rdap", {}).items():
            if v in (None, "", [], {}):
                continue
            lines.append(f"- {k}: {v}")

        lines.append("\nPivots:")
        for k, v in report.get("pivots", {}).items():
            lines.append(f"- {k}: {v}")

    elif t == "ioc":
        lines.append("\nSummary:")
        lines.append(f"- indicator_count: {report.get('indicator_count')}")

        type_counts = report.get("type_counts") or {}
        if type_counts:
            type_bits = [f"{k}={v}" for k, v in sorted(type_counts.items())]
            lines.append(f"- types: {', '.join(type_bits)}")

        risk = report.get("risk") or {}
        lines.append(f"- risk: {risk.get('score', 0)}/100 ({str(risk.get('level', 'low')).upper()})")

        flags = risk.get("flags") or []
        if flags:
            lines.append("\nRisk flags:")
            for f in flags[:8]:
                lines.append(f"- {f}")

        correlations = report.get("correlations") or []
        if correlations:
            lines.append("\nCorrelations:")
            for c in correlations[:8]:
                lines.append(f"- {c}")

        lines.append("\nIndicators:")
        for item in (report.get("items") or [])[:20]:
            it = item.get("type")
            val = item.get("normalized") or item.get("input")
            if it == "domain":
                ips = item.get("ips") or []
                lines.append(f"- [domain] {val} (ips={len(ips)})")
            elif it == "url":
                host = item.get("host") or "(no-host)"
                lines.append(f"- [url] {val} (host={host})")
            elif it == "ip":
                asn = item.get("asn") or "n/a"
                country = item.get("country") or "n/a"
                lines.append(f"- [ip] {val} (asn={asn}, country={country})")
            elif it == "email":
                d = item.get("domain") or "n/a"
                mx_count = item.get("mx_count")
                lines.append(f"- [email] {val} (domain={d}, mx={mx_count})")
            elif it == "asn":
                name = item.get("name") or "n/a"
                lines.append(f"- [asn] {val} ({name})")
            elif it == "phone":
                cg = item.get("country_guess") or "unknown"
                lines.append(f"- [phone] {val} ({cg})")
            elif str(it).startswith("hash-"):
                lines.append(f"- [{it}] {val}")
            else:
                lines.append(f"- [{it}] {val}")

    notes = report.get("notes") or []
    if notes:
        lines.append("\nNotes:")
        for n in notes:
            lines.append(f"- {n}")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="OSINT Helper (passive recon)")
    p.add_argument("--json", action="store_true", help="Output JSON")

    sub = p.add_subparsers(dest="command", required=True)

    p_user = sub.add_parser("username", help="Username pivot helper")
    p_user.add_argument("value", help="Username (with or without @)")
    p_user.add_argument("--probe", action="store_true", help="Probe profile URLs with HEAD requests")

    p_domain = sub.add_parser("domain", help="Domain recon")
    p_domain.add_argument("value", help="Domain or URL")

    p_ip = sub.add_parser("ip", help="IP recon")
    p_ip.add_argument("value", help="IPv4 or IPv6")

    p_email = sub.add_parser("email", help="Email recon")
    p_email.add_argument("value", help="Email address")

    p_phone = sub.add_parser("phone", help="Phone pivot helper")
    p_phone.add_argument("value", help="Phone number (E.164 preferred)")

    p_asn = sub.add_parser("asn", help="ASN lookup")
    p_asn.add_argument("value", help="ASN value (e.g., AS15169 or 15169)")

    p_ioc = sub.add_parser("ioc", help="IOC correlator (multiple indicators)")
    p_ioc.add_argument("values", nargs="+", help="Indicators (space/comma separated)")

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "username":
            report = build_username_report(args.value, probe=args.probe)
        elif args.command == "domain":
            report = build_domain_report(args.value)
        elif args.command == "ip":
            report = build_ip_report(args.value)
        elif args.command == "email":
            report = build_email_report(args.value)
        elif args.command == "phone":
            report = build_phone_report(args.value)
        elif args.command == "asn":
            report = build_asn_report(args.value)
        elif args.command == "ioc":
            report = build_ioc_report(args.values)
        else:
            parser.error("Unknown command")
            return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"error: unexpected failure: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(render_text(report))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
