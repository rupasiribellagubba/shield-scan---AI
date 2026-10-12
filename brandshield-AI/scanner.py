"""URL analysis: transparent rule-based checks + optional Google Safe Browsing lookup.
The scanner NEVER opens or downloads the URL being scanned (no SSRF / no malware contact)."""
import ipaddress, json, os, re, urllib.request
from urllib.parse import urlsplit


class InvalidURL(ValueError):
    pass


SUSP_TLDS = {"zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "icu", "stream"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "banking", "wallet", "password", "confirm", "suspend", "billing"]
BRANDS = {
    "paypal": ("paypal.com",), "google": ("google.com", "google.co.in", "googleapis.com"),
    "microsoft": ("microsoft.com", "live.com"), "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.in"), "facebook": ("facebook.com",), "netflix": ("netflix.com",),
    "paytm": ("paytm.com",), "hdfcbank": ("hdfcbank.com",), "icicibank": ("icicibank.com",), "whatsapp": ("whatsapp.com",),
}
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}
ADVICE = {
    "Low": "Our checks found few warning signs. That does not prove the site is safe, so stay careful with passwords and payments.",
    "Medium": "Some warning signs found. Do not enter passwords or payment details unless you can confirm the site is genuine.",
    "High": "Many warning signs found. Do not open this link or enter any information. Report it if it reached you by email or message.",
}
DISCLAIMER = "Risk scores are estimates from URL patterns, not proof that a site is safe or malicious."


def _is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def normalize(raw):
    raw = (raw or "").strip() if isinstance(raw, str) else ""
    if not raw or len(raw) > 2048 or re.search(r"\s", raw):
        raise InvalidURL("Enter one URL without spaces (max 2048 characters).")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        p = urlsplit(raw)
        host = (p.hostname or "").encode("idna").decode("ascii")
        port = p.port
    except (ValueError, UnicodeError):
        raise InvalidURL("That does not look like a valid URL.")
    ip = _is_ip(host)
    if p.scheme not in ("http", "https") or not host or not (ip or "." in host):
        raise InvalidURL("Only valid http:// or https:// web addresses are supported.")
    norm = f"{p.scheme}://{host}{':' + str(port) if port else ''}{p.path or '/'}" + (f"?{p.query}" if p.query else "")
    return {"url": norm, "scheme": p.scheme, "host": host, "port": port, "path": p.path,
            "userinfo": p.username is not None, "is_ip": ip}


def registered(host):
    parts = host.split(".")
    n = 3 if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2 else 2
    return ".".join(parts[-n:])


def analyze(n):
    out, host = [], n["host"]

    def add(i, label, pts, detail):
        out.append({"id": i, "label": label, "points": pts, "detail": detail})

    if n["is_ip"]:
        add("ip_host", "Uses an IP address", 25, "Real services normally use a domain name, not a raw IP address.")
    if n["scheme"] == "http":
        add("no_https", "Not using HTTPS", 10, "The connection is not encrypted. Never type passwords or card details here.")
    if n["userinfo"]:
        add("userinfo", "Contains a hidden '@' section", 20, "Text before '@' can disguise the real destination.")
    if "xn--" in host:
        add("punycode", "Look-alike characters in domain", 20, "Punycode (xn--) can imitate well-known names with foreign letters.")
    if not n["is_ip"]:
        reg = registered(host)
        subs = host[: -len(reg)].strip(".")
        if subs and len(subs.split(".")) >= 3:
            add("subdomains", "Many subdomains", 10, "Long subdomain chains are used to bury the real domain.")
        if host.rsplit(".", 1)[-1] in SUSP_TLDS:
            add("tld", "Frequently abused domain ending", 12, f"Domains ending in .{host.rsplit('.', 1)[-1]} are often used for throwaway sites.")
        if host.count("-") >= 3:
            add("hyphens", "Many hyphens in domain", 8, "Lots of hyphens are common in made-up look-alike domains.")
        if reg in SHORTENERS:
            add("shortener", "Link shortener", 10, "The final destination is hidden behind a shortened link.")
        tokens = re.split(r"[^a-z0-9]+", host)
        for b, official in BRANDS.items():
            if (b in tokens or (len(b) >= 6 and b in host.replace(".", ""))) and not any(host == o or host.endswith("." + o) for o in official):
                add("brand", "Possible brand impersonation", 25, f"Contains '{b}' but is not an official {b} domain.")
                break
    if n["port"] and n["port"] not in (80, 443):
        add("port", "Unusual port number", 8, f"Port {n['port']} is not normally used by public websites.")
    kws = [k for k in KEYWORDS if k in host + n["path"].lower()]
    if kws:
        add("keywords", "Sensitive words in address", min(18, 6 * len(kws)), "Found: " + ", ".join(kws[:5]) + ". Phishing pages often use these words.")
    if len(n["url"]) > 100:
        add("long", "Very long URL", 8, "Long addresses can hide the important part.")
    if len(re.findall(r"%[0-9a-fA-F]{2}", n["url"])) >= 5:
        add("encoded", "Heavy URL encoding", 5, "Many %-codes can disguise what the address contains.")
    return out


def safe_browsing(url):
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    src = "Google Safe Browsing"
    if not key:
        return {"source": src, "status": "not_configured",
                "detail": "No API key set. This URL was NOT checked against any external threat database."}
    body = {"client": {"clientId": "shieldscan", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    try:
        req = urllib.request.Request("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + key,
                                     data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.load(r)
    except Exception:
        return {"source": src, "status": "error", "detail": "The lookup failed, so no external result is available."}
    if data.get("matches"):
        kinds = ", ".join(sorted({m.get("threatType", "?") for m in data["matches"]}))
        return {"source": src, "status": "listed", "detail": "Listed as dangerous: " + kinds}
    return {"source": src, "status": "not_listed", "detail": "Not on Google's lists. New threats may not be listed yet."}


def level_for(score):
    return "High" if score >= 60 else "Medium" if score >= 30 else "Low"


def scan_url(raw):
    n = normalize(raw)
    findings = analyze(n)
    intel = safe_browsing(n["url"])
    score = 100 if intel["status"] == "listed" else min(100, sum(f["points"] for f in findings))
    level = level_for(score)
    return {"url": n["url"], "host": n["host"], "score": score, "level": level, "advice": ADVICE[level],
            "findings": findings, "intel": intel, "disclaimer": DISCLAIMER}
