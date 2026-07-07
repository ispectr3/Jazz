import json
import os
import re
import sqlite3
import urllib.request
import urllib.error
from datetime import datetime, timedelta


BNVD_API = "https://bnvd.org/api/v1"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DB = os.path.join(os.path.dirname(__file__), "..", "cve_cache.db")


VENDOR_MAP = {
    # Web Servers
    "nginx": "nginx",
    "apache": "apache",
    "iis": "microsoft",
    "tomcat": "apache",
    "jetty": "eclipse",
    "caddy": "caddyserver",
    "openresty": "openresty",
    "litespeed": "litespeedtech",
    "traefik": "traefik",
    "envoy": "envoyproxy",
    "haproxy": "haproxy",
    "varnish": "varnish-software",
    # Languages / Runtimes
    "php": "php",
    "python": "python",
    "ruby": "ruby",
    "node.js": "nodejs",
    "java": "oracle",
    "go": "golang",
    "perl": "perl",
    "rust": "rust-lang",
    "dotnet": "microsoft",
    "asp.net": "microsoft",
    # Frameworks
    "express": "expressjs",
    "django": "djangoproject",
    "flask": "palletsprojects",
    "laravel": "laravel",
    "symfony": "symfony",
    "rails": "rubyonrails",
    "spring boot": "vmware",
    "spring": "vmware",
    "next.js": "vercel",
    "nuxt.js": "nuxt",
    "gatsby": "gatsbyjs",
    "fastapi": "fastapi",
    "koa": "koajs",
    "sveltekit": "svelte",
    # CMS
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "magento": "magento",
    "shopify": "shopify",
    "wix": "wix",
    "squarespace": "squarespace",
    "ghost": "ghost",
    "confluence": "atlassian",
    "hubspot": "hubspot",
    "webflow": "webflow",
    "typo3": "typo3",
    "umbraco": "umbraco",
    "duda": "duda",
    "weebly": "weebly",
    # Frontend / UI
    "react": "facebook",
    "angular": "google",
    "vue.js": "vuejs",
    "svelte": "svelte",
    "bootstrap": "twbs",
    "tailwind css": "tailwindlabs",
    "material ui": "mui",
    "jquery": "jquery",
    # CDN / Edge
    "cloudflare": "cloudflare",
    "cloudfront": "amazon",
    "fastly": "fastly",
    "akamai": "akamai",
    "cloudflare": "cloudflare",
    "keycdn": "keycdn",
    "cdn77": "cdn77",
    "bunnycdn": "bunnycdn",
    "stackpath": "stackpath",
    "imperva": "imperva",
    "sucuri": "sucuri",
    # Cloud Providers
    "aws": "amazon",
    "azure": "microsoft",
    "gcp": "google",
    "heroku": "heroku",
    "vercel": "vercel",
    "netlify": "netlify",
    "digitalocean": "digitalocean",
    "linode": "linode",
    "ovh": "ovh",
    # Security
    "openssl": "openssl",
    "letsencrypt": "letsencrypt",
    "modsecurity": "trustwave",
    "recaptcha": "google",
    "hcaptcha": "intuitionmachines",
    # Databases
    "mysql": "oracle",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "mongodb": "mongodb",
    "redis": "redis",
    "elasticsearch": "elastic",
    "sqlite": "sqlite",
    "cassandra": "apache",
    "couchdb": "apache",
    "neo4j": "neo4j",
    "clickhouse": "clickhouse",
    "dynamodb": "amazon",
    "firebase": "google",
    "supabase": "supabase",
    # Infrastructure / DevOps
    "docker": "docker",
    "kubernetes": "kubernetes",
    "grafana": "grafana",
    "prometheus": "prometheus",
    "vagrant": "hashicorp",
    "terraform": "hashicorp",
    "gitlab": "gitlab",
    "github": "github",
    "jenkins": "jenkins",
    "ansible": "redhat",
    "nginx ingress": "kubernetes",
    "istio": "istio",
    "kong": "kong",
    "consul": "hashicorp",
    "vault": "hashicorp",
    # Monitoring / Observability
    "datadog": "datadog",
    "new relic": "newrelic",
    "sentry": "sentry",
    "jaeger": "jaegertracing",
    "zipkin": "zipkin",
    # API / Messaging
    "graphql": "graphql",
    "swagger": "swagger",
    "rabbitmq": "pivotal",
    "kafka": "apache",
    "nginx": "nginx",
    # Payment
    "stripe": "stripe",
    "paypal": "paypal",
    "mercadopago": "mercadopago",
    "pagseguro": "pagseguro",
    "pix": "bcb",
}


def _get_cache_conn():
    os.makedirs(os.path.dirname(CACHE_DB), exist_ok=True)
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            vendor TEXT, tech TEXT, version TEXT,
            cve_id TEXT, description TEXT, score REAL,
            severity TEXT, exploitability TEXT,
            cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_cve_cache_tech
        ON cve_cache(tech, version)
    """)
    conn.commit()
    return conn


def _cache_get(tech: str, version: str, max_age_hours: int = 24) -> list[dict]:
    conn = _get_cache_conn()
    cutoff = (datetime.now() - timedelta(hours=max_age_hours)).isoformat()
    rows = conn.execute(
        """SELECT cve_id, description, score, severity, exploitability
           FROM cve_cache
           WHERE tech = ? AND version = ? AND cached_at > ?""",
        (tech.lower(), version, cutoff),
    ).fetchall()
    conn.close()
    return [
        {"id": r[0], "description": r[1], "score": r[2],
         "severity": r[3], "exploitability": r[4]}
        for r in rows
    ]


def _cache_set(tech: str, version: str, cves: list[dict]):
    conn = _get_cache_conn()
    for cve in cves:
        conn.execute(
            """INSERT OR REPLACE INTO cve_cache
               (vendor, tech, version, cve_id, description, score, severity, exploitability)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (cve.get("vendor", ""), tech.lower(), version,
             cve["id"], cve.get("description", ""),
             cve.get("score"), cve.get("severity"),
             cve.get("exploitability")),
        )
    conn.commit()
    conn.close()


def _query_bnvd(vendor: str) -> list[dict]:
    url = f"{BNVD_API}/search/vendor/{vendor}?per_page=20"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "JazzNoir/1.0"})
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read().decode())
        cves = []
        for item in data.get("data", []):
            cve_id = item.get("cve_id", "")
            if not cve_id:
                continue
            metrics = item.get("cvss_metrics", {})
            score = None
            severity = "Info"
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    score = metrics[key][0].get("cvssData", {}).get("baseScore")
                    severity = metrics[key][0].get("cvssData", {}).get("baseSeverity", "Info")
                    break
            descs = item.get("descriptions", [])
            desc = ""
            for d in descs:
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:300]
                    break
            if not desc and descs:
                desc = descs[0].get("value", "")[:300]
            cves.append({
                "id": cve_id,
                "description": desc,
                "score": float(score) if score else None,
                "severity": severity.upper() if severity else "INFO",
                "vendor": vendor,
            })
        return cves
    except Exception:
        return []


def _query_nvd_direct(tech: str, version: str) -> list[dict]:
    keyword = f"{tech} {version}" if version else tech
    url = f"{NVD_API}?keywordSearch={urllib.request.quote(keyword)}&resultsPerPage=10"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "JazzNoir/1.0"})
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read().decode())
        cves = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            metrics = cve.get("metrics", {})
            score = None
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics:
                    score = metrics[key][0].get("cvssData", {}).get("baseScore")
                    break
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:300]
                    break
            cves.append({
                "id": cve_id,
                "description": desc,
                "score": float(score) if score else None,
                "severity": _score_to_severity(score),
                "vendor": tech,
            })
        return cves
    except Exception:
        return []


def _score_to_severity(score):
    if score is None:
        return "Info"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def query_cves(tech: str, version: str = "") -> list[dict]:
    cached = _cache_get(tech, version)
    if cached:
        return cached

    tl = tech.lower()
    vendor = VENDOR_MAP.get(tl)

    if not vendor:
        try:
            from app.ai.cve_rag import resolve_vendor
            vendor = resolve_vendor(tl)
        except Exception:
            vendor = None

    cves = []

    if vendor:
        cves = _query_bnvd(vendor)

    if not cves:
        cves = _query_nvd_direct(tech, version)

    if version:
        cves = [c for c in cves if version in c.get("description", "") or version in c["id"]]

    if cves:
        _cache_set(tech, version, cves)
        try:
            from app.ai.cve_rag import add_cve_index
            for cve in cves:
                add_cve_index(tl, cve["id"], cve.get("description", ""),
                              cve.get("score") or 0, cve.get("severity", "Info"))
        except Exception:
            pass

    return cves[:10]


def query_cves_batch(technologies: list[dict]) -> dict:
    results = {}
    for tech in technologies:
        name = tech.get("name", "")
        version = tech.get("version", "")
        cves = query_cves(name, version)
        if cves:
            results[name] = {"version": version, "cves": cves}
    return results


def get_stats() -> dict:
    try:
        req = urllib.request.Request(f"{BNVD_API}/stats", headers={"User-Agent": "JazzNoir/1.0"})
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read().decode()).get("data", {})
    except Exception:
        return {}

    try:
        req = urllib.request.Request(f"{NVD_API}", headers={"User-Agent": "JazzNoir/1.0"})
        resp = urllib.request.urlopen(req, timeout=10)
        return {"nvd": "available"}
    except Exception:
        return {"nvd": "unavailable"}
