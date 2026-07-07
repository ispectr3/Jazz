import os
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings

RAG_DIR = os.path.join(".ralph", "cve_rag")
COLLECTION_NAME = "cve_index"

TECH_DESCRIPTIONS = {
    "nginx": "Nginx web server reverse proxy load balancer HTTP HTTPS",
    "apache": "Apache HTTP Server web server",
    "iis": "Microsoft IIS web server Windows",
    "tomcat": "Apache Tomcat servlet container Java Jakarta",
    "jetty": "Eclipse Jetty web server Java servlet",
    "caddy": "Caddy web server reverse proxy automatic HTTPS",
    "openresty": "OpenResty Lua Nginx web platform",
    "litespeed": "LiteSpeed web server HTTP",
    "traefik": "Traefik reverse proxy load balancer HTTP",
    "envoy": "Envoy proxy load balancer service mesh",
    "haproxy": "HAProxy load balancer proxy TCP HTTP",
    "varnish": "Varnish Cache HTTP accelerator reverse proxy",
    "php": "PHP hypertext preprocessor scripting language web",
    "python": "Python programming language runtime",
    "ruby": "Ruby programming language runtime",
    "node.js": "Node.js JavaScript runtime server-side",
    "node": "Node.js JavaScript runtime",
    "java": "Java programming language runtime JVM",
    "go": "Go programming language golang",
    "rust": "Rust programming language",
    "dotnet": ".NET framework Microsoft ASP.NET",
    "asp.net": "ASP.NET Microsoft web framework",
    "express": "Express.js web framework for Node.js",
    "django": "Django Python web framework",
    "flask": "Flask Python micro web framework",
    "laravel": "Laravel PHP web framework",
    "symfony": "Symfony PHP web framework",
    "rails": "Ruby on Rails web framework",
    "spring boot": "Spring Boot Java framework",
    "spring": "Spring Framework Java enterprise",
    "next.js": "Next.js React framework server-side rendering",
    "nuxt.js": "Nuxt.js Vue.js framework",
    "gatsby": "Gatsby React static site generator",
    "fastapi": "FastAPI Python web framework",
    "koa": "Koa.js Node.js web framework",
    "sveltekit": "SvelteKit Svelte web framework",
    "fastify": "Fastify fast Node.js web framework",
    "wordpress": "WordPress CMS content management PHP",
    "drupal": "Drupal CMS content management PHP",
    "joomla": "Joomla CMS content management PHP",
    "magento": "Magento Adobe e-commerce platform PHP",
    "shopify": "Shopify e-commerce platform",
    "ghost": "Ghost blogging platform Node.js",
    "confluence": "Confluence Atlassian collaboration wiki",
    "typo3": "TYPO3 CMS content management PHP",
    "umbraco": "Umbraco CMS .NET content management",
    "react": "React JavaScript frontend library UI",
    "angular": "Angular TypeScript frontend framework",
    "vue.js": "Vue.js JavaScript frontend framework",
    "vue": "Vue.js frontend framework JavaScript",
    "svelte": "Svelte JavaScript frontend compiler",
    "bootstrap": "Bootstrap CSS framework responsive",
    "tailwind css": "Tailwind CSS utility framework",
    "material ui": "MUI Material Design React components",
    "jquery": "jQuery JavaScript library DOM",
    "cloudflare": "Cloudflare CDN security DDoS WAF",
    "cloudfront": "AWS CloudFront CDN Amazon",
    "fastly": "Fastly CDN edge computing",
    "aws": "Amazon Web Services cloud provider",
    "azure": "Microsoft Azure cloud provider",
    "gcp": "Google Cloud Platform cloud provider",
    "heroku": "Heroku cloud platform",
    "vercel": "Vercel deployment hosting frontend",
    "netlify": "Netlify hosting deployment serverless",
    "mysql": "MySQL relational database Oracle",
    "mariadb": "MariaDB relational database",
    "postgresql": "PostgreSQL relational database",
    "mongodb": "MongoDB NoSQL document database",
    "redis": "Redis in-memory cache data store",
    "elasticsearch": "Elasticsearch search engine analytics",
    "sqlite": "SQLite embedded database",
    "docker": "Docker container runtime platform",
    "kubernetes": "Kubernetes container orchestration k8s",
    "grafana": "Grafana monitoring observability dashboard",
    "prometheus": "Prometheus monitoring time-series",
    "graphql": "GraphQL API query language",
    "hono": "Hono lightweight web framework for edge Node.js",
    "solidjs": "SolidJS JavaScript UI library frontend reactive",
    "preact": "Preact fast React alternative JavaScript UI",
    "alpine.js": "Alpine.js lightweight JavaScript framework",
    "htmx": "htmx HTML hypermedia JavaScript library",
    "stimulus": "Stimulus JavaScript framework HTML",
    "turbo": "Hotwire Turbo JavaScript library",
    "livewire": "Livewire Laravel dynamic PHP framework",
    "inertia": "Inertia.js adapter server-side framework",
    "alpine": "Alpine.js lightweight JavaScript framework",
    "sanic": "Sanic Python async web framework",
    "aiohttp": "aiohttp Python async HTTP server",
    "tornado": "Tornado Python web framework async",
    "starlette": "Starlette Python ASGI framework",
    "elysia": "Elysia Bun web framework TypeScript",
    "bun": "Bun JavaScript runtime bundler npm alternative",
    "deno": "Deno JavaScript TypeScript runtime Node alternative",
    "pnpm": "pnpm fast disk space efficient package manager",
    "yarn": "Yarn JavaScript package manager",
    "npm": "npm Node package manager",
    "webpack": "Webpack JavaScript module bundler",
    "vite": "Vite frontend build tool bundler dev server",
    "esbuild": "esbuild fast JavaScript bundler",
    "rollup": "Rollup JavaScript module bundler",
    "parcel": "Parcel web application bundler",
    "tailscale": "Tailscale VPN mesh networking WireGuard",
    "wireguard": "WireGuard VPN secure network tunnel",
    "hashicorp": "HashiCorp infrastructure cloud Terraform Vault",
    "terraform": "Terraform HashiCorp infrastructure as code",
    "vault": "Vault HashiCorp secrets management",
    "consul": "Consul HashiCorp service mesh networking",
    "nomad": "Nomad HashiCorp workload orchestrator",
    "packer": "Packer HashiCorp machine image builder",
    "vagrant": "Vagrant HashiCorp virtual machine environment",
    "pulumi": "Pulumi infrastructure as code cloud engineering",
    "crossplane": "Crossplane cloud control plane Kubernetes",
    "istio": "Istio service mesh Kubernetes",
    "linkerd": "Linkerd service mesh Kubernetes",
    "consul connect": "Consul Connect service mesh HashiCorp",
    "cilium": "Cilium eBPF Kubernetes networking security",
    "calico": "Calico Kubernetes networking security",
    "flannel": "Flannel Kubernetes networking overlay",
    "kustomize": "Kustomize Kubernetes configuration customization",
    "helm": "Helm Kubernetes package manager",
    "argocd": "ArgoCD Kubernetes deployment GitOps continuous delivery",
    "flux": "Flux Kubernetes GitOps operator",
    "jenkins": "Jenkins continuous integration CI server",
    "github actions": "GitHub Actions CI CD workflow automation",
    "gitlab ci": "GitLab CI continuous integration pipeline",
    "circleci": "CircleCI continuous integration platform",
    "travis ci": "Travis CI continuous integration service",
    "keycloak": "Keycloak identity access management SSO OpenID",
    "auth0": "Auth0 authentication authorization platform",
    "okta": "Okta identity management single sign-on",
    "fission": "Fission serverless Kubernetes functions",
    "knative": "Knative serverless Kubernetes platform",
    "openfaas": "OpenFaaS serverless functions Docker Kubernetes",
    "envoyproxy": "Envoy proxy sidecar service mesh",
    "httpx": "httpx Python HTTP client",
    "requests": "requests Python HTTP library",
    "axios": "axios JavaScript HTTP client",
    "swr": "SWR React data fetching stale while revalidate",
    "react query": "TanStack React Query data fetching caching",
    "redux": "Redux JavaScript state management React",
    "zustand": "Zustand React state management",
    "pinia": "Pinia Vue.js state management",
    "vuex": "Vuex Vue.js state management",
    "solid-start": "SolidStart SolidJS meta framework",
    "remix": "Remix React framework web fundamentals",
    "qwik": "Qwik JavaScript framework resumable",
}


def _get_descriptions() -> Dict[str, str]:
    return TECH_DESCRIPTIONS


def _get_collection() -> Any:
    os.makedirs(RAG_DIR, exist_ok=True)
    client = chromadb.PersistentClient(
        path=RAG_DIR,
        settings=Settings(anonymized_telemetry=False, allow_reset=True),
    )
    try:
        return client.get_or_create_collection(
            COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
    except Exception:
        return client.create_collection(
            COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )


def find_similar_techs(tech_name: str, top_k: int = 3) -> List[Dict[str, Any]]:
    collection = _get_collection()
    desc = _get_descriptions()
    query = desc.get(tech_name.lower(), tech_name)
    try:
        results = collection.query(
            query_texts=[query],
            n_results=min(top_k * 2, collection.count()),
            where={"type": {"$eq": "tech"}},
        )
    except Exception:
        return []

    distances = results.get("distances", [[]])[0] or []
    metadatas = results.get("metadatas", [[]])[0] or []
    documents = (results.get("documents", [[]])[0] or []) if results.get("documents") else []
    matches = []
    for i, meta in enumerate(metadatas):
        if not meta:
            continue
        distance = distances[i] if i < len(distances) else 0
        matches.append({
            "name": meta.get("name", ""),
            "similarity": round(1 - float(distance), 3),
            "description": documents[i] if i < len(documents) else "",
        })
    return matches


def resolve_vendor(tech_name: str) -> Optional[str]:
    from app.ai.cve_database import VENDOR_MAP

    tl = tech_name.lower()
    if tl in VENDOR_MAP:
        return VENDOR_MAP[tl]

    desc = _get_descriptions()
    desc_lower = {k.lower(): k for k in desc}
    if tl in desc_lower:
        orig_key = desc_lower[tl]
        if orig_key in VENDOR_MAP:
            return VENDOR_MAP[orig_key]

    similar = find_similar_techs(tl, top_k=3)
    for s in similar:
        sn = s["name"]
        if sn in VENDOR_MAP:
            return VENDOR_MAP[sn]

    for key, vendor_name in VENDOR_MAP.items():
        if tl in key or key in tl:
            return vendor_name

    return None


def add_cve_index(tech: str, cve_id: str, description: str, score: float = 0, severity: str = "Info"):
    collection = _get_collection()
    doc_id = f"cve_{cve_id}"
    try:
        collection.get([doc_id])
        return
    except Exception:
        pass
    try:
        collection.add(
            documents=[f"{tech}: {description}"],
            metadatas=[{
                "type": "cve",
                "tech": tech.lower(),
                "cve_id": cve_id,
                "score": score or 0,
                "severity": severity or "Info",
            }],
            ids=[doc_id],
        )
    except Exception:
        pass


def add_tech_index(tech_name: str, description: str):
    collection = _get_collection()
    doc_id = f"tech_{tech_name}"
    try:
        collection.get([doc_id])
        return
    except Exception:
        pass
    try:
        collection.add(
            documents=[description],
            metadatas=[{"type": "tech", "name": tech_name}],
            ids=[doc_id],
        )
    except Exception:
        pass


def init_index():
    collection = _get_collection()
    if collection.count() > 0:
        existing = collection.count()
        try:
            existing_techs = collection.get(where={"type": {"$eq": "tech"}})
            if existing_techs and len(existing_techs.get("ids", [])) >= len(_get_descriptions()):
                return existing
        except Exception:
            pass
        return existing

    docs = []
    metas = []
    ids = []
    for tech, desc in _get_descriptions().items():
        docs.append(desc)
        metas.append({"type": "tech", "name": tech})
        ids.append(f"tech_{tech}")

    try:
        collection.add(documents=docs, metadatas=metas, ids=ids)
    except Exception:
        pass

    try:
        from app.ai.cve_database import _get_cache_conn
        conn = _get_cache_conn()
        rows = conn.execute(
            "SELECT DISTINCT tech, cve_id, description, score, severity FROM cve_cache"
        ).fetchall()
        conn.close()
        cve_docs = []
        cve_metas = []
        cve_ids = []
        for row in rows:
            tech, cve_id, desc, score, severity = row
            cve_docs.append(f"{tech}: {desc}")
            cve_metas.append({
                "type": "cve",
                "tech": tech,
                "cve_id": cve_id,
                "score": score or 0,
                "severity": severity or "Info",
            })
            cve_ids.append(f"cve_{cve_id}")
        if cve_docs:
            collection.add(documents=cve_docs, metadatas=cve_metas, ids=cve_ids)
    except Exception:
        pass

    return collection.count()


def get_stats() -> Dict[str, Any]:
    collection = _get_collection()
    count = collection.count()
    return {
        "indexed_documents": count,
        "technologies_indexed": len(_get_descriptions()),
        "ready": count > 0,
    }
