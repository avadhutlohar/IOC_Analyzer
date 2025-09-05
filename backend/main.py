from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import asyncio
from urllib.parse import quote
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from apis import (
    fetch_abuseipdb,
    fetch_otx,
    fetch_shodan,
    fetch_virustotal,
    fetch_whois_ip,
    fetch_whois_domain,
)
from cache import init_cache, get_cache, set_cache

app = FastAPI(title="IOC Analyzer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- Shared IOC analysis ----------------
async def analyze_ioc(ioc: str, ioc_type: str):
    key = f"{ioc_type}:{ioc}"
    # Skip cache for hash IOCs to test analysis data fetching
    if ioc_type != "hash":
        cached = await get_cache(key)
        if cached:
            return {"ioc": ioc, "type": ioc_type, "source": "cache", "results": cached}

    results = {}

    if ioc_type == "ip":
        abuseipdb, otx, shodan, vt = await asyncio.gather(
            fetch_abuseipdb(ioc),
            fetch_otx(ioc, "IPv4"),
            fetch_shodan(ioc),
            fetch_virustotal(ioc, "ip"),
        )
        results.update({
            "abuseipdb": abuseipdb,
            "otx": otx,
            "shodan": shodan,
            "virustotal": vt,
            "whois": fetch_whois_ip(ioc),
        })

    elif ioc_type == "domain":
        otx, vt = await asyncio.gather(
            fetch_otx(ioc, "domain"),
            fetch_virustotal(ioc, "domain"),
        )
        results.update({
            "otx": otx,
            "virustotal": vt,
            "whois": fetch_whois_domain(ioc),
        })

    elif ioc_type == "url":
        otx, vt = await asyncio.gather(
            fetch_otx(ioc, "url"),
            fetch_virustotal(ioc, "url"),
        )
        host = None
        try:
            host = ioc.split("//", 1)[1].split("/", 1)[0]
        except Exception:
            pass
        whois_data = fetch_whois_domain(host) if host else {}
        results.update({"otx": otx, "virustotal": vt, "whois": whois_data})

    elif ioc_type == "hash":
        otx, vt = await asyncio.gather(
            fetch_otx(ioc, "file"),
            fetch_virustotal(ioc, "hash"),
        )
        results.update({"otx": otx, "virustotal": vt})

    await set_cache(key, results)
    return {"ioc": ioc, "type": ioc_type, "source": "live", "results": results}


# ---------------- Bulk helpers ----------------
def tool_links(ioc: str, ioc_type: str) -> Dict[str, str]:
    vt_map = {
        "ip": f"https://www.virustotal.com/gui/ip-address/{quote(ioc)}",
        "domain": f"https://www.virustotal.com/gui/domain/{quote(ioc)}",
        "hash": f"https://www.virustotal.com/gui/file/{quote(ioc)}",
        "url": f"https://www.virustotal.com/gui/search/{quote(ioc)}",
    }
    links = {
        "virustotal": vt_map.get(ioc_type, f"https://www.virustotal.com/gui/search/{quote(ioc)}"),
        "otx": f"https://otx.alienvault.com/indicator/{ioc_type}/{quote(ioc)}",
    }
    if ioc_type == "ip":
        links.update({
            "abuseipdb": f"https://www.abuseipdb.com/check/{quote(ioc)}",
            "shodan": f"https://www.shodan.io/host/{quote(ioc)}",
        })
    if ioc_type in ("domain", "url"):
        links["whois"] = f"https://lookup.icann.org/en/lookup?name={quote(ioc if ioc_type=='domain' else ioc.split('//',1)[-1].split('/',1)[0])}"
    return links


def summarize_for_bulk(ioc_type: str, results: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    cells: Dict[str, Dict[str, Any]] = {}

    # AbuseIPDB
    if ioc_type == "ip":
        abuse = results.get("abuseipdb", {}) or {}
        data = abuse.get("data", {}) if isinstance(abuse, dict) else {}
        score = data.get("abuseConfidenceScore")
        isp = data.get("isp")
        cells["abuseipdb"] = {
            "score_display": f"{score}% AbuseIPDB" if score is not None else "N/A",
            "summary": f"ISP: {isp}" if isp else "",
        }

    # VirusTotal
    vt = results.get("virustotal", {}) or {}
    attr = (vt.get("data") or {}).get("attributes") if isinstance(vt, dict) else None
    if attr:
        stats = attr.get("last_analysis_stats") or {}
        malicious = stats.get("malicious", 0)
        total = sum(v for v in stats.values() if isinstance(v, int)) or 0
        cells["virustotal"] = {
            "score_display": f"{malicious}/{total} VT" if total else "N/A",
            "summary": f"Rep: {attr.get('reputation', 'N/A')}",
        }
    else:
        cells["virustotal"] = {"score_display": "N/A", "summary": ""}

    # Shodan
    if ioc_type == "ip":
        shodan = results.get("shodan", {}) or {}
        asn = shodan.get("asn")
        ports = shodan.get("ports") or []
        cells["shodan"] = {
            "score_display": "✓" if asn or ports else "N/A",
            "summary": f"ASN: {asn}, Ports: {', '.join(map(str, ports[:5]))}" if asn or ports else "",
        }

    # OTX
    otx = results.get("otx", {}) or {}
    pulse_info = otx.get("pulse_info") or {}
    pcount = pulse_info.get("count")
    cells["otx"] = {
        "score_display": f"Pulses: {pcount}" if pcount is not None else "N/A",
        "summary": "",
    }

    # WHOIS
    whois_data = results.get("whois", {}) or {}
    if ioc_type in ("ip", "domain", "url"):
        org = whois_data.get("org") or None
        country = whois_data.get("country") or whois_data.get("asn_country_code")
        cells["whois"] = {
            "score_display": org or "WHOIS",
            "summary": f"Country: {country}" if country else "",
        }

    return cells


# ---------------- Pydantic models ----------------
class BulkRequest(BaseModel):
    type: str = Field(..., pattern="^(ip|domain|url|hash)$")
    values: List[str]


# ---------------- Startup ----------------
@app.on_event("startup")
async def startup():
    await init_cache()

@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "IOC Analyzer API is running"}


# ---------------- Routes ----------------
@app.get("/analyze/ip/{ip}")
async def analyze_ip(ip: str):
    return await analyze_ioc(ip, "ip")


@app.get("/analyze/domain/{domain}")
async def analyze_domain(domain: str):
    return await analyze_ioc(domain, "domain")


@app.get("/analyze/url/{url:path}")
async def analyze_url(url: str):
    return await analyze_ioc(url, "url")


@app.get("/analyze/hash/{hash}")
async def analyze_hash(hash: str):
    return await analyze_ioc(hash, "hash")


@app.post("/analyze/bulk")
async def analyze_bulk(req: BulkRequest):
    vals = list({v.strip() for v in req.values if v.strip()})
    tasks = [analyze_ioc(v, req.type) for v in vals]
    results = await asyncio.gather(*tasks)

    rows = []
    for item in results:
        ioc = item["ioc"]
        cells = summarize_for_bulk(req.type, item["results"])
        links = tool_links(ioc, req.type)
        for tool in cells:
            if tool in links:
                cells[tool]["link"] = links[tool]
        rows.append({"ioc": ioc, "cells": cells})

    return {"type": req.type, "rows": rows}
