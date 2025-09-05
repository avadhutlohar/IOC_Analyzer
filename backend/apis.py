import os
import ssl
import aiohttp
import whois
from ipwhois import IPWhois


async def fetch_abuseipdb(ip: str):
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    if not ABUSEIPDB_API_KEY:
        return {"error": "AbuseIPDB API key not configured"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=headers, params=params) as resp:
                return await resp.json()
    except Exception as e:
        return {"error": str(e)}


async def fetch_otx(ioc: str, ioc_type: str):
    OTX_API_KEY = os.getenv("OTX_API_KEY")
    if not OTX_API_KEY:
        return {"error": "OTX API key not configured"}
    
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            # Fetch general information
            general_url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/general"
            async with session.get(general_url, headers=headers) as resp:
                general_data = await resp.json()
            
            # Fetch additional endpoints for more comprehensive data
            additional_data = {}
            
            # Fetch malware data
            try:
                malware_url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/malware"
                async with session.get(malware_url, headers=headers) as resp:
                    if resp.status == 200:
                        additional_data['malware'] = await resp.json()
            except:
                pass
            
            # Fetch analysis data for file hashes
            if ioc_type == "file":
                try:
                    # OTX uses 'file' as the indicator type for the analysis endpoint
                    analysis_url = f"https://otx.alienvault.com/api/v1/indicators/file/{ioc}/analysis"
                    print(f"Fetching analysis from: {analysis_url}")
                    async with session.get(analysis_url, headers=headers) as resp:
                        print(f"Analysis response status: {resp.status}")
                        if resp.status == 200:
                            analysis_data = await resp.json()
                            print(f"Analysis data keys: {list(analysis_data.keys()) if analysis_data else 'None'}")
                            additional_data['analysis'] = analysis_data
                        else:
                            print(f"Analysis response error: {await resp.text()}")
                except Exception as e:
                    print(f"Analysis fetch error: {e}")
                    pass
            
            # Fetch URL list for IPs
            if ioc_type == "IPv4":
                try:
                    url_list_url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/url_list"
                    async with session.get(url_list_url, headers=headers) as resp:
                        if resp.status == 200:
                            additional_data['url_list'] = await resp.json()
                except:
                    pass
                
                # Fetch passive DNS
                try:
                    passive_dns_url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/passive_dns"
                    async with session.get(passive_dns_url, headers=headers) as resp:
                        if resp.status == 200:
                            additional_data['passive_dns'] = await resp.json()
                except:
                    pass
            
            # Merge additional data into general data
            general_data.update(additional_data)
            return general_data
            
    except Exception as e:
        return {"error": str(e)}


async def fetch_shodan(ip: str):
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    if not SHODAN_API_KEY:
        return {"error": "Shodan API key not configured"}
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url) as resp:
                return await resp.json()
    except Exception as e:
        return {"error": str(e)}


async def fetch_virustotal(ioc: str, ioc_type: str):
    VT_API_KEY = os.getenv("VT_API_KEY")
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}
    
    try:
        if ioc_type == "url":
            url = "https://www.virustotal.com/api/v3/urls"
            headers = {"x-apikey": VT_API_KEY}
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(url, headers=headers, data={"url": ioc}) as resp:
                    res = await resp.json()
                    if "data" in res and "id" in res["data"]:
                        analysis_id = res["data"]["id"]
                        async with session.get(f"{url}/{analysis_id}", headers=headers) as r2:
                            return await r2.json()
                    return res
        else:
            mapping = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}
            vt_type = mapping.get(ioc_type, "urls")
            url = f"https://www.virustotal.com/api/v3/{vt_type}/{ioc}"
            headers = {"x-apikey": VT_API_KEY}
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, headers=headers) as resp:
                    return await resp.json()
    except Exception as e:
        return {"error": str(e)}


def fetch_whois_ip(ip: str):
    try:
        obj = IPWhois(ip)
        return obj.lookup_whois()
    except Exception as e:
        return {"error": str(e)}


def fetch_whois_domain(domain: str):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "org": w.org,
            "country": w.country,
        }
    except Exception as e:
        return {"error": str(e)}
