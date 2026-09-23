import os
import requests
import json

# 建立輸出目錄
OUTPUT_DIR = "ioc_feeds"
os.makedirs(OUTPUT_DIR, exist_ok=True)

HEADERS = {"User-Agent": "Daily-IOC-Crawler/1.0"}

def fetch_threatfox_recent():
    """抓取 ThreatFox 最近的 IOC (包含 IP:Port, Domain, URL, Hashes)"""
    url = "https://threatfox-api.abuse.ch/api/v1/"
    data = {"query": "get_iocs", "days": 1}
    try:
        res = requests.post(url, json=data, headers=HEADERS, timeout=30)
        if res.status_code == 200:
            return res.json().get("data", [])
    except Exception as e:
        print(f"Error fetching ThreatFox: {e}")
    return []

def fetch_urlhaus_recent():
    """抓取 URLhaus 當前活躍的惡意 URL"""
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    try:
        res = requests.get(url, headers=HEADERS, timeout=30)
        if res.status_code == 200:
            return res.json().get("urls", [])
    except Exception as e:
        print(f"Error fetching URLhaus: {e}")
    return []

def main():
    ips = set()
    domains = set()
    urls = set()
    hashes = set()

    print("[*] Fetching ThreatFox...")
    tf_data = fetch_threatfox_recent()
    if tf_data:
        for item in tf_data:
            ioc_type = item.get("ioc_type")
            ioc_val = item.get("ioc_value", "").strip()
            if not ioc_val:
                continue

            if ioc_type in ["ip:port", "ip"]:
                ips.add(ioc_val)
            elif ioc_type == "domain":
                domains.add(ioc_val)
            elif ioc_type == "url":
                urls.add(ioc_val)
            elif "hash" in ioc_type or ioc_type in ["md5", "sha1", "sha256"]:
                hashes.add(ioc_val)

    print("[*] Fetching URLhaus...")
    uh_data = fetch_urlhaus_recent()
    if uh_data:
        for item in uh_data:
            u = item.get("url", "").strip()
            if u:
                urls.add(u)

    # 輸出各類型的純文字列表 (EDL 格式，一行一筆)
    feeds = {
        "ip_list.txt": ips,
        "domain_list.txt": domains,
        "url_list.txt": urls,
        "hash_list.txt": hashes
    }

    for filename, dataset in feeds.items():
        filepath = os.path.join(OUTPUT_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(dataset)))
        print(f"[+] Saved {len(dataset)} items to {filepath}")

if __name__ == "__main__":
    main()
