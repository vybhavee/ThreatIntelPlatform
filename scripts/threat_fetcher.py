import requests
import os
from pymongo import MongoClient
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Connect to MongoDB
client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"))
db = client["threat_intel_db"]
collection = db["threat_indicators"]

def fetch_feodotracker():
    """Feed 1: Feodo Tracker - real botnet C2 IPs"""
    print("[*] Fetching from Feodo Tracker...")
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    response = requests.get(url, timeout=10)
    ips = []
    for line in response.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.append(line)
    return ips

def fetch_emergingthreats():
    """Feed 2: Emerging Threats - known bad IPs"""
    print("[*] Fetching from Emerging Threats...")
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    response = requests.get(url, timeout=10)
    ips = []
    for line in response.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.append(line)
    return ips

def fetch_cinsscore():
    """Feed 3: CINS Score - active threat IPs"""
    print("[*] Fetching from CINS Score...")
    url = "http://cinsscore.com/list/ci-badguys.txt"
    response = requests.get(url, timeout=10)
    ips = []
    for line in response.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.append(line)
    return ips

def save_to_mongodb(ips, source):
    saved = 0
    for ip in ips:
        if not collection.find_one({"ip": ip}):
            collection.insert_one({
                "ip": ip,
                "source": source,
                "risk_score": 85,
                "timestamp": datetime.now(),
                "blocked": False
            })
            saved += 1
    print(f"[+] Saved {saved} new IPs from {source}")

def run_aggregator():
    print("\n====== THREAT INTELLIGENCE AGGREGATOR ======")
    
    try:
        ips1 = fetch_feodotracker()
        save_to_mongodb(ips1, "FeodoTracker")
    except Exception as e:
        print(f"[-] FeodoTracker failed: {e}")

    try:
        ips2 = fetch_emergingthreats()
        save_to_mongodb(ips2, "EmergingThreats")
    except Exception as e:
        print(f"[-] EmergingThreats failed: {e}")

    try:
        ips3 = fetch_cinsscore()
        save_to_mongodb(ips3, "CINSScore")
    except Exception as e:
        print(f"[-] CINSScore failed: {e}")

    total = collection.count_documents({})
    print(f"\n[✓] Total threat indicators in database: {total}")

if __name__ == "__main__":
    run_aggregator()