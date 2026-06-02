import os
from pymongo import MongoClient
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"))
db = client["threat_intel_db"]
collection = db["threat_indicators"]

RULES_FILE = "blocked_ips_rules.txt"
LOG_FILE = "enforcement_log.txt"

def enforce_policies():
    print("\n====== DYNAMIC POLICY ENFORCER ======")
    
    threats = collection.find({"risk_score": {"$gte": 70}, "blocked": False})
    
    blocked_count = 0
    with open(RULES_FILE, "a") as rules, open(LOG_FILE, "a") as log:
        for threat in threats:
            ip = threat["ip"]
            
            rule = f"iptables -A INPUT -s {ip} -j DROP"
            rules.write(rule + "\n")
            
            log_entry = f"[{datetime.now()}] BLOCKED {ip} | Source: {threat['source']} | Risk: {threat['risk_score']}\n"
            log.write(log_entry)
            print(f"[BLOCKED] {ip}")
            
            collection.update_one(
                {"_id": threat["_id"]}, 
                {"$set": {"blocked": True}}
            )
            blocked_count += 1
    
    print(f"\n[✓] Enforced rules for {blocked_count} IPs")
    print(f"[✓] Rules saved to: {RULES_FILE}")
    print(f"[✓] Log saved to: {LOG_FILE}")

def rollback_ip(ip_address):
    """Rollback/unblock a specific IP for false positives"""
    result = collection.update_one(
        {"ip": ip_address},
        {"$set": {"blocked": False}}
    )
    if result.modified_count:
        print(f"[✓] ROLLBACK: {ip_address} has been unblocked")
        with open(LOG_FILE, "a") as log:
            log.write(f"[{datetime.now()}] ROLLBACK {ip_address} - False positive removed\n")
    else:
        print(f"[-] IP {ip_address} not found in database")

if __name__ == "__main__":
    enforce_policies()