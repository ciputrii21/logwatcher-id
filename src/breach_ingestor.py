import requests
import json
import random
import hashlib
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv()

HEC_URL = os.getenv("SPLUNK_HEC_URL")
HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")

# Data breach Indonesia yang nyata (metadata publik)
BREACH_DATABASE = [
    {"name": "BPJS Kesehatan", "year": 2021, "records": 279000000, "type": "health"},
    {"name": "Tokopedia", "year": 2020, "records": 91000000, "type": "ecommerce"},
    {"name": "KPU Indonesia", "year": 2024, "records": 204000000, "type": "government"},
    {"name": "PLN", "year": 2022, "records": 17000000, "type": "utility"},
    {"name": "BCA", "year": 2020, "records": 2000000, "type": "banking"},
    {"name": "Bukalapak", "year": 2019, "records": 13000000, "type": "ecommerce"},
    {"name": "IndiHome", "year": 2023, "records": 1300000, "type": "telecom"},
]

def generate_dummy_email():
    domains = ["gmail.com", "yahoo.com", "outlook.com", "rocketmail.com"]
    names = ["budi", "siti", "agus", "dewi", "eko", "rina", "hadi", "yuli"]
    return f"{random.choice(names)}{random.randint(1,999)}@{random.choice(domains)}"

def generate_dummy_phone():
    prefixes = ["0811", "0812", "0813", "0821", "0822", "0851", "0852"]
    return f"{random.choice(prefixes)}{random.randint(1000000, 9999999)}"

def calculate_severity(breach):
    if breach["records"] > 100000000:
        return "CRITICAL"
    elif breach["records"] > 10000000:
        return "HIGH"
    elif breach["records"] > 1000000:
        return "MEDIUM"
    else:
        return "LOW"

def send_to_splunk(event_data):
    headers = {
        "Authorization": f"Splunk {HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "sourcetype": "breach_detection",
        "index": "main",
        "event": event_data
    }
    try:
        response = requests.post(
            HEC_URL,
            headers=headers,
            data=json.dumps(payload),
            verify=False
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def generate_and_ingest(email=None, phone=None, count=5):
    print(f"\n🔍 LogWatcher ID — Memulai ingest {count} dummy breach log...")
    success_count = 0

    for i in range(count):
        breach = random.choice(BREACH_DATABASE)
        severity = calculate_severity(breach)

        event = {
            "timestamp": datetime.now().isoformat(),
            "app": "LogWatcher ID",
            "query_email": email or generate_dummy_email(),
            "query_phone": phone or generate_dummy_phone(),
            "breach_source": breach["name"],
            "breach_year": breach["year"],
            "breach_type": breach["type"],
            "records_exposed": breach["records"],
            "severity": severity,
            "risk_score": random.randint(60, 100) if severity == "CRITICAL" else random.randint(30, 59),
            "country": "Indonesia",
            "status": "CONFIRMED"
        }

        if send_to_splunk(event):
            success_count += 1
            print(f"  ✅ [{i+1}/{count}] Log terkirim — {breach['name']} ({severity})")
        else:
            print(f"  ❌ [{i+1}/{count}] Gagal kirim — {breach['name']}")

    print(f"\n📊 Hasil: {success_count}/{count} log berhasil dikirim ke Splunk")
    return success_count

if __name__ == "__main__":
    generate_and_ingest(count=5)
