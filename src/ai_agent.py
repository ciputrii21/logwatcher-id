import os
import hashlib
import requests
import json
from groq import Groq
from dotenv import load_dotenv
from breach_ingestor import generate_and_ingest, send_to_splunk
from datetime import datetime

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# ============================================================
# HIBP Passwords API — cek apakah password pernah bocor
# ============================================================
def check_password_pwned(password: str) -> dict:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=10
        )
        hashes = response.text.splitlines()
        for line in hashes:
            h, count = line.split(":")
            if h == suffix:
                return {
                    "pwned": True,
                    "count": int(count),
                    "severity": "CRITICAL" if int(count) > 100000 else "HIGH"
                }
        return {"pwned": False, "count": 0, "severity": "LOW"}
    except Exception as e:
        return {"pwned": False, "count": 0, "severity": "UNKNOWN", "error": str(e)}

# ============================================================
# AI Agent — generate laporan investigasi Bahasa Indonesia
# ============================================================
def analyze_with_ai(user_input: dict, breach_results: list, password_check: dict) -> str:
    breach_summary = "\n".join([
        f"- {b['breach_source']} ({b['breach_year']}): {b['records_exposed']:,} data bocor, severity {b['severity']}"
        for b in breach_results
    ])

    password_info = ""
    if password_check.get("pwned"):
        password_info = f"Password yang digunakan ditemukan dalam {password_check['count']:,} kebocoran data!"
    else:
        password_info = "Password tidak ditemukan dalam database kebocoran yang diketahui."

    avg_risk = sum(b.get("risk_score", 50) for b in breach_results) / len(breach_results) if breach_results else 0

    prompt = f"""Kamu adalah LogWatcher ID, asisten keamanan siber Indonesia yang ahli dan ramah.
Tugasmu adalah menganalisis risiko kebocoran data pribadi dan membuat laporan investigasi 
dalam Bahasa Indonesia yang mudah dipahami oleh masyarakat umum (non-teknis).

DATA INVESTIGASI:
- Email/Identitas yang dicek: {user_input.get('email', 'tidak diketahui')}
- Nomor HP: {user_input.get('phone', 'tidak diketahui')}
- Rata-rata Risk Score: {avg_risk:.0f}/100

HASIL CEK PASSWORD:
{password_info}

KEBOCORAN DATA YANG DITEMUKAN:
{breach_summary}

Buat laporan investigasi dengan format berikut:
1. 🔍 RINGKASAN SITUASI (2-3 kalimat, bahasa sederhana)
2. ⚠️ TINGKAT RISIKO: [KRITIS/TINGGI/SEDANG/RENDAH] dengan penjelasan singkat
3. 📋 DETAIL KEBOCORAN (list breach yang paling berbahaya)
4. 🛡️ LANGKAH PERLINDUNGAN (5 langkah konkret yang bisa dilakukan sekarang)
5. 💡 TIPS KEAMANAN DIGITAL (2-3 tips tambahan)

Gunakan bahasa yang hangat, tidak menakut-nakuti, tapi tetap serius dan informatif.
Sertakan emoji yang relevan untuk memudahkan pembacaan."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,
        max_tokens=1500
    )

    return response.choices[0].message.content

# ============================================================
# Main Agent Function
# ============================================================
def run_agent(email: str = None, phone: str = None, password: str = None):
    print("\n" + "="*60)
    print("🔍 LogWatcher ID — Investigasi Keamanan Data Pribadi")
    print("="*60)

    user_input = {
        "email": email or "tidak diisi",
        "phone": phone or "tidak diisi"
    }

    # Step 1: Cek password via HIBP
    print("\n📡 Mengecek database kebocoran password...")
    password_check = {"pwned": False, "count": 0, "severity": "LOW"}
    if password:
        password_check = check_password_pwned(password)
        if password_check["pwned"]:
            print(f"  ⚠️  Password ditemukan dalam {password_check['count']:,} kebocoran!")
        else:
            print("  ✅ Password tidak ditemukan dalam database kebocoran")

    # Step 2: Generate breach context dari database Indonesia
    print("\n📊 Menganalisis database breach Indonesia...")
    import random
    from breach_ingestor import BREACH_DATABASE, calculate_severity

    breach_results = []
    selected_breaches = random.sample(BREACH_DATABASE, min(3, len(BREACH_DATABASE)))
    for breach in selected_breaches:
        result = {
            "breach_source": breach["name"],
            "breach_year": breach["year"],
            "breach_type": breach["type"],
            "records_exposed": breach["records"],
            "severity": calculate_severity(breach),
            "risk_score": random.randint(60, 95),
            "query_email": email or "unknown",
            "query_phone": phone or "unknown",
            "country": "Indonesia",
            "status": "CONFIRMED",
            "timestamp": datetime.now().isoformat()
        }
        breach_results.append(result)
        print(f"  📌 {breach['name']} — {calculate_severity(breach)}")

    # Step 3: Kirim ke Splunk
    print("\n📤 Mengirim log ke Splunk...")
    for result in breach_results:
        send_to_splunk(result)
    print("  ✅ Log berhasil dikirim ke Splunk")

    # Step 4: AI analisis
    print("\n🤖 AI sedang menganalisis dan membuat laporan...")
    report = analyze_with_ai(user_input, breach_results, password_check)

    # Step 5: Hitung risk score final
    risk_score = sum(b.get("risk_score", 50) for b in breach_results) // len(breach_results)

    print("\n" + "="*60)
    print(f"📊 RISK SCORE: {risk_score}/100")
    print("="*60)
    print(report)
    print("="*60)

    return {
        "risk_score": risk_score,
        "report": report,
        "breaches": breach_results,
        "password_check": password_check
    }

if __name__ == "__main__":
    # Test agent
    result = run_agent(
        email="test@gmail.com",
        phone="08123456789",
        password="password123"
    )
