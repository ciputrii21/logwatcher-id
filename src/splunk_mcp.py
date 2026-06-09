import os
import json
import requests
import urllib3
from datetime import datetime
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

HEC_URL = os.getenv("SPLUNK_HEC_URL")
HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")

# ============================================================
# MCP Tools — via HEC (yang terbukti bekerja)
# ============================================================

def mcp_log_investigation(email: str, phone: str, breaches: list, risk_score: int) -> dict:
    """MCP Tool 1: log_investigation — kirim hasil investigasi ke Splunk"""
    event = {
        "mcp_tool": "log_investigation",
        "timestamp": datetime.now().isoformat(),
        "query_email": email,
        "query_phone": phone,
        "risk_score": risk_score,
        "total_breaches": len(breaches),
        "breach_sources": [b["breach_source"] for b in breaches],
        "highest_severity": max([b["severity"] for b in breaches], key=lambda x: ["LOW","MEDIUM","HIGH","CRITICAL"].index(x)) if breaches else "NONE"
    }
    return _send_hec(event, "mcp_investigation")

def mcp_log_risk_alert(email: str, risk_score: int, severity: str) -> dict:
    """MCP Tool 2: log_risk_alert — kirim alert jika risk tinggi"""
    if risk_score < 60:
        return {"tool": "log_risk_alert", "status": "skipped", "reason": "Risk score di bawah threshold"}

    event = {
        "mcp_tool": "log_risk_alert",
        "timestamp": datetime.now().isoformat(),
        "alert_type": "HIGH_RISK_DETECTED",
        "query_email": email,
        "risk_score": risk_score,
        "severity": severity,
        "action_required": True,
        "message": f"ALERT: Identitas {email} terdeteksi dalam breach dengan risk score {risk_score}/100"
    }
    return _send_hec(event, "mcp_alert")

def mcp_log_password_check(email: str, pwned: bool, count: int) -> dict:
    """MCP Tool 3: log_password_check — log hasil cek password HIBP"""
    event = {
        "mcp_tool": "log_password_check",
        "timestamp": datetime.now().isoformat(),
        "query_email": email,
        "password_pwned": pwned,
        "pwned_count": count,
        "hibp_source": "HaveIBeenPwned Passwords API",
        "severity": "CRITICAL" if count > 100000 else "HIGH" if pwned else "LOW"
    }
    return _send_hec(event, "mcp_password_check")

def mcp_log_summary_report(email: str, report: str, risk_score: int) -> dict:
    """MCP Tool 4: log_summary_report — simpan laporan AI ke Splunk"""
    event = {
        "mcp_tool": "log_summary_report",
        "timestamp": datetime.now().isoformat(),
        "query_email": email,
        "risk_score": risk_score,
        "report_length": len(report),
        "report_preview": report[:200],
        "ai_model": "llama-3.3-70b-versatile",
        "language": "Bahasa Indonesia"
    }
    return _send_hec(event, "mcp_report")

def _send_hec(event: dict, sourcetype: str) -> dict:
    """Helper: kirim event ke Splunk via HEC"""
    headers = {
        "Authorization": f"Splunk {HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "sourcetype": sourcetype,
        "index": "main",
        "event": event
    }
    try:
        response = requests.post(
            HEC_URL,
            headers=headers,
            data=json.dumps(payload),
            verify=False,
            timeout=10
        )
        return {
            "tool": event["mcp_tool"],
            "status": "success" if response.status_code == 200 else "error",
            "sourcetype": sourcetype
        }
    except Exception as e:
        return {"tool": event.get("mcp_tool"), "status": "error", "message": str(e)}

def run_mcp_pipeline(email: str, phone: str, breaches: list, risk_score: int, password_check: dict, report: str) -> dict:
    """Jalankan semua MCP tools sekaligus"""
    print("\n🔌 Splunk MCP Pipeline — Menjalankan 4 tools...")

    results = {}

    print("  📡 [MCP Tool 1] log_investigation...")
    results["investigation"] = mcp_log_investigation(email, phone, breaches, risk_score)

    print("  🚨 [MCP Tool 2] log_risk_alert...")
    severity = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM"
    results["alert"] = mcp_log_risk_alert(email, risk_score, severity)

    print("  🔐 [MCP Tool 3] log_password_check...")
    results["password"] = mcp_log_password_check(
        email,
        password_check.get("pwned", False),
        password_check.get("count", 0)
    )

    print("  📋 [MCP Tool 4] log_summary_report...")
    results["report"] = mcp_log_summary_report(email, report, risk_score)

    success = sum(1 for r in results.values() if r.get("status") == "success")
    print(f"\n✅ MCP Pipeline selesai — {success}/4 tools berhasil dikirim ke Splunk")

    return results

if __name__ == "__main__":
    # Test MCP pipeline
    dummy_breaches = [
        {"breach_source": "BPJS", "severity": "CRITICAL"},
        {"breach_source": "Tokopedia", "severity": "HIGH"}
    ]
    result = run_mcp_pipeline(
        email="test@gmail.com",
        phone="08123456789",
        breaches=dummy_breaches,
        risk_score=75,
        password_check={"pwned": True, "count": 500000},
        report="Laporan test investigasi keamanan data pribadi."
    )
    print(json.dumps(result, indent=2))
