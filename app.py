import streamlit as st
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from ai_agent import run_agent
from splunk_mcp import run_mcp_pipeline

st.set_page_config(page_title="LogWatcher ID", page_icon="🔍", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
.main-header{background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460);padding:2rem;border-radius:12px;text-align:center;margin-bottom:2rem;border:1px solid #e94560;}
.main-title{color:#e94560;font-size:2.5rem;font-weight:800;margin:0;}
.main-subtitle{color:#a8b2d8;font-size:1rem;margin-top:0.5rem;}
.risk-critical{background:linear-gradient(135deg,#ff0000,#8b0000);color:white;padding:1.5rem;border-radius:12px;text-align:center;font-size:2rem;font-weight:800;}
.risk-high{background:linear-gradient(135deg,#ff6b35,#d63000);color:white;padding:1.5rem;border-radius:12px;text-align:center;font-size:2rem;font-weight:800;}
.risk-medium{background:linear-gradient(135deg,#ffd700,#b8860b);color:black;padding:1.5rem;border-radius:12px;text-align:center;font-size:2rem;font-weight:800;}
.risk-low{background:linear-gradient(135deg,#00b09b,#006650);color:white;padding:1.5rem;border-radius:12px;text-align:center;font-size:2rem;font-weight:800;}
.breach-card{background:#1e1e2e;border:1px solid #333;border-radius:8px;padding:1rem;margin:0.5rem 0;}
.info-box{background:#0d1117;border-left:4px solid #e94560;padding:1rem;border-radius:4px;margin:1rem 0;}
.splunk-badge{background:#ff6900;color:white;padding:0.2rem 0.6rem;border-radius:20px;font-size:0.75rem;font-weight:600;}
.mcp-badge{background:#0066cc;color:white;padding:0.2rem 0.6rem;border-radius:20px;font-size:0.75rem;font-weight:600;}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="main-header">
    <p class="main-title">🔍 LogWatcher ID</p>
    <p class="main-subtitle">AI Agent for Indonesian Personal Data Breach Detection</p>
    <p style="color:#666;font-size:0.8rem;margin-top:0.5rem;">
        <span class="splunk-badge">Powered by Splunk</span>&nbsp;
        <span class="mcp-badge">MCP Enabled</span>&nbsp;
        Powered by Groq AI
    </p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### 🌐 Language / Bahasa")
    language = st.radio("Report language:", options=["🇮🇩 Bahasa Indonesia", "🇬🇧 English"], index=0)
    lang_code = "id" if "Indonesia" in language else "en"
    st.markdown("---")
    st.markdown("### 🛡️ About LogWatcher ID")
    if lang_code == "en":
        st.markdown("LogWatcher ID is an AI agent that helps Indonesians check if their personal data has been breached.\n\n**Features:**\n- Check email & phone\n- Detect breached passwords\n- Bilingual report\n- Risk Score 0-100\n- Splunk MCP logging")
    else:
        st.markdown("LogWatcher ID adalah AI agent yang membantu masyarakat Indonesia mengecek apakah data pribadi mereka pernah bocor.\n\n**Fitur:**\n- Cek email & nomor HP\n- Deteksi password bocor\n- Laporan bilingual\n- Risk Score 0-100\n- Log ke Splunk via MCP")
    st.markdown("---")
    st.markdown("### 📊 Database Breach Indonesia")
    for name, records in [("BPJS Kesehatan","279 juta"),("KPU","204 juta"),("Tokopedia","91 juta"),("Bukalapak","13 juta"),("PLN","17 juta"),("IndiHome","1.3 juta"),("BCA","2 juta")]:
        st.markdown(f"• **{name}** — {records} data")
    st.markdown("---")
    st.caption("For educational purposes only." if lang_code == "en" else "Tool ini untuk edukasi.")

if lang_code == "en":
    st.markdown("## 🔎 Check Your Personal Data")
    st.markdown("Enter the information you want to check. **You don't need to fill all fields.**")
    email_label,email_ph,phone_label,phone_ph = "📧 Email Address","example: yourname@gmail.com","📱 Phone Number","example: 08123456789"
    pass_label,pass_ph = "🔐 Password (optional)","Enter password to check"
    btn_label,spinner1,spinner2 = "🔍 Start Investigation","🤖 AI Agent is investigating...","📤 Sending logs to Splunk via MCP..."
    result_title,report_title,breach_title,mcp_title = "## 📊 Investigation Results","### 📋 AI Investigation Report","### 🗂️ Breach Details","### 🔌 Splunk MCP Log"
    privacy = "Your privacy is protected: Password is converted to SHA-1 hash before being sent to HaveIBeenPwned."
    m1,m2,m3,m4 = "🔍 Breaches Found","🔐 Password Breached","🔌 MCP Tools","📍 Country"
    err_msg = "⚠️ Please enter at least an email or phone number."
    safe_txt,success_txt = "Safe ✅","✅ Investigation complete! Logs sent to Splunk via MCP."
    lvl_c,lvl_h,lvl_m,lvl_l = "🔴 CRITICAL","🟠 HIGH","🟡 MEDIUM","🟢 LOW"
else:
    st.markdown("## 🔎 Cek Data Pribadimu")
    st.markdown("Masukkan informasi yang ingin kamu cek. **Tidak perlu isi semua.**")
    email_label,email_ph,phone_label,phone_ph = "📧 Alamat Email","contoh: namakamu@gmail.com","📱 Nomor HP","contoh: 08123456789"
    pass_label,pass_ph = "🔐 Password (opsional)","Masukkan password untuk dicek"
    btn_label,spinner1,spinner2 = "🔍 Mulai Investigasi","🤖 AI Agent sedang menginvestigasi...","📤 Mengirim log ke Splunk via MCP..."
    result_title,report_title,breach_title,mcp_title = "## 📊 Hasil Investigasi","### 📋 Laporan Investigasi AI","### 🗂️ Detail Breach","### 🔌 Splunk MCP Log"
    privacy = "Privasi terjaga: Password dikonversi ke hash SHA-1 sebelum dikirim ke HaveIBeenPwned."
    m1,m2,m3,m4 = "🔍 Breach Ditemukan","🔐 Password Bocor","🔌 MCP Tools","📍 Negara"
    err_msg = "⚠️ Masukkan minimal email atau nomor HP."
    safe_txt,success_txt = "Aman ✅","✅ Investigasi selesai! Log telah dikirim ke Splunk via MCP."
    lvl_c,lvl_h,lvl_m,lvl_l = "🔴 KRITIS","🟠 TINGGI","🟡 SEDANG","🟢 RENDAH"

col1,col2 = st.columns(2)
with col1:
    email = st.text_input(email_label, placeholder=email_ph)
with col2:
    phone = st.text_input(phone_label, placeholder=phone_ph)
password = st.text_input(pass_label, type="password", placeholder=pass_ph)
st.markdown(f'''<div class="info-box">💡 {privacy}</div>''', unsafe_allow_html=True)
cek_button = st.button(btn_label, type="primary", use_container_width=True)

if cek_button:
    if not email and not phone:
        st.error(err_msg)
    else:
        with st.spinner(spinner1):
            result = run_agent(email=email or None, phone=phone or None, password=password or None, language=lang_code)
        risk_score = result["risk_score"]
        report = result["report"]
        breaches = result["breaches"]
        password_check = result["password_check"]
        with st.spinner(spinner2):
            mcp_result = run_mcp_pipeline(email=email or "anonymous", phone=phone or "anonymous", breaches=breaches, risk_score=risk_score, password_check=password_check, report=report)
        st.markdown("---")
        st.markdown(result_title)
        col1,col2,col3 = st.columns([1,2,1])
        with col2:
            if risk_score >= 80:
                css,label = "risk-critical",lvl_c
            elif risk_score >= 60:
                css,label = "risk-high",lvl_h
            elif risk_score >= 30:
                css,label = "risk-medium",lvl_m
            else:
                css,label = "risk-low",lvl_l
            st.markdown(f'''<div class="{css}">RISK SCORE<br>{risk_score}/100<br><span style="font-size:1rem;">{label}</span></div>''', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        col1,col2,col3,col4 = st.columns(4)
        with col1: st.metric(m1, len(breaches))
        with col2: st.metric(m2, f"{password_check.get('count',0):,}x" if password_check.get("pwned") else safe_txt)
        with col3: st.metric(m3, f"{sum(1 for v in mcp_result.values() if v.get('status')=='success')}/4")
        with col4: st.metric(m4, "🇮🇩 Indonesia")
        st.markdown("---")
        col1,col2 = st.columns([3,2])
        with col1:
            st.markdown(report_title)
            st.markdown(report)
        with col2:
            st.markdown(breach_title)
            for b in breaches:
                sc = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(b["severity"],"⚪")
                st.markdown(f'''<div class="breach-card">{sc} <strong>{b["breach_source"]}</strong> ({b["breach_year"]})<br><small>📊 {b["records_exposed"]:,} data | ⚡ {b["severity"]} | Score: {b["risk_score"]}</small></div>''', unsafe_allow_html=True)
            st.markdown(mcp_title)
            for tool,res in mcp_result.items():
                st.markdown(f'{"✅" if res.get("status")=="success" else "⚠️"} `{res.get("tool",tool)}`')
        st.markdown("---")
        st.success(success_txt)
