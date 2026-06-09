import streamlit as st
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from ai_agent import run_agent, check_password_pwned
from splunk_mcp import run_mcp_pipeline

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="LogWatcher ID",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CSS STYLING
# ============================================================
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460);
        padding: 2rem;
        border-radius: 12px;
        text-align: center;
        margin-bottom: 2rem;
        border: 1px solid #e94560;
    }
    .main-title {
        color: #e94560;
        font-size: 2.5rem;
        font-weight: 800;
        margin: 0;
    }
    .main-subtitle {
        color: #a8b2d8;
        font-size: 1rem;
        margin-top: 0.5rem;
    }
    .risk-critical {
        background: linear-gradient(135deg, #ff0000, #8b0000);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        text-align: center;
        font-size: 2rem;
        font-weight: 800;
    }
    .risk-high {
        background: linear-gradient(135deg, #ff6b35, #d63000);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        text-align: center;
        font-size: 2rem;
        font-weight: 800;
    }
    .risk-medium {
        background: linear-gradient(135deg, #ffd700, #b8860b);
        color: black;
        padding: 1.5rem;
        border-radius: 12px;
        text-align: center;
        font-size: 2rem;
        font-weight: 800;
    }
    .risk-low {
        background: linear-gradient(135deg, #00b09b, #006650);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        text-align: center;
        font-size: 2rem;
        font-weight: 800;
    }
    .breach-card {
        background: #1e1e2e;
        border: 1px solid #333;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .info-box {
        background: #0d1117;
        border-left: 4px solid #e94560;
        padding: 1rem;
        border-radius: 4px;
        margin: 1rem 0;
    }
    .splunk-badge {
        background: #ff6900;
        color: white;
        padding: 0.2rem 0.6rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .mcp-badge {
        background: #0066cc;
        color: white;
        padding: 0.2rem 0.6rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================
# HEADER
# ============================================================
st.markdown("""
<div class="main-header">
    <p class="main-title">🔍 LogWatcher ID</p>
    <p class="main-subtitle">AI Agent Deteksi Kebocoran Data Pribadi Indonesia</p>
    <p style="color: #666; font-size: 0.8rem; margin-top: 0.5rem;">
        <span class="splunk-badge">⚡ Powered by Splunk</span>&nbsp;
        <span class="mcp-badge">🔌 MCP Enabled</span>&nbsp;
        Powered by Groq AI • Data breach Indonesia
    </p>
</div>
""", unsafe_allow_html=True)

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/1/16/Splunk_logo.svg/320px-Splunk_logo.svg.png", width=150)
    st.markdown("---")
    st.markdown("### 🛡️ Tentang LogWatcher ID")
    st.markdown("""
    LogWatcher ID adalah AI agent yang membantu masyarakat Indonesia mengecek apakah data pribadi mereka pernah bocor.
    
    **Fitur:**
    - ✅ Cek email & nomor HP
    - ✅ Deteksi password bocor
    - ✅ Laporan dalam Bahasa Indonesia
    - ✅ Risk Score 0-100
    - ✅ Log ke Splunk via MCP
    """)
    st.markdown("---")
    st.markdown("### 📊 Database Breach Indonesia")
    breaches = [
        ("BPJS Kesehatan", "279 juta"),
        ("KPU", "204 juta"),
        ("Tokopedia", "91 juta"),
        ("Bukalapak", "13 juta"),
        ("PLN", "17 juta"),
        ("IndiHome", "1.3 juta"),
        ("BCA", "2 juta"),
    ]
    for name, records in breaches:
        st.markdown(f"• **{name}** — {records} data")
    st.markdown("---")
    st.caption("⚠️ Tool ini untuk edukasi. Data yang dicek tidak disimpan secara permanen.")

# ============================================================
# MAIN FORM
# ============================================================
st.markdown("## 🔎 Cek Data Pribadimu")
st.markdown("Masukkan informasi yang ingin kamu cek. **Tidak perlu isi semua.**")

col1, col2 = st.columns(2)

with col1:
    email = st.text_input(
        "📧 Alamat Email",
        placeholder="contoh: namakamu@gmail.com",
        help="Email yang kamu gunakan untuk mendaftar layanan online"
    )

with col2:
    phone = st.text_input(
        "📱 Nomor HP",
        placeholder="contoh: 08123456789",
        help="Nomor HP Indonesia yang kamu gunakan"
    )

password = st.text_input(
    "🔐 Password (opsional — untuk cek apakah pernah bocor)",
    type="password",
    placeholder="Masukkan password untuk dicek",
    help="Password tidak disimpan. Hanya hash-nya yang dikirim ke HIBP."
)

st.markdown("""
<div class="info-box">
💡 <strong>Privasi terjaga:</strong> Email dan nomor HP digunakan untuk simulasi pengecekan database breach Indonesia. 
Password dikonversi ke hash SHA-1 sebelum dikirim ke HaveIBeenPwned — password asli tidak pernah meninggalkan perangkatmu.
</div>
""", unsafe_allow_html=True)

cek_button = st.button("🔍 Mulai Investigasi", type="primary", use_container_width=True)

# ============================================================
# HASIL INVESTIGASI
# ============================================================
if cek_button:
    if not email and not phone:
        st.error("⚠️ Masukkan minimal email atau nomor HP untuk memulai investigasi.")
    else:
        with st.spinner("🤖 AI Agent sedang menginvestigasi... Mohon tunggu 10-20 detik"):
            result = run_agent(
                email=email or None,
                phone=phone or None,
                password=password or None
            )

        risk_score = result["risk_score"]
        report = result["report"]
        breaches = result["breaches"]
        password_check = result["password_check"]

        # Kirim ke Splunk MCP
        with st.spinner("📤 Mengirim log ke Splunk via MCP..."):
            mcp_result = run_mcp_pipeline(
                email=email or "anonymous",
                phone=phone or "anonymous",
                breaches=breaches,
                risk_score=risk_score,
                password_check=password_check,
                report=report
            )

        st.markdown("---")
        st.markdown("## 📊 Hasil Investigasi")

        # Risk Score Display
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if risk_score >= 80:
                css_class = "risk-critical"
                label = "🔴 KRITIS"
            elif risk_score >= 60:
                css_class = "risk-high"
                label = "🟠 TINGGI"
            elif risk_score >= 30:
                css_class = "risk-medium"
                label = "🟡 SEDANG"
            else:
                css_class = "risk-low"
                label = "🟢 RENDAH"

            st.markdown(f"""
            <div class="{css_class}">
                RISK SCORE<br>{risk_score}/100<br>
                <span style="font-size: 1rem;">{label}</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("🔍 Breach Ditemukan", len(breaches))
        with col2:
            pwned_text = f"{password_check.get('count', 0):,}x" if password_check.get('pwned') else "Aman ✅"
            st.metric("🔐 Password Bocor", pwned_text)
        with col3:
            mcp_success = sum(1 for v in mcp_result.values() if v.get("status") == "success")
            st.metric("🔌 MCP Tools", f"{mcp_success}/4")
        with col4:
            st.metric("📍 Negara", "🇮🇩 Indonesia")

        st.markdown("---")

        # Laporan AI
        col1, col2 = st.columns([3, 2])

        with col1:
            st.markdown("### 📋 Laporan Investigasi AI")
            st.markdown(report)

        with col2:
            st.markdown("### 🗂️ Detail Breach")
            for b in breaches:
                severity_color = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢"
                }.get(b["severity"], "⚪")

                st.markdown(f"""
                <div class="breach-card">
                    {severity_color} <strong>{b['breach_source']}</strong> ({b['breach_year']})<br>
                    <small>📊 {b['records_exposed']:,} data bocor</small><br>
                    <small>⚡ Severity: {b['severity']} | Score: {b['risk_score']}</small>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("### 🔌 Splunk MCP Log")
            for tool, res in mcp_result.items():
                status = "✅" if res.get("status") == "success" else "⚠️"
                st.markdown(f"{status} `{res.get('tool', tool)}`")

        st.markdown("---")
        st.success("✅ Investigasi selesai! Log telah dikirim ke Splunk Cloud via MCP Pipeline.")
        st.caption("🔒 Data investigasi ini telah dilog ke Splunk untuk analisis keamanan lebih lanjut.")
