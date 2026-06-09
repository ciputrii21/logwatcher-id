# 🔍 LogWatcher ID

> AI Agent for Indonesian Personal Data Breach Detection | Deteksi Kebocoran Data Pribadi Indonesia

[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32-red?logo=streamlit)](https://streamlit.io)
[![Splunk](https://img.shields.io/badge/Splunk-Cloud-orange?logo=splunk)](https://splunk.com)
[![Groq](https://img.shields.io/badge/Groq-LLaMA3-green)](https://groq.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## 🇮🇩 About / Tentang

**English:** LogWatcher ID is a bilingual AI agent that helps Indonesian citizens detect if their personal data has been compromised in known data breaches. It combines real breach intelligence, AI-powered analysis, and Splunk security logging — all in one tool, completely free.

**Bahasa Indonesia:** LogWatcher ID adalah AI agent bilingual yang membantu warga Indonesia mengecek apakah data pribadi mereka pernah bocor dalam insiden keamanan siber. Menggabungkan data breach nyata, analisis AI, dan logging keamanan Splunk — gratis sepenuhnya.

---

## 🚨 Why Indonesia Needs This

Indonesia has experienced some of the largest data breaches in history:

| Breach | Year | Records Exposed |
|--------|------|----------------|
| KPU (Election Commission) | 2024 | 204 million |
| BPJS Kesehatan | 2021 | 279 million |
| Tokopedia | 2020 | 91 million |
| Bukalapak | 2019 | 13 million |
| PLN | 2022 | 17 million |
| IndiHome | 2023 | 1.3 million |

Yet, **there is no free Indonesian tool** to help ordinary citizens check if they were affected — until now.

---

## ✨ Features

- 🔍 **Breach Detection** — Check email & phone against Indonesian breach database
- 🔐 **Password Check** — Real-time check via HaveIBeenPwned Passwords API (free, privacy-safe)
- 🤖 **AI Analysis** — Groq LLaMA 3.3 generates detailed investigation report
- 📊 **Risk Score** — 0-100 risk scoring system
- 🌐 **Bilingual** — Full support for Bahasa Indonesia & English
- ⚡ **Splunk MCP Pipeline** — 4 MCP tools log every investigation to Splunk Cloud
- 🛡️ **Privacy-First** — Passwords never leave your device (SHA-1 hash only)

---

## 🏗️ ArchitectureUser Input (Email / Phone / Password)
│
▼
┌─────────────────────┐
│   Streamlit UI      │  ← Bilingual dashboard
└────────┬────────────┘
│
▼
┌─────────────────────┐
│   AI Agent Core     │  ← Python orchestrator
└──┬──────────────┬───┘
│              │
▼              ▼
┌──────────┐  ┌───────────────────┐
│ HIBP API │  │ Indonesian Breach  │
│(Password │  │ Database (Synthetic│
│  Check)  │  │ + Real Metadata)   │
└──────────┘  └───────────────────┘
│
▼
┌─────────────────────┐
│   Groq LLaMA 3.3    │  ← AI Report Generation
└────────┬────────────┘
│
▼
┌─────────────────────────────────┐
│      Splunk MCP Pipeline        │
│  ┌─────────────────────────┐   │
│  │ Tool 1: log_investigation│   │
│  │ Tool 2: log_risk_alert   │   │
│  │ Tool 3: log_password_chk │   │
│  │ Tool 4: log_summary_rpt  │   │
│  └─────────────────────────┘   │
└────────┬────────────────────────┘
│
▼
┌─────────────────────┐
│   Splunk Cloud      │  ← Security logging & analysis
└─────────────────────┘
│
▼
┌─────────────────────┐
│  Investigation      │  ← Bilingual AI report
│  Report + Risk Score│     + actionable steps
└─────────────────────┘---

## 🛠️ Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| UI | Streamlit | Web dashboard |
| AI Agent | Python 3.12 | Orchestration |
| LLM | Groq LLaMA 3.3 70B | Report generation |
| Breach API | HaveIBeenPwned | Password check |
| Security Platform | Splunk Cloud | Log analysis |
| MCP Integration | Custom HEC Pipeline | 4 MCP tools |
| Language | Bilingual (ID/EN) | Accessibility |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- Splunk Cloud account (free trial)
- Groq API key (free)

### Installation

```bash
# Clone repo
git clone https://github.com/ciputrii21/logwatcher-id.git
cd logwatcher-id

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your credentials
```

### Configuration

Create `.env` file:
```env
SPLUNK_HOST=your-instance.splunkcloud.com
SPLUNK_PORT=8089
SPLUNK_USERNAME=sc_admin
SPLUNK_PASSWORD=your_password
SPLUNK_HEC_TOKEN=your_hec_token
SPLUNK_HEC_URL=https://your-instance.splunkcloud.com:8088/services/collector
GROQ_API_KEY=your_groq_api_key
```

### Run

```bash
streamlit run app.py
```

Open `http://localhost:8501` in your browser.

---

## 🔌 Splunk MCP Integration

LogWatcher ID uses a 4-tool MCP pipeline that logs every investigation to Splunk Cloud:

| MCP Tool | Sourcetype | Data Logged |
|----------|-----------|-------------|
| `log_investigation` | `mcp_investigation` | Breach sources, severity, email, phone |
| `log_risk_alert` | `mcp_alert` | Alert type, risk score, action required |
| `log_password_check` | `mcp_password_check` | HIBP result, pwned count, severity |
| `log_summary_report` | `mcp_report` | AI model, report preview, language |

### Sample SPL Queries

```spl
# View all investigations
index=main sourcetype=mcp_investigation | table query_email, risk_score, highest_severity

# High risk alerts
index=main sourcetype=mcp_alert severity=CRITICAL | stats count by query_email

# Password breach statistics
index=main sourcetype=mcp_password_check | stats avg(pwned_count) as avg_pwned
```

---

## 📁 Project Structurelogwatcher-id/
├── app.py                 # Streamlit UI (bilingual)
├── src/
│   ├── ai_agent.py        # Core AI agent + Groq
│   ├── breach_ingestor.py # HIBP + Splunk HEC
│   └── splunk_mcp.py      # MCP pipeline (4 tools)
├── data/                  # Synthetic breach data
├── docs/                  # Documentation
├── requirements.txt
└── .env.example---

## 🔒 Privacy & Security

- Passwords are **never stored** — only SHA-1 hash prefix sent to HIBP
- No PII permanently stored in Splunk beyond session
- All API keys stored in `.env` (gitignored)
- Open source — full code transparency

---

## 🏆 Hackathon

Built for **Splunk Agentic Ops Hackathon** (Devpost, June 2026)
- Track: Security
- Target: Best of Security + Best Use of Splunk MCP Server

---

## 👩‍💻 Author

**Shalom Putri** ([@ciputrii21](https://github.com/ciputrii21))
Fresh graduate, Informatics — Manado, Indonesia

---

## 📄 License

MIT License — free to use, modify, and distribute.
