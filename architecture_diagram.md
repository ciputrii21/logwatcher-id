# LogWatcher ID - Architecture Diagram

## System Flow

User Input (Email / Phone / Password)
           |
           v
[ Streamlit UI ]  <- Bilingual dashboard (ID/EN)
           |
           v
[ AI Agent Core ]  <- Python orchestrator (src/ai_agent.py)
   |              |
   v              v
[ HIBP API ]   [ Indonesian Breach Database ]
(Password       (BPJS, KPU, Tokopedia, PLN,
 Check via       Bukalapak, IndiHome, BCA)
 k-anonymity)
           |
           v
[ Groq LLaMA 3.3 70B ]  <- AI Bilingual Report Generation
           |
           v
[ Splunk MCP Pipeline - 4 Tools ]
   (src/splunk_mcp.py)
   - log_investigation
   - log_risk_alert
   - log_password_check
   - log_summary_report
           |
           v  (via HTTP Event Collector)
[ Splunk Cloud ]  <- Security logging, search & analysis
   (4 sourcetypes)
           |
           v
[ Bilingual Report + Risk Score ]
   (0-100 score + actionable steps)


## Data Flow Summary

1. User submits email/phone/password via Streamlit UI
2. AI Agent checks password against HaveIBeenPwned (k-anonymity)
3. AI Agent cross-references Indonesian breach database
4. Groq LLaMA 3.3 generates bilingual investigation report
5. Splunk MCP Pipeline logs 4 structured events via HEC
6. Results displayed to user with Risk Score and recommendations

## Components

| Component | Technology | File |
|-----------|-----------|------|
| UI | Streamlit | app.py |
| AI Agent | Python + Groq | src/ai_agent.py |
| Breach Data | HIBP API | src/breach_ingestor.py |
| MCP Pipeline | Splunk HEC | src/splunk_mcp.py |
