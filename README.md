# Microsoft Defender XDR AI SOC Agent 🛡️🤖

An autonomous AI Security Operations Center (SOC) agent designed for **Microsoft Defender XDR** (Microsoft 365 Defender, Defender for Endpoint, Defender for Identity, and Defender for Cloud Apps).

The agent connects directly to the **Microsoft Graph Security API v1.0**, ingests alerts and incidents, performs deep AI analysis (triaging, attack reconstruction, decoding obfuscated commands, MITRE ATT&CK mapping), assesses blast radius, recommends containment playbooks, and generates ready-to-run **KQL (Kusto Query Language) Threat Hunting Queries** for Defender Advanced Hunting and Microsoft Sentinel.

---

## 🚀 Key Capabilities

- **Direct Microsoft Defender XDR Connectivity**: Authenticates to Microsoft Entra ID (Azure AD) via OAuth2 client credentials and queries `/v1.0/security/alerts_v2` and `/v1.0/security/incidents`.
- **Automated AI Triaging**: Classifies alerts into **True Positive (Malicious)**, **False Positive**, or **Suspicious**, computing an objective confidence score.
- **De-obfuscation & Deep Inspection**: Automatically decodes Base64 encoded PowerShell/cmdline arguments, identifies LSASS injection, macro executions, and C2 beacons.
- **MITRE ATT&CK Mapping**: Maps attacker tactics & techniques (e.g., T1003.001, T1059.001, T1204.002, T1071.001).
- **Blast Radius & Threat Story**: Reconstructs the kill chain and evaluates exposed identities, devices, and domain impact.
- **Automated KQL Hunting Queries**: Generates targeted KQL queries for `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceLogonEvents`, and `SigninLogs`.
- **Containment Orchestration**: Recommends immediate containment actions (Device Isolation, Entra ID session revocation, IOC blocking) and generates emergency PowerShell remediation scripts.
- **Automated Incident Response (IR) Reports**: Automatically generates enterprise-grade, **NIST SP 800-61 Rev 2** and **SANS DFIR** compliant incident response reports in **Print-Ready HTML (PDF)**, **Markdown (.md)**, and **SOAR-ready JSON**.
- **Multi-Modal AI Engine**: Supports Google Gemini, OpenAI, Azure OpenAI, and includes a built-in **Expert SOC Heuristic Engine** that runs offline with 0 external API keys required!
- **Dual Interfaces**: High-speed **Terminal CLI** and a dark-themed **FastAPI SOC Operations Web Dashboard**.

---

## 📁 Architecture Overview

```
MS XDR AI Agent/
├── .env                  # Azure & AI configuration
├── .env.example          # Template configuration
├── config.py             # Settings manager
├── models.py             # Pydantic models (Alerts, MITRE, AI Report)
├── mock_data.py          # Authentic Defender XDR alert schemas for simulation
├── defender_client.py    # MS Graph Security API client & OAuth2 MSAL handler
├── ai_analyzer.py        # AI SOC Analyst engine (Gemini / OpenAI / Heuristics)
├── remediation.py        # Containment action execution & PowerShell script generator
├── ir_report_generator.py # Automated NIST SP 800-61 Incident Response Report generator
├── cli.py                # Command-line interface with Rich formatting
├── web_dashboard.py      # FastAPI backend for SOC web interface
├── templates/
│   └── dashboard.html    # Modern dark-mode SOC dashboard
└── requirements.txt      # Python dependencies
```

---

## ⚡ Quick Start

### 1. Activate Environment & Install Dependencies

```bash
# Python 3.10+ recommended
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment (`.env`)

Edit `.env` to configure connectivity:

```ini
# Microsoft Entra ID (Azure AD) App Registration
AZURE_TENANT_ID=your-azure-tenant-id-here
AZURE_CLIENT_ID=your-azure-client-id-here
AZURE_CLIENT_SECRET=your-azure-client-secret-here

# AI Provider ("gemini", "openai", "azure_openai", or "heuristic")
LLM_PROVIDER=gemini
GEMINI_API_KEY=your-gemini-api-key-here
GEMINI_MODEL=gemini-2.5-flash
```

> **Note:** If Azure credentials or AI keys are not yet provided, the agent will **automatically run in Simulation/Mock Mode** using realistic Defender XDR incident schemas and the built-in Expert Heuristic engine. You can test immediately!

---

## 🔑 Azure Entra ID Setup Guide (Step-by-Step)

To establish live connectivity to your Microsoft Defender XDR tenant:

1. **Sign in to Azure Portal**: Navigate to [https://portal.azure.com](https://portal.azure.com).
2. **Register an Application**:
   - Go to **Microsoft Entra ID** > **App registrations** > **New registration**.
   - Name: `Defender-XDR-AI-SOC-Agent`.
   - Supported account types: *Accounts in this organizational directory only (Single tenant)*.
   - Click **Register**.
3. **Copy Application Credentials**:
   - Copy **Application (client) ID** -> `AZURE_CLIENT_ID` in `.env`.
   - Copy **Directory (tenant) ID** -> `AZURE_TENANT_ID` in `.env`.
4. **Create Client Secret**:
   - Go to **Certificates & secrets** > **Client secrets** > **New client secret**.
   - Add a description (e.g. `SOC-Agent-Key`) and select an expiration.
   - Click **Add** and immediately copy the **Value** -> `AZURE_CLIENT_SECRET` in `.env`.
5. **Grant Microsoft Graph API Permissions**:
   - Go to **API permissions** > **Add a permission** > **Microsoft Graph** > **Application permissions**.
   - Add the following permissions:
     - `SecurityAlert.Read.All` (or `SecurityAlert.ReadWrite.All`)
     - `SecurityIncident.Read.All` (or `SecurityIncident.ReadWrite.All`)
     - `User.ReadWrite.All` *(Optional: needed to revoke compromised user sessions)*
   - Click **Add permissions**.
   - **Crucial Step**: Click **Grant admin consent for [Your Organization]** and verify status turns green.

---

## 💻 CLI Usage

### Test Connectivity
```bash
python cli.py test
```

### List Defender Alerts
```bash
python cli.py list
# Or filter by severity
python cli.py list --severity high
```

### Run AI Investigation on an Alert
```bash
python cli.py analyze da-9821-lsass-dump
```

### Automatically Generate Full Incident Response (IR) Report
Generates NIST SP 800-61 Rev 2 compliant reports in Markdown, Print-Ready HTML (Print to PDF), and JSON:
```bash
python cli.py report da-9821-lsass-dump --ticket INC-2026-901
```

### Launch Interactive Menu Shell
```bash
python cli.py
```

---

## 🌐 SOC Web Dashboard

Launch the interactive web operations console:

```bash
python cli.py web
# Or:
uvicorn web_dashboard:app --host 127.0.0.1 --port 8000
```

Open your browser at **[http://localhost:8000](http://localhost:8000)** to:
- Monitor live alerts from Microsoft Defender XDR.
- Click **"AI Triage & Analyze"** to inspect threats in real-time.
- View interactive **MITRE ATT&CK** tactic tags.
- Copy pre-written **KQL queries** with one click.
- Execute simulated or live **Containment Actions** (Device Isolation, Session Revocation).
- Export complete Markdown investigation reports for ticket resolution.
- Test Azure Entra ID credentials dynamically via the UI modal.

---

## 📜 Example AI Analysis Output

```
╭─────────────────────────── AI SOC TRIAGE VERDICT ────────────────────────────╮
│ VERDICT: True Positive (Malicious)                                           │
│ Confidence Score: 96%                                                        │
│ Assessed Severity: HIGH                                                      │
│ Analysis Model: AI SOC Analyst (Gemini / Heuristic Engine)                   │
╰──────────────────────────────────────────────────────────────────────────────╯
╭───────────────── Executive Summary (CISO / SOC Management) ──────────────────╮
│ CRITICAL: Active credential dumping detected on host FIN-SRV-01 targeting   │
│ LSASS memory. User credentials for svc_backup may have been compromised.     │
│ Immediate device isolation and password resets required.                     │
╰──────────────────────────────────────────────────────────────────────────────╯
...
```
