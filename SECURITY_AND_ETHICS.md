# SECURITY_AND_ETHICS.md — Legal, Ethical & Security Guidelines

---

## 1. Intended Use

GOD_EYE is designed exclusively for:

| Permitted Use | Description |
|---|---|
| **Personal privacy auditing** | Scanning your own digital footprint to understand your exposure |
| **Authorized security research** | Penetration testing and security assessments with written consent |
| **Academic research** | Studying digital privacy with institutional ethics board approval |
| **Journalism** | Verifying identities and connections for legitimate public interest reporting |
| **Corporate security** | Assessing employee exposure with proper authorization and disclosure |

---

## 2. Prohibited Uses

The following uses are strictly prohibited:

- **Stalking or harassment** of any individual
- **Doxing** — publishing private information to intimidate or harm
- **Unauthorized surveillance** of individuals without their knowledge or consent
- **Identity theft or fraud**
- **Blackmail or extortion**
- **Employment discrimination** based on gathered intelligence
- **Circumventing legal restrictions** on data access
- **Targeting minors** (persons under 18) under any circumstance
- **State-level surveillance** without proper legal authority

---

## 3. Consent Banner Implementation

**Required:** The application MUST display a consent banner on every first run and before every scan. The user must type `I AGREE` to proceed.

```python
CONSENT_TEXT = """
╔══════════════════════════════════════════════════════════════════╗
║                    ⚠️  LEGAL & ETHICAL USE ONLY                  ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  This tool gathers publicly available information (OSINT).       ║
║  It is designed for AUTHORIZED use only.                         ║
║                                                                  ║
║  PERMITTED:                                                      ║
║  ✓ Auditing your own digital footprint                           ║
║  ✓ Authorized security research with written consent             ║
║  ✓ Academic research with ethics board approval                  ║
║                                                                  ║
║  PROHIBITED:                                                     ║
║  ✗ Stalking, harassment, or doxing                               ║
║  ✗ Unauthorized surveillance                                     ║
║  ✗ Identity theft, fraud, or blackmail                           ║
║  ✗ Targeting minors (under 18)                                   ║
║  ✗ Any illegal activity                                          ║
║                                                                  ║
║  By continuing, you confirm that:                                ║
║  1. You have legal authorization to investigate this target      ║
║  2. You will comply with all applicable laws in your jurisdiction║
║  3. You accept full responsibility for how you use this data     ║
║  4. You understand this tool logs all searches for audit         ║
║                                                                  ║
║  Violations may result in criminal liability under laws such     ║
║  as the CFAA (US), GDPR (EU), and equivalent local statutes.    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

Type 'I AGREE' to continue or 'EXIT' to quit: """
```

**Implementation rules:**
1. Display on first run AND store consent timestamp
2. Re-display if config changes or version updates
3. Consent can be skipped for automated pipelines with `--accept-terms` flag, but this must be explicitly documented
4. The `--accept-terms` flag must be used with `--audit-log` enabled

---

## 4. Audit Logging

**Every search action MUST be logged.** The audit log is append-only and should never be deleted by the application.

```json
{
    "timestamp": "2026-01-20T14:30:52.123Z",
    "event_type": "scan_started",
    "request_id": "req_20260120_143052_abc123",
    "system_user": "johndoe",
    "target": "target@example.com",
    "target_type": "email",
    "modules_requested": ["hibp", "sherlock", "github"],
    "ip_address": "192.168.1.100",
    "consent_given": true,
    "consent_timestamp": "2026-01-20T14:30:45.000Z"
}
```

**Events to log:**
- `consent_given` — user accepted terms
- `scan_started` — new scan initiated
- `module_executed` — individual module completed
- `data_accessed` — raw data file opened/viewed
- `report_generated` — report created
- `data_exported` — data exported to file
- `data_deleted` — scan data deleted
- `settings_changed` — configuration modified

---

## 5. Data Handling Rules

### Collection Minimization
- Only collect data that is publicly available
- Do not attempt to access private/protected resources without authorization
- Respect `robots.txt` directives (configurable, but ON by default)
- Do not scrape content behind authentication walls without valid credentials

### Data Retention
- Default retention: 90 days (configurable via `DATA_RETENTION_DAYS`)
- Implement automatic cleanup of expired data
- Allow users to manually delete specific scans
- Compressed archives for scans older than 30 days

### Data Security
- All API keys stored in `.env` file (never in code or config.yaml)
- Optional AES-256 encryption for stored scan data
- Neo4j requires authentication
- Redis password protection in production
- No sensitive data in log files (redact API keys, passwords)

---

## 6. Rate Limiting & Respect

### Implementation Requirements
1. **Per-API rate limiting** — honor each API's documented limits
2. **Global rate limiting** — max 100 total requests/second
3. **robots.txt compliance** — check and respect before scraping
4. **Human-like delays** — random 1-5 second delays between browser actions
5. **User-Agent honesty** — identify as a research tool when possible (not mandatory for stealth mode)
6. **Backoff on errors** — exponential backoff on rate limit errors (429s)

### Rate Limit Defaults

| API | Requests/Min | Requests/Day |
|---|---|---|
| HIBP | 40 | 5,000 |
| Google CSE | 10 | 100 (free) |
| GitHub | 83 | 5,000 |
| Reddit | 60 | — |
| Shodan | 1 | 100 (free) |
| General scraping | 10 | — |
| Browser automation | 5 | — |

---

## 7. Legal Disclaimer

**MUST be included in every generated report:**

```
DISCLAIMER: This report was generated using publicly available information 
(Open Source Intelligence - OSINT). The data herein was gathered from public 
sources including but not limited to: public social media profiles, public 
records, data breach databases, DNS records, and search engine results.

This report is provided for authorized use only. The accuracy of information 
cannot be guaranteed. The tool operators and developers accept no liability 
for the use or misuse of information contained in this report.

Users are responsible for ensuring their use complies with all applicable 
laws and regulations including but not limited to: the Computer Fraud and 
Abuse Act (CFAA), General Data Protection Regulation (GDPR), California 
Consumer Privacy Act (CCPA), and equivalent local legislation.

Generated by GOD_EYE OSINT Platform v{version}
Scan ID: {request_id}
Date: {date}
```

---

## 8. Legal Considerations by Region

### United States
- **CFAA** — Do not access systems without authorization
- **ECPA** — Do not intercept electronic communications
- **State laws** — Some states have specific anti-stalking digital laws
- **CCPA** — California residents have data rights

### European Union
- **GDPR** — Personal data processing requires legal basis
- **Article 6** — Legitimate interest may apply for security research
- **Right to be forgotten** — Subjects can request data deletion
- **Data Protection Impact Assessment** may be required for systematic monitoring

### General Best Practices
- Document your legal basis before starting any investigation
- Maintain records of consent/authorization
- Do not combine data in ways that create new privacy risks
- Notify targets when conducting authorized security assessments
- Delete data when no longer needed

---

## 9. Responsible Disclosure

If during an OSINT investigation you discover:
- **Security vulnerabilities** — Follow responsible disclosure practices (notify the affected party, allow 90 days to fix)
- **Child exploitation material** — Report immediately to NCMEC (US) or equivalent authority
- **Imminent threats** — Report to appropriate law enforcement
- **Data breaches** — Notify the affected organization

---

## 10. Security of the Tool Itself

### API Key Protection
```python
# NEVER do this:
api_key = "sk-1234567890abcdef"  # Hardcoded

# ALWAYS do this:
from pydantic import SecretStr
api_key: SecretStr = settings.hibp_api_key

# SecretStr prevents accidental logging:
print(api_key)  # Outputs: SecretStr('**********')
print(api_key.get_secret_value())  # Only when explicitly needed
```

### Credential Rotation
- Use dedicated accounts for browser automation (not personal)
- Rotate credentials regularly
- Use 2FA on all accounts used for scraping
- Monitor for account bans/lockouts

### Network Security
- Use proxy/VPN for all scraping operations
- TOR for sensitive investigations
- Never expose Neo4j/Redis ports to public internet in production
- Use firewall rules to restrict access
