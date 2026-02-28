"""All LLM prompt templates for GOD_EYE AI operations."""

CORRELATION_PROMPT = """
You are an OSINT intelligence analyst. Analyze the following data collected about a target and identify connections, patterns, and cross-references between different data sources.

Target: {target}
Target Type: {target_type}

Collected Data:
{data_summary}

Please identify:
1. Connections between different platforms/accounts (same person theory)
2. Username patterns and variations
3. Geographic patterns
4. Temporal patterns (account creation dates, activity patterns)
5. Potential aliases or alternative identities
6. Inconsistencies or red flags
7. Confidence assessment for each connection

Respond in JSON format with keys: connections, patterns, aliases, inconsistencies, summary
"""

RISK_SCORING_PROMPT = """
You are a privacy risk analyst. Based on the following OSINT findings, assess the privacy risk level for this individual.

Target: {target}
Findings Summary:
{findings}

Risk Score (1-10):
- 1-3: Low (minimal public exposure)
- 4-6: Medium (moderate digital footprint)
- 7-8: High (significant privacy risks)
- 9-10: Critical (severe exposure, immediate action needed)

Respond in JSON format with:
- score (float 1.0-10.0)
- level (low/medium/high/critical)
- breakdown (dict of category: score)
- top_risks (list of 3-5 specific risks)
- recommendations (list of 5 actionable recommendations)
"""

EXECUTIVE_SUMMARY_PROMPT = """
You are writing an OSINT intelligence report. Create a professional executive summary for the following investigation.

Target: {target}
Investigation Date: {date}
Risk Score: {risk_score}/10 ({risk_level})

Key Findings:
{findings}

Write a 2-3 paragraph executive summary covering:
1. Overview of the investigation and key findings
2. Most significant privacy risks identified
3. Recommended actions

Keep it professional, factual, and suitable for security/privacy professionals.
"""

FULL_REPORT_PROMPT = """
You are an OSINT intelligence analyst writing a comprehensive investigation report.

Target: {target}
Investigation Date: {date}
Request ID: {request_id}
Risk Score: {risk_score}/10

Execution Summary:
{execution_summary}

Observed Search Activity:
{search_activity}

Image / Visual Activity:
{image_activity}

Data from {module_count} intelligence modules:
{all_data}

Write a comprehensive report with these sections:
1. Executive Summary
2. Target Profile (what we know about this person)
3. Digital Presence (accounts, platforms found)
4. Email Intelligence (breach exposure, email accounts)
5. Network Intelligence (IPs, domains)
6. Social Media Analysis
7. Visual Intelligence (if applicable)
8. Risk Assessment
9. Recommendations

Strict rules:
- Include only verified findings from the provided module results and search activity.
- Do not claim a platform was searched directly unless its direct module actually executed.
- If a platform was checked only through Google/Bing/DuckDuckGo dorks, say that explicitly.
- If a module did not run, failed, or was skipped, say "not searched" or omit it; do not write "not found".
- If a search query returned zero results, phrase it as "no indexed results were found for this query/source".
- Do not invent platform-by-platform tables unless the data clearly supports them.
- Only include Visual Intelligence metrics when image modules ran or image results exist. If nothing was collected, state that no images were discovered/processed.
- Avoid overstating certainty; distinguish between absence of evidence and evidence of absence.
"""

TIMELINE_PROMPT = """
Extract a chronological timeline of events from the following OSINT data.

Target: {target}
Data: {data}

Create a timeline of events with:
- timestamp (ISO 8601 or approximate year/date)
- event_type (account_created/breach/post/location_seen/company_joined)
- description
- platform/source
- confidence (high/medium/low)

Respond as JSON array sorted by timestamp ascending.
"""
