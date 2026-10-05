# Suspicious Banking URL and Financial Phishing

## Attack Name
Suspicious Banking URL and Financial Phishing

## Security Domain
ENDPOINT

## Description
Financial phishing and fake banking URL attacks use brand impersonation and deceptive web addresses to harvest banking credentials, payment card numbers, or one-time verification codes. Attackers deploy lookalike domains, deceptive subdomains, or typo-squatted URLs combined with urgent account verification or security alert lures to convince victims to authenticate against a fraudulent portal.

## Common API Pattern
Telemetry from an endpoint or protective gateway observes navigation to, or credential submission at, an untrusted host mimicking financial services.

Example:

POST /lab/phishing/login
GET /login?verify=bank-account
Destination: https://secure-bank.example.test/auth/login

## Suspicious Behaviour
- Use of reserved or synthetic test domains (.example.test) impersonating banking brands.
- URL structure containing financial keywords (e.g., "secure", "bank", "portal", "verify", "login", "account").
- Urgent social engineering language in message bodies demanding immediate verification to prevent account suspension.
- Credential capture forms hosted outside official banking subdomains.
- Sender email domain mismatching the purported financial institution.

## Example Evidence
An event contains an embedded URL pointing to a synthetic banking portal (e.g., secure-bank.example.test/verify) alongside urgent verification lure text and dummy credential submission telemetry.

## Detection Indicators
- Domain analysis: suspicious subdomain depth, brand keywords combined with generic domains, or known synthetic test domains.
- Lexical indicators: keywords like "account", "suspended", "urgent", "security alert" combined with external links.
- Credential capture telemetry: forms capturing authentication fields on non-authoritative endpoints.
- Absence of valid organizational certificates or trusted enterprise domain alignment.

## Recommended Response
1. Block access to the suspicious URL at the DNS and gateway level.
2. Invalidate any credentials or session tokens submitted to the fraudulent host.
3. Alert the Security Operations Center (SOC) and initiate domain takedown or quarantine procedures.
4. Notify the user to verify communications exclusively through official institution channels.

## Severity
HIGH to CRITICAL due to the imminent risk of account takeover and financial credential compromise.
