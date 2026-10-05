# Credential Phishing

## Attack Name
Credential Phishing

## Description
Credential phishing attempts to trick a user into submitting login details to
a page controlled by an attacker rather than the legitimate application.

## Common API Pattern
The victim visits a fake login page and submits credentials to an endpoint
that is not part of the trusted authentication flow.

Example:

POST /lab/phishing/login

## Suspicious Behaviour
- Login page is served from an unexpected URL.
- Credentials are submitted to a suspicious endpoint.
- The page records a username or password-submission signal.
- The session or URL should be blocked after detection.

## Example Evidence
A dummy victim submits credentials to a controlled local phishing page and the
monitoring layer observes credential_submission_observed=true.

## Detection Indicators
- Credential submission to an untrusted login path.
- Controlled credential-capture telemetry.
- Suspicious phishing URL or page classification.

## Recommended Response
Block the phishing page or session, alert administrators, and educate users to
verify login URLs. In production, rotate exposed credentials and review access
logs for misuse.

## Severity
Usually HIGH because credential exposure can lead to account compromise.
