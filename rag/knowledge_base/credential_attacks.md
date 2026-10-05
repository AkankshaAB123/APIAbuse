# Credential Attacks

## Attack Name
Credential Attacks

## Description
Credential attacks involve attempts to gain unauthorized access to
accounts by using stolen, guessed, or repeatedly tested credentials.

## Common API Pattern
An attacker repeatedly sends authentication requests to an API endpoint.

Example:

POST /api/login

The attacker may try many username and password combinations.

## Suspicious Behaviour
- Large number of login attempts.
- Multiple failed authentication requests.
- Repeated requests from the same source IP.
- Attempts against multiple user accounts.
- Rapid authentication requests.
- Unusual login activity.

## Example Evidence
A source IP generates hundreds of failed login requests within a
short period.

## Detection Indicators
- High failed_auth_count.
- High request_count.
- Repeated HTTP 401 responses.
- Multiple accounts targeted from one source.
- Unusual request frequency.

## Recommended Response
Investigate the authentication activity and apply appropriate
protections such as rate limiting, temporary account restrictions,
or additional authentication controls.

## Severity
Potentially MEDIUM, HIGH, or CRITICAL depending on the volume,
targeted accounts, and confidence of detection.