# Security Misconfiguration

## Attack Name
Security Misconfiguration

## Description
Security misconfiguration occurs when an API or server is deployed
with insecure settings that expose unnecessary functionality,
information, or access.

## Common API Pattern
An API exposes debugging information, unnecessary endpoints, weak
security settings, or improperly configured access controls.

Example:

GET /api/debug

## Suspicious Behaviour
- Access to debug endpoints.
- Exposure of sensitive error messages.
- Unexpected information disclosure.
- Access to administrative functionality.
- Use of insecure API configurations.

## Example Evidence
An API returns detailed internal error information or exposes a
debugging endpoint to an unauthorized user.

## Detection Indicators
- Debug endpoints exposed.
- Sensitive information in responses.
- Unexpected server information.
- Missing security controls.
- Improperly protected administrative endpoints.

## Recommended Response
Disable unnecessary functionality, remove sensitive information from
responses, and apply secure configuration and access controls.

## Severity
Potentially MEDIUM or HIGH depending on the information or
functionality exposed.