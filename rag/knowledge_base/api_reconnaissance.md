# API Reconnaissance

## Attack Name
API Reconnaissance

## Description
API reconnaissance involves systematically exploring API endpoints
and functionality to discover available resources, parameters, and
potential weaknesses.

## Common API Pattern
An attacker sends requests to multiple endpoints to learn about the
API structure.

Example:

GET /api/users
GET /api/orders
GET /api/admin
GET /api/config

## Suspicious Behaviour
- Requests to many different endpoints.
- Sequential endpoint exploration.
- Access attempts to undocumented endpoints.
- Repeated requests resulting in 404 responses.
- Enumeration of API resources.

## Example Evidence
A source IP accesses a large number of different API endpoints in a
short period.

## Detection Indicators
- High endpoint diversity.
- Multiple 404 responses.
- Sequential endpoint probing.
- Access attempts to administrative endpoints.
- Unusual endpoint discovery patterns.

## Recommended Response
Monitor endpoint enumeration and apply appropriate access controls
and rate limiting.

Suspicious reconnaissance activity should contribute to the risk
assessment.

## Severity
Potentially LOW, MEDIUM, or HIGH depending on the intensity and
associated attack behaviour.