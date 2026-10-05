# Resource Exhaustion

## Attack Name
Resource Exhaustion

## Description
Resource exhaustion occurs when an attacker generates excessive API
requests or expensive operations in an attempt to consume server
resources.

## Common API Pattern
An attacker repeatedly sends requests to an API endpoint at a rate
that is significantly higher than normal.

Example:

GET /api/search

## Suspicious Behaviour
- Extremely high request rate.
- Repeated requests from the same source.
- Large numbers of expensive API operations.
- Sudden traffic spikes.
- Abnormally high resource usage.

## Example Evidence
A source IP sends thousands of requests to an API endpoint within a
short period.

## Detection Indicators
- High request_count.
- High request frequency.
- Sudden increase in traffic.
- Repeated access to resource-intensive endpoints.
- Unusual traffic patterns.

## Recommended Response
Apply rate limiting, request throttling, quotas, and other controls
to prevent excessive resource consumption.

High-confidence attacks may be recommended for blocking.

## Severity
Potentially MEDIUM, HIGH, or CRITICAL depending on the traffic volume
and impact on service availability.