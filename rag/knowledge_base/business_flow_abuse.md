# Business Flow Abuse

## Attack Name
Business Flow Abuse

## Description
Business Flow Abuse occurs when an attacker misuses legitimate API
functionality in a way that violates the intended business process.

## Common API Pattern
An attacker repeatedly performs a legitimate API operation in an
unexpected sequence or at an abnormal rate.

Example:

POST /api/checkout

## Suspicious Behaviour
- Repeated execution of sensitive operations.
- Unexpected sequence of API calls.
- Rapid repetition of business actions.
- Attempts to bypass business rules.
- Unusual usage of legitimate API functionality.

## Example Evidence
A user repeatedly performs a sensitive transaction operation far
beyond normal usage.

## Detection Indicators
- Abnormal request frequency.
- Unexpected endpoint sequences.
- Repeated sensitive operations.
- Behaviour inconsistent with normal users.
- Unusual combinations of API operations.

## Recommended Response
Validate business rules on the server side and enforce appropriate
limits on sensitive operations.

Suspicious activity should be investigated and may contribute to a
higher risk score.

## Severity
Potentially MEDIUM or HIGH depending on the affected business
function and impact.