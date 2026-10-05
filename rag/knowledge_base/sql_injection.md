# SQL Injection

## Attack Name
SQL Injection

## Description
SQL Injection occurs when attacker-controlled input is improperly
included in a database query, allowing the attacker to manipulate
the intended SQL operation.

## Common API Pattern
An attacker sends specially crafted input through an API parameter.

Example:

GET /api/users?id=123

The attacker may attempt to manipulate the parameter to alter the
underlying database query.

## Suspicious Behaviour
- SQL-related payloads in API parameters.
- Unexpected database query patterns.
- Repeated requests with modified input.
- Attempts to bypass authentication using crafted input.
- Unusual characters or SQL keywords in parameters.

## Example Evidence
An API receives suspicious input containing SQL syntax in a user ID
or search parameter.

## Detection Indicators
- SQL keywords appearing in request parameters.
- Repeated parameter manipulation.
- Unusual error responses from the database layer.
- Suspicious query patterns.
- Unexpected changes in response behaviour.

## Recommended Response
Validate and sanitize input and use parameterized queries or prepared
statements.

Suspicious requests should be investigated and may contribute to a
higher risk score.

## Severity
Potentially HIGH or CRITICAL depending on whether database access
or sensitive information is affected.