# Server-Side Request Forgery (SSRF)

## Attack Name
Server-Side Request Forgery (SSRF)

## Description
SSRF occurs when an attacker manipulates an API or server-side
function to make requests to unintended internal or external
resources.

## Common API Pattern
An API accepts a URL or remote resource as input.

Example:

POST /api/fetch

The attacker provides a URL that points to an internal service.

## Suspicious Behaviour
- Requests to internal IP addresses.
- Requests to localhost.
- Access attempts to internal services.
- Unexpected external destinations.
- Repeated URL manipulation.
- Requests to unusual ports or network locations.

## Example Evidence
An API normally fetches public URLs but receives requests targeting
localhost or internal network addresses.

## Detection Indicators
- Internal IP addresses in request parameters.
- localhost or loopback addresses.
- Unusual destination ports.
- Repeated URL manipulation.
- Unexpected server-to-server requests.

## Recommended Response
Validate and restrict user-supplied URLs and prevent access to
internal network resources.

Suspicious requests should be investigated and may contribute to a
higher risk score.

## Severity
Potentially HIGH or CRITICAL when internal services or sensitive
resources are targeted.