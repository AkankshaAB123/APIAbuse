# BOLA / IDOR

## Attack Name
Broken Object Level Authorization (BOLA)

## Description
BOLA occurs when an API allows a user to access an object or resource
belonging to another user without properly checking authorization.

## Common API Pattern
A user requests a resource using an object identifier such as:

GET /api/users/123

The server should verify that the authenticated user is authorized
to access resource 123.

## Suspicious Behaviour
- User accesses another user's resource.
- Object identifiers are changed repeatedly.
- Sequential resource IDs are requested.
- The same user accesses resources belonging to multiple users.
- Authorization checks appear to be missing.

## Example Evidence
User user123 requests:

GET /api/users/456

when resource 456 belongs to a different user.

## Detection Indicators
- User ID does not match resource owner.
- Repeated object ID manipulation.
- Access to multiple unauthorized resources.
- Unusual sequence of object identifiers.

## Recommended Response
Investigate the authorization failure and restrict access to the
affected resources.

For high-confidence malicious behaviour, the system may recommend
blocking or additional access controls.

## Severity
Potentially HIGH or CRITICAL depending on the affected resource
and confidence of detection.