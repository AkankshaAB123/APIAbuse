# Broken Authorization

## Attack Name
Broken Authorization

## Description
Broken Authorization occurs when an API fails to properly enforce
permissions for authenticated users.

## Common API Pattern
An authenticated user sends a request to an API endpoint that requires
specific permissions.

For example:

GET /api/admin/users

The server should verify that the requesting user has the required
administrator privileges.

## Suspicious Behaviour
- Regular users accessing administrator endpoints.
- Users performing actions outside their assigned role.
- Repeated unauthorized requests.
- Access to restricted API resources.
- Attempts to modify protected resources.

## Example Evidence
A normal user repeatedly requests:

GET /api/admin/users

without having administrator privileges.

## Detection Indicators
- User role does not match the requested operation.
- Repeated HTTP 401 or 403 responses.
- Access attempts to restricted endpoints.
- Privilege-related endpoint enumeration.

## Recommended Response
Verify the user's permissions before allowing access to the requested
resource or operation.

Suspicious repeated attempts should be investigated and may contribute
to a higher risk score.

## Severity
Potentially HIGH or CRITICAL depending on the resource being accessed
and the user's privileges.