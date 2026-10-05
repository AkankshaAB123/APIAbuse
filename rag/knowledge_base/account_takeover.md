# Account Takeover

## Attack Name
Account Takeover

## Description
Account takeover occurs when an attacker gains unauthorized access
to a legitimate user's account.

## Common API Pattern
An attacker successfully authenticates using compromised credentials
or a stolen authentication token.

Example:

POST /api/login

or

GET /api/account/profile

## Suspicious Behaviour
- Login from unusual sources.
- Sudden changes in user behaviour.
- Authentication using suspicious credentials or tokens.
- Access to sensitive account information.
- Multiple login attempts followed by successful authentication.
- Rapid changes to account settings.

## Example Evidence
A user account experiences many failed authentication attempts
followed by a successful login from an unusual source.

## Detection Indicators
- Unusual authentication patterns.
- Multiple failed attempts before successful login.
- Suspicious source IP.
- Abnormal request frequency.
- Unexpected access to sensitive endpoints.

## Recommended Response
Investigate the account activity and verify whether the successful
authentication was legitimate.

Additional authentication or temporary account restrictions may be
recommended when the risk is high.

## Severity
Usually HIGH and potentially CRITICAL when sensitive accounts or
resources are affected.