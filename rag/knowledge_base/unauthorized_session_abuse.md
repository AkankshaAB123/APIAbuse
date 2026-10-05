# Unauthorized Session and Transaction Abuse

## Attack Name
Unauthorized Session and Transaction Abuse

## Security Domain
API

## Description
Unauthorized session and transaction abuse occurs when an adversary leverages a valid, compromised, or replayed session token to execute transactions or sensitive actions without the legitimate account holder's consent. This scenario typically involves an active user session hijacked or abused across an unexpected source IP, irregular device fingerprint, or out-of-sequence financial or operational endpoint.

## Common API Pattern
The attacker submits unauthorized transactions using a hijacked or stolen session identifier or bearer token.

Example:

POST /api/transaction/transfer
POST /api/checkout/pay
POST /api/session/action

## Suspicious Behaviour
- Sudden change in client source IP or user agent during an established session.
- High-value or rapid sequence transactions occurring without typical preceding interaction flow.
- Token or session identifier used concurrently from geographically disparate locations.
- Replay of previously validated transaction tokens or session headers.
- Deviation from normal transaction frequency, volume, or user timing profile.

## Example Evidence
An established session ID associated with authenticated user user_101 suddenly submits a funds transfer or checkout request from an unrecognized IP address, bypassing normal multi-factor or secondary confirmation checkpoints.

## Detection Indicators
- Session continuity mismatch (IP address or device fingerprint change during active session).
- Rapid transaction attempts following authentication.
- Business flow violation (transaction executed without required prerequisite steps).
- Discrepancy between session owner identity and destination beneficiary or resource owner.

## Recommended Response
1. Terminate or invalidate the suspicious session token immediately.
2. Require step-up re-authentication (multi-factor challenge) for subsequent operations.
3. Apply rate limiting and temporary transaction hold on affected account.
4. Notify the user via an out-of-band channel regarding the suspicious transaction.

## Severity
HIGH to CRITICAL depending on transaction value and scope of affected financial or operational data.
