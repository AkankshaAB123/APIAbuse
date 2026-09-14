# Fraudulent Shopping and E-Commerce Abuse

## Attack Name
Fraudulent Shopping and E-Commerce Abuse

## Security Domain
API

## Description
Fraudulent shopping scenarios involve malicious actors simulating deceptive storefronts or exploiting e-commerce API flows. In classic consumer fraud, victims are lured via social engineering messages to fraudulent shopping pages where orders and payments are collected for illegitimate goods, followed by transaction rejection, order abandonment, or service shutdown. In API abuse scenarios, automated bots manipulate cart flows, exploit checkout pricing, or bypass checkout stages.

## Common API Pattern
An automated client or spoofed interface interacts with shopping checkout, coupon, or cart endpoints in an abnormal sequence or submits forged transaction payloads.

Example:

POST /api/cart/checkout
POST /api/orders/place
POST /api/payment/process

## Suspicious Behaviour
- Deceptive promotions leading to checkout endpoints hosted on untrusted or spoofed domains (.example.test).
- Abnormal order frequency, manipulated item prices, or altered quantities during checkout.
- Fast-flux checkout endpoints that become abruptly unreachable or return invalid order statuses.
- Discrepancies between payment gateway confirmation and internal order validation.
- Repetitive checkout submissions using synthetic identities or automated scripts.

## Example Evidence
A checkout request contains anomalous quantity or price modifications, or originates from a synthetic consumer interaction pattern lacking legitimate browsing history, pointing to automated fraud or predatory checkout manipulation.

## Detection Indicators
- Checkout requests originating without preceding catalog view or cart-addition events.
- Price, currency, or discount parameter tampering in request bodies.
- Rapid bursts of purchase requests from a single client IP or coordinated proxies.
- Destination endpoints referencing unverified payment gateways or disposable domains.

## Recommended Response
1. Enforce strict server-side price, quantity, and inventory validation on all checkout endpoints.
2. Rate limit and throttle automated checkout submissions.
3. Validate origin headers and referrers for incoming order requests.
4. Flag suspicious orders for manual review prior to processing.

## Severity
MEDIUM to HIGH depending on financial exposure and customer fraud risk.
