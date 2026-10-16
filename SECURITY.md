# Security Design Document

This document describes the security architecture of mcp-rhhi-crunchtools.

## 1. Threat Model

### 1.1 Assets to Protect

The catalog API is public and read-only, and the server holds no credentials. What matters is that the server cannot be turned against its host or the agent using it.

| Asset | Sensitivity | Impact if Compromised |
|-------|-------------|----------------------|
| Host network reachability | Medium | SSRF into services next to the server |
| Agent context window | Medium | Flooding with oversized or hostile upstream content |
| Integrity of catalog answers | Medium | An agent picks a wrong image or misses a CVE |

### 1.2 Attack Vectors

| Vector | Description | Mitigation |
|--------|-------------|------------|
| **Path Traversal** | `../` or `/` in an image, tag or digest | Published patterns, re-checked in `segment()` / `digest_segment()`, then URL-encoded |
| **SSRF** | Redirect requests to an internal host | Base URL comes only from `RHHI_API_URL`; HTTPS required except localhost |
| **Oversized responses** | Memory exhaustion or context flooding | 20 MB cap on header and body; tools filter and cap lists |
| **Hostile upstream text** | Long or crafted error bodies | Error messages truncated to 200 characters, identifiers to 40 |
| **Supply Chain** | Compromised dependencies | Weekly pip-audit, Trivy and CodeQL; Hummingbird base image |

## 2. Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Credentials                                         │
│ - None. The catalog API is unauthenticated                  │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Input Validation                                    │
│ - Every parameter typed and constrained in the schema       │
│ - Closed schemas (additionalProperties: false)              │
│ - Optional "" / null / 0 normalize to "not given"           │
│ - All tools annotated readOnlyHint                          │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: API Hardening                                       │
│ - TLS certificate validation (httpx default)                │
│ - Request timeout (RHHI_TIMEOUT, default 30s)               │
│ - Response size limit (20MB)                                │
│ - URL-encoded path segments                                 │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Dangerous Operation Prevention                      │
│ - GET only; no filesystem access, shell or eval             │
├─────────────────────────────────────────────────────────────┤
│ Layer 5: Supply Chain                                        │
│ - Weekly CVE scanning, Gourmand, Hummingbird base           │
└─────────────────────────────────────────────────────────────┘
```

## 3. Reporting a Vulnerability

Report security vulnerabilities using [GitHub's private security advisory](https://github.com/crunchtools/mcp-rhhi/security/advisories/new). This creates a private channel visible only to maintainers.
