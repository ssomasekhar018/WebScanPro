# Authentication Patterns & Attack Scenarios

## Overview

This document defines normal authentication behaviors and malicious attack patterns for dataset generation and anomaly detection model training.

---

## Normal Authentication Flows

### 1. Normal Login Flow

**Description**: Standard successful authentication process.

**Flow**:
1. User submits valid credentials (username + password)
2. Server validates credentials
3. Server creates session token (e.g., JWT, session cookie)
4. Returns 200 OK with session identifier
5. User performs authorized actions using session token

**Characteristics**:
- Single attempt per login
- Valid credentials on first attempt
- Consistent IP address and user agent
- Normal time intervals between logins (> minutes)

**Example**:
```
POST /login
{ "username": "user123", "password": "correct_pass" }
→ 200 OK, Set-Cookie: session_id=abc123...
```

---

### 2. Session Creation

**Description**: After successful login, server creates a session with associated metadata.

**Characteristics**:
- Session ID generated (UUID or random token)
- Session expiry time set (e.g., 30 minutes, 24 hours)
- Session metadata stored: IP, user_agent, creation time
- Session linked to user account

**Session Lifecycle**:
- Creation: At login success
- Refresh: Via `/session/refresh` endpoint
- Invalidation: At logout or expiry

---

### 3. Logout

**Description**: User-initiated session termination.

**Flow**:
1. User sends logout request with valid session token
2. Server invalidates session
3. Returns 200 OK

**Characteristics**:
- Requires valid session token
- Session removed from active sessions
- Subsequent requests with same token rejected

---

### 4. Session Refresh

**Description**: Extending session lifetime without re-authentication.

**Flow**:
1. Client sends refresh request with valid session token
2. Server extends expiry time
3. Returns 200 OK with updated session info

**Characteristics**:
- Only valid sessions can be refreshed
- Extends session lifetime
- Same session ID typically maintained

---

## Failed Authentication Scenarios

### 1. Bad Password

**Description**: Incorrect password provided.

**Characteristics**:
- Status: 401 Unauthorized
- Auth result: `failure`
- Failure reason: `bad_password`
- Username exists, password mismatch
- No account lockout triggered (unless threshold reached)

**Example**:
```
POST /login
{ "username": "user123", "password": "wrong_pass" }
→ 401 Unauthorized
```

---

### 2. Invalid User

**Description**: Username does not exist in system.

**Characteristics**:
- Status: 401 Unauthorized
- Auth result: `failure`
- Failure reason: `invalid_user`
- May be indistinguishable from bad_password (security best practice)

---

### 3. Locked Account

**Description**: Account temporarily locked after multiple failed attempts.

**Characteristics**:
- Status: 423 Locked or 401 with lockout message
- Auth result: `locked`
- Failure reason: `locked`
- Triggered after N failed attempts (e.g., 5-10 attempts)
- Lockout duration: 15-60 minutes typically

---

### 4. Rate-Limited Response

**Description**: Too many requests from same IP/username trigger rate limiting.

**Characteristics**:
- Status: 429 Too Many Requests
- Auth result: `rate_limited`
- Failure reason: `rate_limited`
- Indicates suspicious activity pattern
- Retry-After header may be present

**Example**:
```
POST /login (repeated many times)
→ 429 Too Many Requests, Retry-After: 300
```

---

## Attack Patterns

### 1. Brute-Force Attacks

**Description**: Rapid repeated login attempts with varying passwords to guess correct credentials.

**Characteristics**:
- High attempt rate: > 10 attempts/minute
- Same username, different passwords
- Multiple failed attempts (401) before potential success
- May target single account or multiple accounts
- Short intervals between attempts (< 5 seconds)

**Detection Indicators**:
- `attempt_count_for_username >= 10 within 10 minutes`
- High failure-to-success ratio
- Rapid sequential attempts

**Variants**:
- **Rapid brute-force**: Very high rate (> 50 attempts/minute)
- **Slow brute-force**: Low rate (< 1 attempt/minute) to evade detection
- **Distributed brute-force**: Multiple IPs attacking same account

---

### 2. Credential Stuffing

**Description**: Automated login attempts using stolen credentials from data breaches.

**Characteristics**:
- Many different usernames attempted
- Moderate attempt rate per username (1-5 attempts/minute)
- Same password or small password set tested across many accounts
- Distributed across multiple IPs
- Some successes expected if credentials valid

**Detection Indicators**:
- `attempt_count_from_ip >= 50 across multiple usernames within 10 minutes`
- Many distinct usernames from single IP
- Pattern: attempt user1, user2, user3... with same password set

---

### 3. Account Takeover Patterns

**Description**: Successful authentication after reconnaissance, followed by suspicious activity.

**Characteristics**:
- Multiple failed attempts followed by success
- Login from new/unusual IP/geolocation
- Rapid session creation after many failures
- Changes in user agent or device

**Detection Indicators**:
- Successful login after `>= 5` failed attempts for username
- IP geolocation change < 1 minute after last login
- Session from different country than previous sessions

**Example Flow**:
1. Failed attempts from IP_A (attacker testing)
2. Successful login from IP_A
3. Immediate access from IP_B (different country) - suspicious

---

### 4. Session Abuse Patterns

#### Session Hijack Simulation

**Description**: Reusing session token from different IP/location (lab environment only).

**Characteristics**:
- Same session token used from multiple IPs
- Short time window (< 5 minutes) between IP changes
- No logout between IP switches
- Violates normal session behavior

**Detection Indicators**:
- `session_reused_flag = 1`: Same session token from different IP
- Geographic anomaly: session from country A, then country B immediately

---

#### Long-Lived Suspicious Sessions

**Description**: Unusually long session duration, potentially indicating compromised account.

**Characteristics**:
- Session duration > 24 hours (depends on normal policy)
- No refresh activity
- Continuous activity pattern
- May indicate automated bot

---

#### Session Fixation Attempts

**Description**: Attacker sets session ID, then tricks user to authenticate with that ID.

**Characteristics**:
- Session ID provided by attacker
- Login accepts attacker's session ID
- Attacker reuses session after user authenticates

**Note**: Requires vulnerable application accepting session IDs from client.

---

### 5. Valid-Then-Malicious Pattern

**Description**: Normal login followed by suspicious actions.

**Flow**:
1. Normal successful login (valid credentials)
2. Immediate suspicious activity (e.g., password change, privilege escalation)
3. Unusual access patterns (many privileged endpoints)

**Characteristics**:
- Initial authentication appears normal
- Post-login behavior anomalous
- Rapid privilege actions
- May indicate compromised credentials

---

## Attack Pattern Categories for Simulation

### Category A: High-Frequency Attacks
- **Rapid brute-force**: 50-100 attempts/minute
- **Credential stuffing burst**: 20-50 usernames/minute from single IP

### Category B: Distributed Attacks
- **Multi-IP brute-force**: Same username from 5-10 different IPs
- **Geographically distributed**: Attempts from multiple countries

### Category C: Low-and-Slow Attacks
- **Slow brute-force**: 1 attempt every 2-5 minutes
- **Stealth credential stuffing**: < 1 attempt/minute per username

### Category D: Sophisticated Patterns
- **Valid-then-malicious**: Successful login + immediate suspicious actions
- **Session hijack simulation**: Token reuse across IPs (lab only)

---

## Labeling Heuristics Summary

### is_bruteforce_candidate = 1
- `attempt_count_for_username >= 10 within 10 minutes`, OR
- `attempt_count_from_ip >= 50 across multiple usernames within 10 minutes`, OR
- > 5 distinct IPs attempting same username within 1 hour

### is_anomalous = 1
- Successful login from different country < 1 minute after last login, OR
- Session token reused across IPs within 5 minutes, OR
- Status code 429 (rate-limiting) after multiple failures, OR
- `is_bruteforce_candidate = 1`, OR
- Successful login after >= 5 failed attempts for same username

### Manual Review Flags
- Geographic change borderline (e.g., same region but different city)
- Low-attempt anomalies (5-9 attempts for username)
- Unusual but potentially legitimate patterns (VPN usage, travel)

---

## Dataset Generation Considerations

1. **Balance**: Mix normal (70-80%) and attack patterns (20-30%)
2. **Variety**: Include all attack categories above
3. **Realism**: Mimic real-world timing and patterns
4. **Privacy**: Hash/anonymize PII (usernames, IPs, session IDs)
5. **Timestamps**: Ensure realistic temporal distribution
6. **Validation**: Include edge cases and ambiguous scenarios

