# Authentication & Session Security: Attack Patterns

This document defines common authentication and session-related security patterns, both normal and malicious. It serves as a reference for generating a labeled dataset for anomaly detection.

## 1. Normal User Behavior

### 1.1. Successful Login
- **Flow**: User provides correct credentials (username/password) and gains access.
- **Events**:
  - `POST /login` with valid credentials.
  - HTTP `200 OK` response.
  - `auth_result: success`.
  - A new `session_id` is created and returned.

### 1.2. Failed Login (Incorrect Credentials)
- **Flow**: User provides incorrect credentials.
- **Events**:
  - `POST /login` with invalid password.
  - HTTP `401 Unauthorized` response.
  - `auth_result: failure`.
  - `failure_reason: wrong password`.

### 1.3. Session Logout
- **Flow**: Authenticated user ends their session.
- **Events**:
  - `POST /logout` with a valid `session_id`.
  - HTTP `200 OK` response.
  - The `session_id` is invalidated on the server.

### 1.4. Session Refresh
- **Flow**: An application with a long-lived session automatically refreshes its session token.
- **Events**:
  - `POST /session/refresh` with a valid refresh token.
  - A new `session_id` is issued.

## 2. Malicious & Anomalous Patterns

### 2.1. Brute-Force Attacks
A threat actor attempts to guess a user's password by systematically trying many possibilities.

- **a) Rapid Brute-Force (Single User, Single IP)**
  - **Description**: High-frequency login attempts for one username from one IP address.
  - **Pattern**: `attempt_count_for_username >= 10` within a short time window (e.g., 5 minutes).
  - **Example**: 20 failed login attempts for `admin` from IP `192.168.1.100` in 1 minute.

- **b) Slow Brute-Force (Single User, Single IP)**
  - **Description**: Low-frequency login attempts to avoid simple rate-limiting.
  - **Pattern**: Attempts are spaced out (e.g., 1 attempt every 30 seconds).
  - **Example**: 100 failed login attempts for `user1` from IP `192.168.1.101` over 1 hour.

### 2.2. Credential Stuffing
A threat actor uses lists of compromised credentials (username/password pairs) to attempt logins across many accounts.

- **a) Distributed Credential Stuffing (Many IPs, Many Users)**
  - **Description**: Many different IPs attempt to log in to many different user accounts. This is a large-scale, noisy attack.
  - **Pattern**: High `attempt_count_from_ip` across many distinct usernames.
  - **Example**: IP `203.0.113.55` tries to log in as `userA`, `userB`, `userC`...

- **b) Targeted Credential Stuffing (Many IPs, Single User)**
  - **Description**: Multiple IPs are used to attack a single high-value account to bypass IP-based blocking.
  - **Pattern**: High `distinct_ips_60m` for a single username with many failed logins.
  - **Example**: `user_ceo` receives failed login attempts from 50 different IPs in 10 minutes.

### 2.3. Account Takeover (ATO) Patterns
Behaviors that may indicate a successful compromise of an account.

- **a) Multiple Failures Followed by Success**
  - **Description**: A series of failed login attempts is suddenly followed by a successful one.
  - **Pattern**: `fail_count_15m > 5` for a username, then a successful login.
  - **Example**: 15 failed attempts for `user2`, then a `200 OK` login.

- **b) Impossible Travel / Geolocation Change**
  - **Description**: A successful login occurs from a geographic location that is physically impossible to travel to in the time since the last login.
  - **Pattern**: `geolocation_change_flag = 1`.
  - **Example**: `user3` logs in from the USA, and 5 minutes later, a successful login for `user3` occurs from Russia.

### 2.4. Session Abuse
Exploiting or misusing valid session tokens.

- **a) Session Hijacking / Reuse**
  - **Description**: A stolen `session_id` is used by an attacker from a different IP address or with a different user agent.
  - **Pattern**: `session_reused_flag = 1` (same `session_id` used with a new IP or User-Agent).
  - **Example**: A valid session for `user4` on IP `1.2.3.4` is suddenly used from IP `5.6.7.8`.

- **b) Session Fixation**
  - **Description**: An attacker tricks a user into using a session identifier known to the attacker. This is harder to detect from logs alone but may involve unusual session creation sequences.
  - **Pattern**: A session is created but never used for a successful login, then is later used by another user.

## 3. Other Suspicious Behaviors

- **Rate Limit Triggering**: An IP or user that repeatedly hits the rate limit (`HTTP 429 Too Many Requests`) is highly suspicious.
- **User Agent Anomalies**: A user account that typically uses a standard browser suddenly has login attempts from a script or tool (e.g., `curl`, `python-requests`).
