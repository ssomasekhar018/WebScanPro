# XSS Patterns Reference

## Definitions
- **Reflected XSS**: Non-persistent attack where malicious script is injected via URL/query params and immediately reflected in the response (e.g., search results). Example flow: User crafts URL with payload → Server echoes it unescaped in HTML → Browser executes on load.
  - Request: `GET /search?q=<script>alert(1)</script>`
  - Response: `<p>Results for <script>alert(1)</script></p>` → Alert pops.

- **Stored XSS**: Persistent attack where payload is stored (e.g., in DB) and served to all users viewing the page. Example flow: Attacker submits payload in form → Stored in backend → Victim views page → Script executes.
  - Request: `POST /comment {body: "<script>alert(1)</script>"}`
  - Response (later): `<div class="comment"><script>alert(1)</script></div>` → Alert for victim.

- **DOM-based XSS**: Client-side only; payload manipulates DOM via JS (e.g., `document.write(location.hash)`). Not covered here (focus on server-reflected/stored), but example: `?hash=<script>alert(1)</script>` → JS inserts unescaped.

## Payload Categories
- **Simple Alert-Based**: Direct `<script>` or onload triggers. Easy to detect via reflection.
- **Attribute/Event Handlers**: Exploit `onerror`, `onload` in tags like `<img>`. Requires user interaction sometimes.
- **Encoded/Obfuscated**: Bypass filters with URL/hex entities (e.g., `%3Cscript%3E`).
- **Template/Edge-Case**: Target specific parsers (e.g., SVG, CSS expressions) or frameworks (Vue/Angular escapes).

## Safety Notes
- Test only on local labs (Juice Shop/WebGoat).
- Sanitize logs; avoid real PII.
- Get team approval for shared infra.

See `data/payloads_*.csv` for full lists.