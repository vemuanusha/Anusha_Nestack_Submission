# Abuse-Resistant OTP System (Node.js)

Backend for an OTP login flow, hardened against brute force, send-endpoint spam and code reuse.
Zero runtime dependencies, no auth libraries: only Node's built-in `http` and `crypto`.

**Deployment link:** `<add your live URL here>`

## Setup

Requires Node.js 18+.

```bash
npm start          # http://localhost:3000   (set PORT to change)
npm test           # unit + HTTP tests (node:test)
```

Optional env var: `OTP_PEPPER` (server-side secret mixed into every hash; random per process if unset;
set it on the host if you want codes to survive restarts, though in-memory state is lost on restart anyway).

**OTP delivery:** no real SMS/email provider is integrated. The code is **logged to the server console**
(`[DEV ONLY] OTP for <identifier>: 123456`). Remove that log line in production.

## API

```bash
curl -X POST localhost:3000/auth/send   -H 'content-type: application/json' -d '{"identifier":"user@example.com"}'
curl -X POST localhost:3000/auth/verify -H 'content-type: application/json' -d '{"identifier":"user@example.com","code":"123456"}'
```

| Case | Status | Body |
|---|---|---|
| send OK | 200 | `{ "message": "OTP sent to user@example.com" }` |
| send over limit | 429 | `{ "message": ..., "retry_after_seconds": n }` |
| verify OK | 200 | `{ "message": "Verified", "session_token": "..." }` |
| wrong / expired / used / unknown | 400 | `{ "message": "Invalid or expired code", "attempts_remaining": n }` |
| attempt limit reached | 429 | `{ "message": ..., "attempts_remaining": 0 }` |

Bad input is 400, oversized body 413, unknown route 404.

## Security design

**CSPRNG:** `crypto.randomInt(0, 1_000_000)` zero-padded to 6 digits. It draws from the OS CSPRNG and is
uniform (no modulo bias). `Math.random()` is never used. Session tokens use `crypto.randomBytes(32)`.

**Hashing:** the OTP is never stored in plaintext. Each OTP gets a random 16-byte salt and is hashed with
**scrypt** (N=16384, r=8, p=1) keyed additionally with a server-side **pepper** (`OTP_PEPPER`) that is not
stored with the OTP records. Comparison uses `crypto.timingSafeEqual`. Why scrypt rather than plain SHA-256:
a 6-digit code has only 1,000,000 possibilities, so a fast hash is reversible in milliseconds; a slow
memory-hard hash plus a secret pepper makes offline recovery meaningfully harder. Session tokens are stored
only as SHA-256 hashes (they are 256-bit random, so a fast hash is fine).

**Stored per OTP:** identifier, salt, hash, `created_at`, `expires_at` (+10 min), `used`, `attempts`.

**Rate limits (both per identifier, never per IP, in memory):**
- *Send:* a sliding window of send timestamps per identifier. Max 3 within 10 minutes; the 4th gets 429 and
  the limit frees up as old timestamps age out. Checked before any code is generated.
- *Verify:* an `attempts` counter on the current OTP. After 5 incorrect attempts the OTP is locked and every
  further verify (even the correct code) returns 429. Expiry, `used` and attempt checks run on every verify.
- Identifiers are normalised (emails lowercased/trimmed, phone punctuation stripped) so `User@X.com` and
  `user@x.com` cannot be used to dodge limits.

**Reuse:** on success `used` is set to true synchronously (single-threaded event loop, no await between
check and set), so two concurrent verifies cannot both succeed. A new `/auth/send` replaces the previous OTP.

**Known trade-off:** since a fresh send resets the attempt counter, an attacker gets at most
3 sends x 5 guesses = 15 guesses per 10 minutes per identifier (~1.5e-5 chance per window).

**Limitations (in-memory scope):** state is lost on restart and is per-process; a multi-instance deployment
needs a shared store (e.g. Redis). Per-identifier limiting also means an attacker can lock out/spam a victim's
identifier (DoS); pair with per-IP limiting and CAPTCHA in production.

## If the OTP table were leaked

**Attacker could recover:** which identifiers requested codes recently, timestamps, expiry, whether a code
was used and how many attempts were made. If they *also* obtained the pepper (e.g. env/config leak), they could
brute-force all 1,000,000 possible codes against each row's salt offline; scrypt makes this slower but still
feasible for a handful of rows. Codes are only valid 10 minutes and single use, so the window for abuse is small.

**Attacker could not:** read the plaintext code directly, reverse the hash without the pepper (the pepper-keyed
salted scrypt gives no shortcut to the 6 digits beyond guessing), or use rainbow tables (per-row salt). They also
could not obtain session tokens (only SHA-256 hashes are stored; tokens are 256-bit random) or log in from the
table alone. Honest caveat: the hash protects against casual exposure, not against a determined attacker who
holds both the table and the pepper, because the code space is tiny. Short expiry, single use and attempt
limits are what really bound the risk.

## Project layout

```
src/otpService.js   core logic (CSPRNG, hashing, rate limits, verify)
src/server.js       HTTP layer (built-in http module)
test/               unit + HTTP tests
```

## Submission checklist

1. Create a **private** GitHub repo `yourName_Nestack_Submission`; add bishal@nestack.com, sannidhya@nestack.com, sanjay@nestack.com.
2. Deploy (Render/Railway/Fly: start command `npm start`) and put the URL at the top of this README.
3. Submit the ZIP + repo + live link.
