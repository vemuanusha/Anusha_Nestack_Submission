'use strict';
/**
 * OTP service: generation (CSPRNG), hashed storage, rate limiting, verification.
 * All state is in memory (acceptable per the assessment brief).
 */
const crypto = require('node:crypto');

const CONFIG = {
  OTP_TTL_MS: 10 * 60 * 1000,        // code expires 10 minutes after generation
  MAX_VERIFY_ATTEMPTS: 5,            // lock OTP after 5 incorrect attempts
  SEND_LIMIT: 3,                     // max 3 sends ...
  SEND_WINDOW_MS: 10 * 60 * 1000,    // ... per identifier per 10 minutes
  SESSION_TTL_MS: 60 * 60 * 1000,    // session tokens live 1 hour
};

// Server-side secret ("pepper") mixed into every hash. Never stored with the OTP rows.
const PEPPER = process.env.OTP_PEPPER || crypto.randomBytes(32).toString('hex');

class HttpError extends Error {
  constructor(status, body) {
    super(body.message);
    this.status = status;
    this.body = body;
  }
}

class OtpService {
  constructor({ now = () => Date.now(), log = console.log } = {}) {
    this.now = now;
    this.log = log;
    this.otps = new Map();       // identifier -> OTP record (only the latest is valid)
    this.sendLog = new Map();    // identifier -> array of send timestamps (sliding window)
    this.sessions = new Map();   // token hash -> { identifier, expiresAt }
  }

  // ---------- helpers ----------

  static normalizeIdentifier(raw) {
    if (typeof raw !== 'string') return null;
    const v = raw.trim();
    if (v.length === 0 || v.length > 254) return null;
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return v.toLowerCase();       // email
    const phone = v.replace(/[\s\-().]/g, '');
    if (/^\+?[0-9]{7,15}$/.test(phone)) return phone;                        // phone
    return null;
  }

  /** CSPRNG 6-digit code. crypto.randomInt is uniform (no modulo bias) and uses the OS CSPRNG. */
  static generateCode() {
    return crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
  }

  /** scrypt (memory-hard, per-OTP random salt) keyed with a server-side pepper. */
  static hashCode(code, saltHex) {
    return crypto
      .scryptSync(code, Buffer.from(saltHex + PEPPER, 'utf8'), 32, { N: 16384, r: 8, p: 1 })
      .toString('hex');
  }

  static safeEqualHex(a, b) {
    const ba = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  }

  // ---------- send ----------

  send(rawIdentifier) {
    const identifier = OtpService.normalizeIdentifier(rawIdentifier);
    if (!identifier) throw new HttpError(400, { message: 'A valid email or phone number is required' });

    const now = this.now();

    // Rate limit per identifier (sliding window), checked BEFORE doing any work.
    const recent = (this.sendLog.get(identifier) || []).filter((t) => now - t < CONFIG.SEND_WINDOW_MS);
    if (recent.length >= CONFIG.SEND_LIMIT) {
      const retryAfterSec = Math.ceil((recent[0] + CONFIG.SEND_WINDOW_MS - now) / 1000);
      this.sendLog.set(identifier, recent);
      throw new HttpError(429, {
        message: 'Too many OTP requests. Try again later.',
        retry_after_seconds: retryAfterSec,
      });
    }
    recent.push(now);
    this.sendLog.set(identifier, recent);

    const code = OtpService.generateCode();
    const salt = crypto.randomBytes(16).toString('hex');
    // A new OTP replaces (and so invalidates) any previous one for this identifier.
    this.otps.set(identifier, {
      identifier,
      salt,
      code_hash: OtpService.hashCode(code, salt),
      created_at: now,
      expires_at: now + CONFIG.OTP_TTL_MS,
      used: false,
      attempts: 0,
    });

    // Development delivery: log to console instead of a real SMS/email provider.
    this.log(`[DEV ONLY] OTP for ${identifier}: ${code} (expires in 10 minutes)`);
    return { message: `OTP sent to ${identifier}` };
  }

  // ---------- verify ----------

  verify(rawIdentifier, rawCode) {
    const identifier = OtpService.normalizeIdentifier(rawIdentifier);
    if (!identifier || typeof rawCode !== 'string') {
      throw new HttpError(400, { message: 'identifier and code are required' });
    }
    const generic = { message: 'Invalid or expired code' };
    const rec = this.otps.get(identifier);
    if (!rec) throw new HttpError(400, generic);

    const now = this.now();

    // Attempt limit first: a locked OTP stays locked and never reveals anything.
    if (rec.attempts >= CONFIG.MAX_VERIFY_ATTEMPTS) {
      throw new HttpError(429, {
        message: 'Too many incorrect attempts. Request a new code.',
        attempts_remaining: 0,
      });
    }
    if (rec.used) throw new HttpError(400, generic);
    if (now >= rec.expires_at) throw new HttpError(400, generic);

    const submitted = rawCode.trim();
    // Always run the hash so timing does not depend on the format of the guess.
    const ok =
      OtpService.safeEqualHex(OtpService.hashCode(/^\d{6}$/.test(submitted) ? submitted : '------', rec.salt), rec.code_hash) &&
      /^\d{6}$/.test(submitted);

    if (!ok) {
      rec.attempts += 1;
      const remaining = CONFIG.MAX_VERIFY_ATTEMPTS - rec.attempts;
      if (remaining <= 0) {
        throw new HttpError(429, {
          message: 'Too many incorrect attempts. Request a new code.',
          attempts_remaining: 0,
        });
      }
      throw new HttpError(400, { ...generic, attempts_remaining: remaining });
    }

    // Success: invalidate immediately (synchronous, so no race between two requests).
    rec.used = true;

    const token = crypto.randomBytes(32).toString('base64url');
    this.sessions.set(crypto.createHash('sha256').update(token).digest('hex'), {
      identifier,
      expiresAt: now + CONFIG.SESSION_TTL_MS,
    });
    return { message: 'Verified', session_token: token };
  }

  /** Housekeeping so memory does not grow forever. */
  sweep() {
    const now = this.now();
    for (const [id, rec] of this.otps) {
      if (now - rec.expires_at > CONFIG.OTP_TTL_MS) this.otps.delete(id);
    }
    for (const [id, arr] of this.sendLog) {
      const fresh = arr.filter((t) => now - t < CONFIG.SEND_WINDOW_MS);
      if (fresh.length) this.sendLog.set(id, fresh);
      else this.sendLog.delete(id);
    }
    for (const [h, s] of this.sessions) {
      if (s.expiresAt <= now) this.sessions.delete(h);
    }
  }
}

module.exports = { OtpService, HttpError, CONFIG };
