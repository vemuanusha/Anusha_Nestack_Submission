'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { OtpService, HttpError, CONFIG } = require('../src/otpService');

function setup() {
  const clock = { t: 1_700_000_000_000 };
  const logs = [];
  const svc = new OtpService({ now: () => clock.t, log: (m) => logs.push(m) });
  const lastCode = () => /: (\d{6}) /.exec(logs[logs.length - 1])[1];
  return { svc, clock, logs, lastCode };
}
const status = (fn) => {
  try { fn(); return 200; } catch (e) { assert.ok(e instanceof HttpError); return e.status; }
};

test('code is 6 digits and plaintext is never stored', () => {
  const { svc, lastCode } = setup();
  svc.send('user@example.com');
  const code = lastCode();
  assert.match(code, /^\d{6}$/);
  const rec = svc.otps.get('user@example.com');
  assert.ok(!JSON.stringify(rec).includes(code));
  assert.equal(rec.used, false);
  assert.equal(rec.attempts, 0);
});

test('happy path returns session token; reuse fails with 400', () => {
  const { svc, lastCode } = setup();
  svc.send('user@example.com');
  const code = lastCode();
  const ok = svc.verify('user@example.com', code);
  assert.equal(ok.message, 'Verified');
  assert.ok(ok.session_token.length >= 32);
  assert.equal(status(() => svc.verify('user@example.com', code)), 400);
});

test('expired code is rejected with 400', () => {
  const { svc, clock, lastCode } = setup();
  svc.send('user@example.com');
  const code = lastCode();
  clock.t += CONFIG.OTP_TTL_MS + 1;
  assert.equal(status(() => svc.verify('user@example.com', code)), 400);
});

test('locks after 5 wrong attempts (429), even for the correct code', () => {
  const { svc, lastCode } = setup();
  svc.send('user@example.com');
  const code = lastCode();
  const wrong = code === '000000' ? '111111' : '000000';
  for (let i = 1; i <= 4; i++) {
    try { svc.verify('user@example.com', wrong); assert.fail(); }
    catch (e) { assert.equal(e.status, 400); assert.equal(e.body.attempts_remaining, 5 - i); }
  }
  assert.equal(status(() => svc.verify('user@example.com', wrong)), 429);
  assert.equal(status(() => svc.verify('user@example.com', code)), 429);
});

test('send limit: 4th request in window is 429, resets after window', () => {
  const { svc, clock } = setup();
  for (let i = 0; i < 3; i++) svc.send('+919876543210');
  assert.equal(status(() => svc.send('+919876543210')), 429);
  assert.equal(status(() => svc.send('other@example.com')), 200); // per identifier
  clock.t += CONFIG.SEND_WINDOW_MS + 1;
  assert.equal(status(() => svc.send('+919876543210')), 200);
});

test('identifier normalisation prevents rate-limit bypass via casing', () => {
  const { svc } = setup();
  svc.send('User@Example.com'); svc.send('user@example.com'); svc.send(' USER@example.com ');
  assert.equal(status(() => svc.send('user@EXAMPLE.com')), 429);
});

test('new send invalidates the previous code', () => {
  const { svc, logs } = setup();
  svc.send('user@example.com');
  const first = /: (\d{6}) /.exec(logs[0])[1];
  svc.send('user@example.com');
  const second = /: (\d{6}) /.exec(logs[1])[1];
  if (first !== second) assert.equal(status(() => svc.verify('user@example.com', first)), 400);
});

test('invalid input is rejected', () => {
  const { svc } = setup();
  assert.equal(status(() => svc.send('not-an-identifier')), 400);
  assert.equal(status(() => svc.send(undefined)), 400);
  assert.equal(status(() => svc.verify('user@example.com', '123456')), 400);
});
