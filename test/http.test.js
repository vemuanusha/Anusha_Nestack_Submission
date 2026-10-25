'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../src/server');
const { OtpService } = require('../src/otpService');

test('HTTP end to end: status codes and response shapes', async () => {
  const logs = [];
  const server = createApp(new OtpService({ log: (m) => logs.push(m) }));
  await new Promise((r) => server.listen(0, r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = async (path, body) => {
    const r = await fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: r.status, body: await r.json() };
  };
  try {
    const id = 'http@example.com';
    let r = await post('/auth/send', { identifier: id });
    assert.equal(r.status, 200);
    assert.equal(r.body.message, `OTP sent to ${id}`);
    const code = /: (\d{6}) /.exec(logs[0])[1];

    const wrong = code === '000000' ? '111111' : '000000';
    r = await post('/auth/verify', { identifier: id, code: wrong });
    assert.equal(r.status, 400);
    assert.equal(r.body.attempts_remaining, 4);

    r = await post('/auth/verify', { identifier: id, code });
    assert.equal(r.status, 200);
    assert.ok(r.body.session_token);

    r = await post('/auth/verify', { identifier: id, code });
    assert.equal(r.status, 400);

    await post('/auth/send', { identifier: id });
    await post('/auth/send', { identifier: id });
    r = await post('/auth/send', { identifier: id });
    assert.equal(r.status, 429);
  } finally {
    server.close();
  }
});
