'use strict';
const http = require('node:http');
const { OtpService, HttpError } = require('./otpService');

const MAX_BODY_BYTES = 4 * 1024;

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new HttpError(413, { message: 'Request body too large' }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
        resolve(parsed);
      } catch {
        reject(new HttpError(400, { message: 'Body must be a JSON object' }));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(data);
}

function createApp(service = new OtpService()) {
  const server = http.createServer(async (req, res) => {
    const path = (req.url || '').split('?')[0];
    try {
      if (req.method === 'GET' && (path === '/' || path === '/health')) {
        return sendJson(res, 200, { message: 'OTP service running', endpoints: ['POST /auth/send', 'POST /auth/verify'] });
      }
      if (path === '/auth/send' || path === '/auth/verify') {
        if (req.method !== 'POST') return sendJson(res, 405, { message: 'Method not allowed' });
        const body = await readJson(req);
        const result = path === '/auth/send' ? service.send(body.identifier) : service.verify(body.identifier, body.code);
        return sendJson(res, 200, result);
      }
      return sendJson(res, 404, { message: 'Not found' });
    } catch (err) {
      if (err instanceof HttpError) return sendJson(res, err.status, err.body);
      console.error(err);
      return sendJson(res, 500, { message: 'Internal server error' });
    }
  });
  const timer = setInterval(() => service.sweep(), 60 * 1000);
  timer.unref();
  server.on('close', () => clearInterval(timer));
  return server;
}

module.exports = { createApp };

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  createApp().listen(port, () => console.log(`OTP service listening on port ${port}`));
}
