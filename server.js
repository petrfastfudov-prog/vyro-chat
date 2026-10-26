const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 1_500_000,
  pingInterval: 25000,
  pingTimeout: 20000
});
const PUBLIC_DIR = path.join(__dirname, 'public');
const PORT = Number(process.env.PORT) || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const allowedOrigin = process.env.APP_ORIGIN || '';

// Privacy-first: no chat history, uploaded files, IP addresses or message bodies are stored.
// Reports contain only reason, time and transient socket IDs, in memory, and vanish on restart.
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), payment=()');
  if (process.env.NODE_ENV === 'production') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
app.use(express.static(PUBLIC_DIR, { dotfiles: 'deny', etag: true, maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0 }));
app.get('/healthz', (_req, res) => res.status(200).json({ ok: true }));
app.get('/admin/reports', (req, res) => {
  if (!ADMIN_TOKEN) return res.status(503).json({ error: 'ADMIN_TOKEN is not configured' });
  const auth = req.get('authorization') || '';
  const supplied = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const a = Buffer.from(supplied); const b = Buffer.from(ADMIN_TOKEN);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Unauthorized' });
  res.setHeader('Cache-Control', 'no-store');
  res.json({ reports: reports.slice(-200), note: 'In-memory only; reports disappear when the process restarts.' });
});

const searchQueues = { general: [], flirt: [], adult: [] };
const rooms = new Map(); // socket ID -> room name
const rateEvents = new Map();
const blockedUntil = new Map();
const reports = [];
const MAX_REPORTS = 500;
const MAX_TEXT = 2000;
const MAX_MEDIA_DATA_URL = 1_350_000;
const MAX_IGNORED = 50;

if (allowedOrigin) {
  io.engine.on('headers', (headers, req) => {
    // Socket.IO's same-origin defaults remain in effect. APP_ORIGIN is intended for deployment checks.
    const origin = req.headers.origin;
    if (origin && origin !== allowedOrigin) req._vhsOriginRejected = true;
  });
  io.use((socket, next) => {
    const origin = socket.handshake.headers.origin;
    if (origin && origin !== allowedOrigin) return next(new Error('Origin not allowed'));
    next();
  });
}

function limited(socket, bucket, max, windowMs, cooldownMs = 10000) {
  const now = Date.now();
  const key = `${socket.id}:${bucket}`;
  const until = blockedUntil.get(key) || 0;
  if (until > now) return true;
  const times = (rateEvents.get(key) || []).filter(t => now - t < windowMs);
  times.push(now);
  rateEvents.set(key, times);
  if (times.length > max) {
    blockedUntil.set(key, now + cooldownMs);
    return true;
  }
  return false;
}
function cleanSocketLimits(id) {
  for (const key of rateEvents.keys()) if (key.startsWith(`${id}:`)) rateEvents.delete(key);
  for (const key of blockedUntil.keys()) if (key.startsWith(`${id}:`)) blockedUntil.delete(key);
}
function validPhoto(dataUrl) {
  if (typeof dataUrl !== 'string' || dataUrl.length > MAX_MEDIA_DATA_URL) return false;
  const match = /^data:image\/jpeg;base64,([A-Za-z0-9+/]+=*)$/.exec(dataUrl);
  if (!match || match[1].length < 16) return false;
  try { return Buffer.from(match[1], 'base64').subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff])); } catch { return false; }
}
function validVoice(dataUrl) {
  if (typeof dataUrl !== 'string' || dataUrl.length > MAX_MEDIA_DATA_URL) return false;
  const match = /^data:audio\/(webm|ogg|mp4)(?:;codecs=[^;,]+)?;base64,([A-Za-z0-9+/]+=*)$/.exec(dataUrl);
  if (!match || match[2].length < 24) return false;
  try {
    const bytes = Buffer.from(match[2], 'base64');
    if (match[1] === 'webm') return bytes.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]));
    if (match[1] === 'ogg') return bytes.subarray(0, 4).toString('ascii') === 'OggS';
    return bytes.length > 12 && bytes.subarray(4, 8).toString('ascii') === 'ftyp';
  } catch { return false; }
}

io.on('connection', socket => {
  // Do not log socket IDs, tokens, IP addresses, or chat content.
  socket.emit('server_policy', { age: '18+', historyStored: false });
  updateOnlineCount();

  socket.on('find_partner', data => {
    if (limited(socket, 'find', 5, 10000, 30000)) {
      socket.emit('rate_limited', { message: 'Слишком частые запросы. Подожди 30 секунд.' });
      return;
    }
    const mode = data && ['general', 'flirt', 'adult'].includes(data.mode) ? data.mode : 'general';
    const ignored = Array.isArray(data && data.ignored)
      ? data.ignored.filter(x => typeof x === 'string' && x.length <= 80).slice(0, MAX_IGNORED)
      : [];
    if (rooms.has(socket.id)) leaveRoom(socket);
    removeFromAllQueues(socket.id);
    socket.currentMode = mode;
    socket.ignoredPartners = new Set(ignored);
    tryMatch(socket);
  });

  socket.on('signal', data => {
    if (limited(socket, 'signal', 45, 10000, 15000)) {
      socket.emit('rate_limited', { message: 'Слишком много сообщений. Подожди немного.' });
      return;
    }
    if (!data || typeof data.room !== 'string' || rooms.get(socket.id) !== data.room || !socket.rooms.has(data.room) || !data.signal || typeof data.signal !== 'object') return;
    const signal = data.signal;
    if (typeof signal.chatText === 'string') {
      const text = signal.chatText.trim();
      if (!text || text.length > MAX_TEXT || limited(socket, 'text', 15, 10000, 15000)) return;
      socket.to(data.room).emit('signal', { signal: { chatText: text }, sender: socket.id });
    } else if (typeof signal.typing === 'boolean') {
      if (limited(socket, 'typing', 8, 5000, 5000)) return;
      socket.to(data.room).emit('signal', { signal: { typing: signal.typing }, sender: socket.id });
    } else if (signal.media === 'photo' && validPhoto(signal.dataUrl)) {
      if (limited(socket, 'media', 4, 60000, 30000)) return;
      socket.to(data.room).emit('signal', { signal: { media: 'photo', dataUrl: signal.dataUrl }, sender: socket.id });
    } else if (signal.media === 'voice' && validVoice(signal.dataUrl)) {
      if (limited(socket, 'media', 4, 60000, 30000)) return;
      socket.to(data.room).emit('signal', { signal: { media: 'voice', dataUrl: signal.dataUrl }, sender: socket.id });
    }
  });

  socket.on('report_user', data => {
    if (limited(socket, 'report', 3, 60000, 60000)) return socket.emit('report_result', { ok: false, message: 'Слишком много жалоб. Попробуй позже.' });
    const room = rooms.get(socket.id);
    if (!room || !data || data.room !== room) return socket.emit('report_result', { ok: false, message: 'Нет активного собеседника для жалобы.' });
    const reason = ['spam', 'abuse', 'sexual', 'underage', 'other'].includes(data.reason) ? data.reason : 'other';
    const partnerId = [...(io.sockets.adapter.rooms.get(room) || [])].find(id => id !== socket.id) || null;
    reports.push({ id: crypto.randomUUID(), at: new Date().toISOString(), reason, reporter: socket.id, reported: partnerId });
    if (reports.length > MAX_REPORTS) reports.shift();
    socket.emit('report_result', { ok: true, message: 'Жалоба принята в оперативную очередь. Не отправляй личные данные.' });
  });

  socket.on('leave_room', () => leaveRoom(socket));
  socket.on('disconnect', () => {
    leaveRoom(socket);
    removeFromAllQueues(socket.id);
    cleanSocketLimits(socket.id);
    updateOnlineCount();
  });
});

function tryMatch(socket) {
  const queue = searchQueues[socket.currentMode || 'general'];
  if (!queue) return;
  const index = queue.findIndex(id => id !== socket.id && !socket.ignoredPartners?.has(id));
  if (index < 0) {
    if (!queue.includes(socket.id)) queue.push(socket.id);
    socket.emit('waiting');
    return;
  }
  const partnerId = queue.splice(index, 1)[0];
  const partner = io.sockets.sockets.get(partnerId);
  if (!partner || rooms.has(partnerId)) return tryMatch(socket);
  const room = `r_${crypto.randomUUID()}`;
  socket.join(room); partner.join(room);
  rooms.set(socket.id, room); rooms.set(partnerId, room);
  socket.emit('matched', { room, partnerId, initiator: true });
  partner.emit('matched', { room, partnerId: socket.id, initiator: false });
}
function leaveRoom(socket) {
  const room = rooms.get(socket.id);
  if (room) {
    socket.to(room).emit('partner_left');
    io.in(room).socketsLeave(room);
    for (const [id, name] of rooms) if (name === room) rooms.delete(id);
  }
  removeFromAllQueues(socket.id);
}
function removeFromAllQueues(id) {
  for (const mode of Object.keys(searchQueues)) searchQueues[mode] = searchQueues[mode].filter(x => x !== id);
}
function updateOnlineCount() { io.emit('online', io.engine.clientsCount); }

server.listen(PORT, () => console.log(`VYRO chat listening on port ${PORT}`));
