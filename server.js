const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1);

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('CORS blocked'));
  },
  credentials: true
}));

app.use(bodyParser.json({ limit: '15mb' }));

const PORT = process.env.PORT || 5000;
const DATABASE_URL = process.env.FIREBASE_DATABASE_URL || 'https://comparex-cebd8-default-rtdb.asia-southeast1.firebasedatabase.app/';

const BET_LIMITS = {
  MIN_BET: 10, MAX_BET: 500,
  MAX_DAILY_BETS: 50, MAX_DAILY_LOSS: 2000, MAX_DAILY_WIN: 5000
};

const WAGER_CONFIG = { MULTIPLIER: 3 };
const HOUSE_EDGE = { COLOR_PAYOUT: 1.9, NUMBER_PAYOUT: 8.5 };
const DEPOSIT_VERIFY = { MIN_DEPOSIT: 100, MAX_DEPOSIT: 50000, UTR_REGEX: /^[A-Za-z0-9]{10,22}$/ };

const AVIATOR_CONFIG = {
  WAIT_TIME: 5000, CRASH_HOLD: 3000, TICK_MS: 100,
  MIN_BET: 10, MAX_BET: 500,
  HOUSE_EDGE: 0.10,
  GROWTH_RATE: 0.055,
  MIN_CRASH: 1.00, MAX_CRASH: 100.00, MAX_HISTORY: 20
};

const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 100, message: { success: false, message: 'बहुत ज़्यादा requests!' }, standardHeaders: true, legacyHeaders: false });
app.use('/api/', apiLimiter);

const strictLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, message: { success: false, message: 'बहुत तेज़! 1 मिनट बाद।' }, standardHeaders: true, legacyHeaders: false });
const betLimiter = rateLimit({ windowMs: 10 * 1000, max: 5, message: { success: false, message: 'धीरे! बहुत तेज़ bet।' }, standardHeaders: true, legacyHeaders: false });
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 3, message: { success: false, message: 'बहुत ज़्यादा accounts!' }, standardHeaders: true, legacyHeaders: false });
const depositLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, message: { success: false, message: 'बहुत ज़्यादा deposits!' }, standardHeaders: true, legacyHeaders: false });

const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCK_TIME = 15 * 60 * 1000;

function checkLoginAttempts(mobile) {
  const attempts = loginAttempts.get(String(mobile || '')) || { count: 0, until: 0 };
  if (attempts.count >= MAX_LOGIN_ATTEMPTS && Date.now() < attempts.until) return { blocked: true, waitMin: Math.ceil((attempts.until - Date.now()) / 60000) };
  return { blocked: false };
}
function recordFailedLogin(mobile) {
  const key = String(mobile || '');
  const attempts = loginAttempts.get(key) || { count: 0, until: 0 };
  attempts.count++;
  if (attempts.count >= MAX_LOGIN_ATTEMPTS) { attempts.until = Date.now() + LOGIN_LOCK_TIME; attempts.count = 0; }
  loginAttempts.set(key, attempts);
}
function resetLoginAttempts(mobile) { loginAttempts.delete(String(mobile || '')); }

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of loginAttempts.entries()) { if (val.until && now > val.until + 60000) loginAttempts.delete(key); }
}, 30 * 60 * 1000);

function sanitize(input, maxLength = 100) {
  if (typeof input !== 'string') return '';
  return input.trim().slice(0, maxLength).replace(/[<>]/g, '');
}
function isValidMobile(m) { return /^\d{10}$/.test(String(m || '')); }

function initFirebase() {
  if (admin.apps.length) return admin.app();
  let credential;
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    let raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
    try { raw = raw.replace(/\\n/g, '\n'); } catch (_) {}
    credential = admin.credential.cert(JSON.parse(raw));
  } else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
    credential = admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
    });
  } else throw new Error('Firebase credentials not configured.');
  return admin.initializeApp({ credential, databaseURL: DATABASE_URL });
}

let firebaseApp, firebaseDb;
try { firebaseApp = initFirebase(); firebaseDb = admin.database(firebaseApp); } catch (e) { console.error('Firebase init failed:', e.message); }

function requireDb() { if (!firebaseDb) throw new Error('Firebase not configured.'); return firebaseDb; }
const usersRef = () => requireDb().ref('users');
const depositsRef = () => requireDb().ref('deposits');
const withdrawalsRef = () => requireDb().ref('withdrawals');
const metaRef = () => requireDb().ref('meta');

function cleanUser(u) {
  if (!u) return null;
  return { id: Number(u.id), name: u.name, mobile: String(u.mobile), balance: Number(u.balance || 0), is_blocked: !!u.is_blocked, created_at: u.created_at || new Date().toISOString(), password_hash: u.password_hash };
}
function publicUser(u) { return { name: u.name, mobile: u.mobile, balance: Number(u.balance || 0), isBlocked: !!u.is_blocked }; }
async function getUser(mobile) { const snap = await usersRef().child(String(mobile)).once('value'); return snap.exists() ? cleanUser(snap.val()) : null; }
async function nextId(type) { const ref = metaRef().child(`next_${type}_id`); const result = await ref.transaction(v => (Number(v) || 0) + 1); return Number(result.snapshot.val()); }

async function initDb() {
  const meta = await metaRef().once('value');
  if (!meta.exists()) await metaRef().set({ next_deposit_id: 0, next_withdrawal_id: 0 });
  const demo = await getUser('9876543210');
  if (!demo) {
    const hash = await bcrypt.hash('123', 10);
    await usersRef().child('9876543210').set({ id: 1, name: 'Player 1', mobile: '9876543210', password_hash: hash, balance: 1000, is_blocked: false, created_at: new Date().toISOString(), wager_required: 0, wager_completed: 0, is_vip: true });
  }
}

function adminAuth(req, res, next) {
  const key = process.env.ADMIN_KEY;
  if (!key) return res.status(500).json({ success: false, message: 'ADMIN_KEY not configured.' });
  const provided = String(req.headers['x-admin-key'] || '');
  try {
    const a = Buffer.from(provided), b = Buffer.from(key);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ success: false, message: 'Unauthorized' });
  } catch (e) { return res.status(401).json({ success: false, message: 'Unauthorized' }); }
  next();
}

async function sendTelegramMessage(text, replyMarkup = null) {
  const token = process.env.TELEGRAM_BOT_TOKEN, chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return false;
  try {
    const body = { chat_id: chatId, text, parse_mode: 'HTML' };
    if (replyMarkup) body.reply_markup = replyMarkup;
    const r = await fetch(`https://api.telegram.org/bot${encodeURIComponent(token)}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return r.ok;
  } catch (e) { return false; }
}

async function sendTelegramPhoto(base64DataUrl, caption, replyMarkup = null) {
  const token = process.env.TELEGRAM_BOT_TOKEN, chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return false;
  try {
    const matches = base64DataUrl.match(/^data:(image\/\w+);base64,(.+)$/);
    if (!matches) return sendTelegramMessage(caption, replyMarkup);
    const buffer = Buffer.from(matches[2], 'base64');
    const boundary = '----FormBoundary' + Math.random().toString(36).slice(2);
    const parts = [];
    parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n${chatId}\r\n`);
    parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="caption"\r\n\r\n${caption}\r\n`);
    parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="parse_mode"\r\n\r\nHTML\r\n`);
    if (replyMarkup) parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="reply_markup"\r\n\r\n${JSON.stringify(replyMarkup)}\r\n`);
    const header = Buffer.from(parts.join(''));
    const fileHeader = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="photo"; filename="proof.jpg"\r\nContent-Type: ${matches[1]}\r\n\r\n`);
    const footer = Buffer.from(`\r\n--${boundary}--\r\n`);
    const r = await fetch(`https://api.telegram.org/bot${encodeURIComponent(token)}/sendPhoto`, { method: 'POST', headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` }, body: Buffer.concat([header, fileHeader, buffer, footer]) });
    return r.ok;
  } catch (e) { return sendTelegramMessage(caption, replyMarkup); }
}

function telegramAdminId() { return String(process.env.TELEGRAM_ADMIN_ID || '6930997805').trim(); }

async function telegramApi(method, payload = {}) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  if (!token) return null;
  try {
    const r = await fetch(`https://api.telegram.org/bot${encodeURIComponent(token)}/${method}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    return await r.json();
  } catch (e) { return null; }
}

async function editTelegramMessage(chatId, messageId, text) { return telegramApi('editMessageText', { chat_id: chatId, message_id: messageId, text, parse_mode: 'HTML' }); }

let telegramOffset = 0, telegramPolling = false;

async function handleTelegramUpdate(update) {
  const callback = update.callback_query;
  if (!callback) return;
  if (String(callback.from?.id || '') !== telegramAdminId()) { await telegramApi('answerCallbackQuery', { callback_query_id: callback.id, text: 'Unauthorized.', show_alert: true }); return; }
  const match = String(callback.data || '').match(/^deposit:(approve|reject):(\d+)$/);
  if (!match) return;
  const action = match[1], depositId = Number(match[2]);
  try {
    const ref = depositsRef().child(String(depositId));
    const snap = await ref.once('value');
    if (!snap.exists()) { await telegramApi('answerCallbackQuery', { callback_query_id: callback.id, text: 'Not found.', show_alert: true }); return; }
    const dep = snap.val();
    if (dep.status !== 'PENDING') { await telegramApi('answerCallbackQuery', { callback_query_id: callback.id, text: `Already ${dep.status}.`, show_alert: true }); return; }
    if (action === 'approve') {
      const userRef = usersRef().child(String(dep.mobile));
      const userSnap = await userRef.once('value');
      if (!userSnap.exists()) throw new Error('User not found');
      const wagerToAdd = Number(dep.amount) * WAGER_CONFIG.MULTIPLIER;
      await userRef.transaction(u => {
        if (!u) return u;
        return { ...u, balance: Number(u.balance || 0) + Number(dep.amount || 0), wager_required: Number(u.wager_required || 0) + wagerToAdd, wager_completed: Number(u.wager_completed || 0), is_vip: true, vip_since: u.vip_since || new Date().toISOString() };
      });
      if (dep.utr_number) await requireDb().ref('utr_registry').child(String(dep.utr_number).trim().toLowerCase()).set({ depositId: dep.id, mobile: dep.mobile, used_at: new Date().toISOString() });
      await ref.update({ status: 'APPROVED', processed_at: new Date().toISOString() });
    } else await ref.update({ status: 'REJECTED', processed_at: new Date().toISOString() });
    const statusText = action === 'approve' ? '✅ APPROVED' : '❌ REJECTED';
    const text = `<b>📥 Deposit #${depositId}</b>\n\n<b>User:</b> ${dep.name}\n<b>Mobile:</b> ${dep.mobile}\n<b>Amount:</b> ₹${Number(dep.amount).toFixed(2)}\n<b>UTR:</b> <code>${dep.utr_number}</code>\n<b>Status:</b> ${statusText}`;
    if (callback.message) await editTelegramMessage(callback.message.chat.id, callback.message.message_id, text);
    await telegramApi('answerCallbackQuery', { callback_query_id: callback.id, text: action === 'approve' ? 'Approved.' : 'Rejected.' });
  } catch (e) { await telegramApi('answerCallbackQuery', { callback_query_id: callback.id, text: 'Action failed.', show_alert: true }); }
}

async function telegramPollLoop() {
  if (telegramPolling || !process.env.TELEGRAM_BOT_TOKEN || !firebaseDb) return;
  telegramPolling = true;
  while (true) {
    try {
      const data = await telegramApi('getUpdates', { offset: telegramOffset, timeout: 25, allowed_updates: ['callback_query'] });
      if (data?.ok && Array.isArray(data.result)) { for (const u of data.result) { telegramOffset = Math.max(telegramOffset, u.update_id + 1); await handleTelegramUpdate(u); } }
    } catch (e) {}
    await new Promise(r => setTimeout(r, 500));
  }
}

async function getUserTodayStats(mobile) {
  const today = new Date().toISOString().slice(0, 10);
  const snap = await requireDb().ref('bet_history').child(String(mobile)).child(today).once('value');
  return snap.exists() ? snap.val() : { bets: 0, loss: 0, win: 0 };
}
async function updateUserTodayStats(mobile, delta) {
  const today = new Date().toISOString().slice(0, 10);
  const ref = requireDb().ref('bet_history').child(String(mobile)).child(today);
  await ref.transaction(curr => {
    const c = curr || { bets: 0, loss: 0, win: 0 };
    return { bets: (c.bets || 0) + (delta.bets || 0), loss: (c.loss || 0) + (delta.loss || 0), win: (c.win || 0) + (delta.win || 0) };
  });
}

let currentRound = { roundId: Date.now(), timeLeft: 30, status: 'OPEN' };
let currentBets = [];
let winningColor = 'GREEN', winningNumber = 5;

async function calculateAndPayResults() {
  const colors = ['GREEN', 'RED', 'VIOLET'];
  winningColor = colors[Math.floor(Math.random() * colors.length)];
  winningNumber = Math.floor(Math.random() * 10);
  await Promise.all(currentBets.map(async bet => {
    try {
      const userRef = usersRef().child(String(bet.userId));
      const snap = await userRef.once('value');
      if (!snap.exists()) return;
      let winAmount = 0;
      if (bet.betType === 'COLOR' && bet.betValue === winningColor) winAmount = bet.amount * HOUSE_EDGE.COLOR_PAYOUT;
      if (bet.betType === 'NUMBER' && parseInt(bet.betValue) === winningNumber) winAmount = bet.amount * HOUSE_EDGE.NUMBER_PAYOUT;
      winAmount = Math.floor(winAmount);
      if (winAmount) { await userRef.transaction(u => u ? { ...u, balance: Number(u.balance || 0) + winAmount } : u); await updateUserTodayStats(bet.userId, { bets: 0, loss: 0, win: winAmount }); }
      else await updateUserTodayStats(bet.userId, { bets: 0, loss: bet.amount, win: 0 });
    } catch (e) {}
  }));
}

setInterval(() => {
  currentRound.timeLeft--;
  if (currentRound.timeLeft <= 3 && currentRound.status === 'OPEN') currentRound.status = 'CLOSED';
  if (currentRound.timeLeft <= 0) { calculateAndPayResults(); currentRound = { roundId: Date.now(), timeLeft: 30, status: 'OPEN' }; currentBets = []; }
}, 1000);

let aviator = { status: 'WAITING', roundId: 1, multiplier: 1.00, crashPoint: 1.00, waitingEndsAt: Date.now() + AVIATOR_CONFIG.WAIT_TIME, flyingStartedAt: null, players: [], history: [], serverSeed: null, clientSeed: null };

function generateAviatorCrashPoint() {
  const serverSeed = crypto.randomBytes(16).toString('hex');
  const clientSeed = 'cx-' + Date.now();
  const hash = crypto.createHmac('sha256', serverSeed).update(`${clientSeed}:${aviator.roundId}`).digest('hex');
  const hashInt = parseInt(hash.slice(0, 13), 16);
  const randomValue = hashInt / Math.pow(2, 52);
  if (randomValue < AVIATOR_CONFIG.HOUSE_EDGE) return { crashPoint: 1.00, serverSeed, clientSeed };
  const u = randomValue - AVIATOR_CONFIG.HOUSE_EDGE;
  let crashPoint = (1 - AVIATOR_CONFIG.HOUSE_EDGE) / (1 - u);
  crashPoint = Math.floor(crashPoint * 100) / 100;
  if (crashPoint < AVIATOR_CONFIG.MIN_CRASH) crashPoint = AVIATOR_CONFIG.MIN_CRASH;
  if (crashPoint > AVIATOR_CONFIG.MAX_CRASH) crashPoint = AVIATOR_CONFIG.MAX_CRASH;
  return { crashPoint, serverSeed, clientSeed };
}

setInterval(() => {
  const now = Date.now();
  if (aviator.status === 'WAITING') {
    if (now >= aviator.waitingEndsAt) {
      const { crashPoint, serverSeed, clientSeed } = generateAviatorCrashPoint();
      aviator.crashPoint = crashPoint; aviator.serverSeed = serverSeed; aviator.clientSeed = clientSeed;
      aviator.status = 'FLYING'; aviator.flyingStartedAt = now; aviator.multiplier = 1.00;
    }
  } else if (aviator.status === 'FLYING') {
    const elapsed = (now - aviator.flyingStartedAt) / 1000;
    let m = Math.round(Math.pow(Math.E, AVIATOR_CONFIG.GROWTH_RATE * elapsed) * 100) / 100;
    if (m >= aviator.crashPoint) {
      aviator.multiplier = aviator.crashPoint; aviator.status = 'CRASHED';
      aviator.history.unshift({ roundId: aviator.roundId, crashPoint: aviator.crashPoint });
      if (aviator.history.length > AVIATOR_CONFIG.MAX_HISTORY) aviator.history.pop();
      aviator.players.forEach(p => { if (!p.cashedOut) updateUserTodayStats(p.userId, { bets: 0, loss: p.amount, win: 0 }).catch(() => {}); });
      aviator.waitingEndsAt = now + AVIATOR_CONFIG.CRASH_HOLD;
    } else aviator.multiplier = m;
  } else if (aviator.status === 'CRASHED') {
    if (now >= aviator.waitingEndsAt) {
      aviator.status = 'WAITING'; aviator.roundId++; aviator.multiplier = 1.00; aviator.crashPoint = 1.00; aviator.players = [];
      aviator.waitingEndsAt = now + AVIATOR_CONFIG.WAIT_TIME;
    }
  }
}, AVIATOR_CONFIG.TICK_MS);

app.post('/api/register', registerLimiter, async (req, res) => {
  try {
    const name = sanitize(req.body.name, 50), mobile = sanitize(req.body.mobile, 10), password = String(req.body.password || '');
    if (!name || !mobile || !password) return res.status(400).json({ success: false, message: 'सभी fields ज़रूरी!' });
    if (!isValidMobile(mobile)) return res.status(400).json({ success: false, message: '10 digit mobile!' });
    if (password.length < 4) return res.status(400).json({ success: false, message: 'Password कम से कम 4!' });
    if (await getUser(mobile)) return res.status(400).json({ success: false, message: 'Mobile registered!' });
    const hash = await bcrypt.hash(password, 10);
    const snap = await usersRef().once('value');
    let maxId = 0; snap.forEach(c => { maxId = Math.max(maxId, Number(c.val()?.id) || 0); });
    const user = { id: maxId + 1, name, mobile, password_hash: hash, balance: 1000, is_blocked: false, created_at: new Date().toISOString(), wager_required: 0, wager_completed: 0, is_vip: false };
    await usersRef().child(mobile).set(user);
    res.json({ success: true, message: 'Registration Successful! ₹1000 Bonus मिला।', user: publicUser(user) });
  } catch (e) { res.status(500).json({ success: false, message: 'Registration failed!' }); }
});

app.post('/api/login', strictLimiter, async (req, res) => {
  try {
    const mobile = sanitize(req.body.mobile, 10), password = String(req.body.password || '');
    if (!mobile || !password) return res.status(400).json({ success: false, message: 'Mobile और Password ज़रूरी!' });
    const check = checkLoginAttempts(mobile);
    if (check.blocked) return res.status(429).json({ success: false, message: `बहुत बार गलत password! ${check.waitMin} मिनट बाद।` });
    const user = await getUser(mobile);
    const isValid = user && await bcrypt.compare(password, user.password_hash);
    if (!isValid) { recordFailedLogin(mobile); return res.status(400).json({ success: false, message: 'Invalid Mobile/Password!' }); }
    if (user.is_blocked) return res.status(403).json({ success: false, message: 'Account blocked!' });
    resetLoginAttempts(mobile);
    res.json({ success: true, message: 'Login Successful!', user: publicUser(user) });
  } catch (e) { res.status(500).json({ success: false, message: 'Login failed!' }); }
});

app.get('/api/game-status', (req, res) => {
  res.json({ roundId: currentRound.roundId, timeLeft: currentRound.timeLeft, status: currentRound.status, canBet: currentRound.status === 'OPEN', lastWinningColor: winningColor, lastWinningNumber: winningNumber });
});

app.get('/api/user/:userId', async (req, res) => {
  try {
    const mobile = sanitize(req.params.userId, 10);
    if (!isValidMobile(mobile)) return res.status(400).json({ success: false, message: 'Invalid' });
    const user = await getUser(mobile);
    if (!user) return res.status(404).json({ success: false, message: 'Not found' });
    const snap = await usersRef().child(mobile).once('value');
    const u = snap.val() || {};
    const required = Number(u.wager_required || 0), completed = Number(u.wager_completed || 0);
    const pending = Math.max(0, required - completed);
    const isVip = !!u.is_vip;
    res.json({ success: true, balance: Number(user.balance), userId: user.mobile, name: user.name, wagerRequired: required, wagerCompleted: completed, wagerPending: pending, canWithdraw: pending <= 0, isVip });
  } catch (e) { res.status(500).json({ success: false, message: 'Server error' }); }
});

app.post('/api/place-bet', betLimiter, async (req, res) => {
  try {
    const mobile = sanitize(req.body.userId, 10);
    const betType = String(req.body.betType || '').toUpperCase();
    const betValue = sanitize(req.body.betValue, 20);
    const value = Number(req.body.amount);
    if (!isValidMobile(mobile)) return res.status(400).json({ success: false, message: 'Invalid user' });
    if (!['COLOR', 'NUMBER'].includes(betType)) return res.status(400).json({ success: false, message: 'Invalid bet type' });
    const bettorSnap = await usersRef().child(mobile).once('value');
    const bettor = bettorSnap.val();
    if (!bettor || !bettor.is_vip) return res.status(403).json({ success: false, message: '🔒 VIP ज़रूरी! पहले Add Money करें।', requiresVip: true });
    if (currentRound.status !== 'OPEN') return res.status(400).json({ success: false, message: 'Betting बंद है!' });
    if (!Number.isFinite(value) || value < BET_LIMITS.MIN_BET) return res.status(400).json({ success: false, message: `Minimum ₹${BET_LIMITS.MIN_BET}!` });
    if (value > BET_LIMITS.MAX_BET) return res.status(400).json({ success: false, message: `Maximum ₹${BET_LIMITS.MAX_BET}!` });
    const stats = await getUserTodayStats(mobile);
    if (stats.bets >= BET_LIMITS.MAX_DAILY_BETS) return res.status(400).json({ success: false, message: 'Daily bet limit!' });
    if (stats.loss >= BET_LIMITS.MAX_DAILY_LOSS) return res.status(400).json({ success: false, message: 'Daily loss limit!' });
    if (stats.win >= BET_LIMITS.MAX_DAILY_WIN) return res.status(400).json({ success: false, message: 'Daily win limit!' });
    const ref = usersRef().child(mobile);
    let remaining = null;
    const tx = await ref.transaction(u => {
      if (!u || u.is_blocked || Number(u.balance || 0) < value) return;
      remaining = Number(u.balance) - value;
      const cw = Number(u.wager_completed || 0), rq = Number(u.wager_required || 0);
      return { ...u, balance: remaining, wager_completed: Math.min(cw + value, rq) };
    });
    if (!tx.committed) return res.status(400).json({ success: false, message: 'Insufficient Balance!' });
    currentBets.push({ userId: mobile, betType, betValue, amount: value });
    await updateUserTodayStats(mobile, { bets: 1, loss: 0, win: 0 });
    res.json({ success: true, message: 'Bet Placed!', remainingBalance: remaining });
  } catch (e) { res.status(500).json({ success: false, message: 'Bet failed!' }); }
});

async function listDeposits() {
  const snap = await depositsRef().once('value');
  const a = [];
  snap.forEach(c => { const d = c.val(); if (d) { delete d.screenshot; a.push(d); } });
  return a.sort((x, y) => Number(y.id) - Number(x.id));
}

app.post('/api/add-money', depositLimiter, async (req, res) => {
  try {
    const mobile = sanitize(req.body.userId, 10);
    const value = Number(req.body.amount);
    const cleanUTR = sanitize(req.body.utrNumber, 30);
    const screenshot = req.body.screenshot;
    if (!isValidMobile(mobile)) return res.status(400).json({ success: false, message: 'Invalid user' });
    const user = await getUser(mobile);
    if (!user) return res.status(404).json({ success: false, message: 'User not found!' });
    if (user.is_blocked) return res.status(403).json({ success: false, message: 'Account blocked!' });
    if (!Number.isFinite(value) || value < DEPOSIT_VERIFY.MIN_DEPOSIT) return res.status(400).json({ success: false, message: `Minimum ₹${DEPOSIT_VERIFY.MIN_DEPOSIT}!` });
    if (value > DEPOSIT_VERIFY.MAX_DEPOSIT) return res.status(400).json({ success: false, message: `Maximum ₹${DEPOSIT_VERIFY.MAX_DEPOSIT}!` });
    if (!cleanUTR) return res.status(400).json({ success: false, message: 'UTR ज़रूरी!' });
    if (!DEPOSIT_VERIFY.UTR_REGEX.test(cleanUTR)) return res.status(400).json({ success: false, message: 'UTR invalid!' });
    if (!screenshot || !screenshot.startsWith('data:image')) return res.status(400).json({ success: false, message: '📸 Screenshot ज़रूरी!' });
    if (screenshot.length > 7 * 1024 * 1024) return res.status(400).json({ success: false, message: 'Screenshot बहुत बड़ा!' });
    const usedSnap = await requireDb().ref('utr_registry').child(cleanUTR.toLowerCase()).once('value');
    if (usedSnap.exists()) return res.status(400).json({ success: false, message: '⚠️ UTR पहले use हुआ!' });
    const allDeps = await listDeposits();
    const dup = allDeps.find(d => d.status !== 'REJECTED' && String(d.utr_number || '').toLowerCase() === cleanUTR.toLowerCase());
    if (dup) return res.status(400).json({ success: false, message: '⚠️ UTR pending में है!' });
    const id = await nextId('deposit');
    await depositsRef().child(String(id)).set({ id, user_id: user.id, mobile: user.mobile, name: user.name, amount: value, utr_number: cleanUTR, screenshot, status: 'PENDING', created_at: new Date().toISOString() });
    const caption = `<b>💰 New Deposit Request</b>\n\n<b>Request ID:</b> #${id}\n<b>User:</b> ${String(user.name).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]))}\n<b>Mobile:</b> ${user.mobile}\n<b>Amount:</b> ₹${value.toFixed(2)}\n<b>UTR:</b> <code>${cleanUTR}</code>\n<b>Time:</b> ${new Date().toLocaleString('en-IN')}\n\n📸 <b>Verify करके decide करें:</b>`;
    const keyboard = { inline_keyboard: [[{ text: '✅ APPROVE', callback_data: `deposit:approve:${id}` }, { text: '❌ REJECT', callback_data: `deposit:reject:${id}` }]] };
    await sendTelegramPhoto(screenshot, caption, keyboard);
    res.json({ success: true, message: `₹${value} deposit submit! Admin verify करेगा।`, newBalance: Number(user.balance), status: 'PENDING', depositId: id });
  } catch (e) { res.status(500).json({ success: false, message: 'Deposit failed!' }); }
});

async function listWithdrawals() {
  const snap = await withdrawalsRef().once('value');
  const a = [];
  snap.forEach(c => a.push(c.val()));
  return a.sort((x, y) => Number(y.id) - Number(x.id));
}

app.post('/api/withdraw', strictLimiter, async (req, res) => {
  try {
    const mobile = sanitize(req.body.userId, 10);
    const value = Number(req.body.amount);
    const upiId = sanitize(req.body.upiId, 60);
    const accountDetails = sanitize(req.body.accountDetails, 200);
    if (!isValidMobile(mobile)) return res.status(400).json({ success: false, message: 'Invalid user' });
    if (!Number.isFinite(value) || value < 110) return res.status(400).json({ success: false, message: 'Minimum ₹110!' });
    if (!upiId && !accountDetails) return res.status(400).json({ success: false, message: 'UPI ID ज़रूरी!' });
    const userSnap = await usersRef().child(mobile).once('value');
    if (!userSnap.exists()) return res.status(404).json({ success: false, message: 'Not found' });
    const u = userSnap.val();
    if (!u.is_vip) return res.status(403).json({ success: false, message: '🔒 VIP ज़रूरी! पहले deposit करें।' });
    const required = Number(u.wager_required || 0), completed = Number(u.wager_completed || 0);
    const pending = Math.max(0, required - completed);
    if (pending > 0) return res.status(400).json({ success: false, message: `⚠️ ₹${pending.toFixed(0)} का और bet लगाएँ!`, wagerRequired: required, wagerCompleted: completed, wagerPending: pending });
    const userRef = usersRef().child(mobile);
    let remaining = null;
    const tx = await userRef.transaction(u => { if (!u || Number(u.balance || 0) < value) return; remaining = Number(u.balance) - value; return { ...u, balance: remaining }; });
    if (!tx.committed) return res.status(400).json({ success: false, message: 'Insufficient Balance!' });
    const id = await nextId('withdrawal');
    await withdrawalsRef().child(String(id)).set({ id, user_id: tx.snapshot.val().id, mobile, name: tx.snapshot.val().name, amount: value, upi_id: upiId || null, account_details: accountDetails || null, status: 'PENDING', created_at: new Date().toISOString() });
    res.json({ success: true, message: `₹${value} withdrawal submit!`, newBalance: remaining });
  } catch (e) { res.status(500).json({ success: false, message: 'Withdrawal failed!' }); }
});

app.get('/api/aviator/state', (req, res) => {
  const now = Date.now();
  let timeLeft = 0;
  if (aviator.status === 'WAITING' || aviator.status === 'CRASHED') timeLeft = Math.max(0, Math.ceil((aviator.waitingEndsAt - now) / 1000));
  res.json({ success: true, status: aviator.status, roundId: aviator.roundId, multiplier: aviator.multiplier, crashPoint: aviator.status === 'CRASHED' ? aviator.crashPoint : null, timeLeft, history: aviator.history, playersCount: aviator.players.length, config: { MIN_BET: AVIATOR_CONFIG.MIN_BET, MAX_BET: AVIATOR_CONFIG.MAX_BET } });
});

app.post('/api/aviator/bet', betLimiter, async (req, res) => {
  try {
    const mobile = sanitize(req.body.userId, 10);
    const value = Number(req.body.amount);
    if (!isValidMobile(mobile)) return res.status(400).json({ success: false, message: 'Invalid user' });
    const aviatorSnap = await usersRef().child(mobile).once('value');
    const aviatorUser = aviatorSnap.val();
    if (!aviatorUser || !aviatorUser.is_vip) return res.status(403).json({ success: false, message: '🔒 VIP ज़रूरी! पहले Add Money करें।', requiresVip: true });
    if (aviator.status !== 'WAITING') return res.status(400).json({ success: false, message: 'Betting बंद!' });
    if (!Number.isFinite(value) || value < AVIATOR_CONFIG.MIN_BET || value > AVIATOR_CONFIG.MAX_BET) return res.status(400).json({ success: false, message: `Bet ₹${AVIATOR_CONFIG.MIN_BET}-₹${AVIATOR_CONFIG.MAX_BET}!` });
    const stats = await getUserTodayStats(mobile);
    if (stats.loss >= BET_LIMITS.MAX_DAILY_LOSS) return res.status(400).json({ success: false, message: 'Daily loss limit!' });
    if (aviator.players.find(p => p.userId === mobile)) return res.status(400).json({ success: false, message: 'इस round में पहले bet!' });
    const ref = usersRef().child(mobile);
    let remaining = null;
    const tx = await ref.transaction(u => { if (!u || u.is_blocked || Number(u.balance || 0) < value) return; remaining = Number(u.balance) - value; const cw = Number(u.wager_completed || 0), rq = Number(u.wager_required || 0); return { ...u, balance: remaining, wager_completed: Math.min(cw + value, rq) }; });
    if (!tx.committed) return res.status(400).json({ success: false, message: 'Insufficient Balance!' });
    aviator.players.push({ userId: mobile, amount: value, cashedOut: false, cashoutMultiplier: null });
    await updateUserTodayStats(mobile, { bets: 1, loss: 0, win: 0 });
    res.json({ success: true, message: 'Bet placed!', newBalance: remaining });
  } catch (e) { res.status(500).json({ success: false, message: 'Bet failed!' }); }
});

app.post('/api/aviator/cashout', betLimiter, async (req, res) => {
  try {
    const mobile = sanitize(req.body.userId, 10);
    if (!isValidMobile(mobile)) return res.status(400).json({ success: false, message: 'Invalid user' });
    if (aviator.status !== 'FLYING') return res.status(400).json({ success: false, message: 'Game active नहीं!' });
    const player = aviator.players.find(p => p.userId === mobile && !p.cashedOut);
    if (!player) return res.status(400).json({ success: false, message: 'Bet नहीं लगाई!' });
    const multiplier = aviator.multiplier;
    const winAmount = Math.floor(player.amount * multiplier);
    player.cashedOut = true; player.cashoutMultiplier = multiplier;
    await usersRef().child(mobile).transaction(u => u ? { ...u, balance: Number(u.balance || 0) + winAmount } : u);
    await updateUserTodayStats(mobile, { bets: 0, loss: 0, win: winAmount });
    res.json({ success: true, multiplier, winAmount, message: `${multiplier.toFixed(2)}x पर cashout!` });
  } catch (e) { res.status(500).json({ success: false, message: 'Cashout failed!' }); }
});

app.get('/api/user/:userId/deposits', async (req, res) => {
  try {
    const mobile = sanitize(req.params.userId, 10);
    if (!isValidMobile(mobile)) return res.status(400).json({ success: false, message: 'Invalid' });
    const user = await getUser(mobile);
    if (!user) return res.status(404).json({ success: false, message: 'Not found' });
    const a = (await listDeposits()).filter(x => String(x.mobile) === String(user.mobile)).slice(0, 100).map(x => ({ id: x.id, amount: Number(x.amount), utr_number: x.utr_number, status: x.status, created_at: x.created_at }));
    res.json({ success: true, deposits: a });
  } catch (e) { res.status(500).json({ success: false, message: 'Failed' }); }
});

app.get('/api/user/:userId/withdrawals', async (req, res) => {
  try {
    const mobile = sanitize(req.params.userId, 10);
    if (!isValidMobile(mobile)) return res.status(400).json({ success: false, message: 'Invalid' });
    const user = await getUser(mobile);
    if (!user) return res.status(404).json({ success: false, message: 'Not found' });
    const a = (await listWithdrawals()).filter(x => String(x.mobile) === String(user.mobile)).slice(0, 100).map(x => ({ id: x.id, amount: Number(x.amount), upi_id: x.upi_id, status: x.status, created_at: x.created_at }));
    res.json({ success: true, withdrawals: a });
  } catch (e) { res.status(500).json({ success: false, message: 'Failed' }); }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const snap = await usersRef().once('value');
    const users = [];
    snap.forEach(c => { const u = cleanUser(c.val()); if (u) users.push({ ...u, password_hash: undefined, is_vip: !!c.val().is_vip }); });
    users.sort((a, b) => b.id - a.id);
    res.json({ success: true, users });
  } catch (e) { res.status(500).json({ success: false, message: 'Failed' }); }
});

app.post('/api/admin/users/:id/block', adminAuth, async (req, res) => {
  try { const snap = await usersRef().once('value'); let key = null; snap.forEach(c => { if (Number(c.val()?.id) === Number(req.params.id)) key = c.key; }); if (!key) return res.status(404).json({ success: false, message: 'Not found' }); await usersRef().child(key).update({ is_blocked: true }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false, message: 'Failed' }); }
});

app.post('/api/admin/users/:id/unblock', adminAuth, async (req, res) => {
  try { const snap = await usersRef().once('value'); let key = null; snap.forEach(c => { if (Number(c.val()?.id) === Number(req.params.id)) key = c.key; }); if (!key) return res.status(404).json({ success: false, message: 'Not found' }); await usersRef().child(key).update({ is_blocked: false }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false, message: 'Failed' }); }
});

app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
  try { const snap = await usersRef().once('value'); let key = null; snap.forEach(c => { if (Number(c.val()?.id) === Number(req.params.id)) key = c.key; }); if (!key) return res.status(404).json({ success: false, message: 'Not found' }); await usersRef().child(key).remove(); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false, message: 'Failed' }); }
});

app.get('/api/admin/deposits', adminAuth, async (req, res) => { try { res.json({ success: true, deposits: await listDeposits() }); } catch (e) { res.status(500).json({ success: false, message: 'Failed' }); } });

app.post('/api/admin/deposits/:id/approve', adminAuth, async (req, res) => {
  try {
    const ref = depositsRef().child(String(req.params.id));
    const snap = await ref.once('value');
    if (!snap.exists() || snap.val().status !== 'PENDING') return res.json({ success: false, message: 'Already processed' });
    const d = snap.val();
    if (d.utr_number) await requireDb().ref('utr_registry').child(String(d.utr_number).trim().toLowerCase()).set({ depositId: d.id, mobile: d.mobile, used_at: new Date().toISOString() });
    const uref = usersRef().child(String(d.mobile));
    const wagerToAdd = Number(d.amount) * WAGER_CONFIG.MULTIPLIER;
    const tx = await uref.transaction(u => { if (!u) return u; return { ...u, balance: Number(u.balance || 0) + Number(d.amount || 0), wager_required: Number(u.wager_required || 0) + wagerToAdd, wager_completed: Number(u.wager_completed || 0), is_vip: true, vip_since: u.vip_since || new Date().toISOString() }; });
    if (!tx.committed) return res.status(404).json({ success: false, message: 'User not found' });
    await ref.update({ status: 'APPROVED', processed_at: new Date().toISOString() });
    await sendTelegramMessage(`<b>✅ Deposit Approved</b>\n\n<b>ID:</b> #${d.id}\n<b>User:</b> ${d.name}\n<b>Amount:</b> ₹${Number(d.amount).toFixed(2)}\n<b>Wager Added:</b> ₹${wagerToAdd}`);
    res.json({ success: true, message: 'Approved!' });
  } catch (e) { res.status(500).json({ success: false, message: 'Failed' }); }
});

app.post('/api/admin/deposits/:id/reject', adminAuth, async (req, res) => {
  try { const ref = depositsRef().child(String(req.params.id)); const snap = await ref.once('value'); if (!snap.exists() || snap.val().status !== 'PENDING') return res.json({ success: false, message: 'Already processed' }); await ref.update({ status: 'REJECTED', processed_at: new Date().toISOString() }); res.json({ success: true, message: 'Rejected!' }); } catch (e) { res.status(500).json({ success: false, message: 'Failed' }); }
});

app.get('/api/admin/withdrawals', adminAuth, async (req, res) => { try { res.json({ success: true, withdrawals: await listWithdrawals() }); } catch (e) { res.status(500).json({ success: false, message: 'Failed' }); } });

app.post('/api/admin/withdrawals/:id/approve', adminAuth, async (req, res) => {
  try { const ref = withdrawalsRef().child(String(req.params.id)); const snap = await ref.once('value'); if (!snap.exists() || snap.val().status !== 'PENDING') return res.json({ success: false, message: 'Already processed' }); await ref.update({ status: 'APPROVED', processed_at: new Date().toISOString() }); res.json({ success: true, message: 'Approved' }); } catch (e) { res.status(500).json({ success: false, message: 'Failed' }); }
});

app.post('/api/admin/withdrawals/:id/reject', adminAuth, async (req, res) => {
  try { const ref = withdrawalsRef().child(String(req.params.id)); const snap = await ref.once('value'); if (!snap.exists() || snap.val().status !== 'PENDING') return res.json({ success: false, message: 'Already processed' }); const w = snap.val(); const uref = usersRef().child(String(w.mobile)); const tx = await uref.transaction(u => u ? { ...u, balance: Number(u.balance || 0) + Number(w.amount || 0) } : u); if (!tx.committed) return res.status(404).json({ success: false, message: 'User not found' }); await ref.update({ status: 'REJECTED', processed_at: new Date().toISOString() }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false, message: 'Failed' }); }
});

app.get('/api/health', (req, res) => res.json({ success: true, database: !!firebaseDb, firebase: !!firebaseDb }));
app.use(express.static(__dirname));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.use((err, req, res, next) => { console.error('Server error:', err.message); res.status(500).json({ success: false, message: 'Server error' }); });

if (!firebaseDb) {
  app.listen(PORT, () => console.log(`Server on ${PORT}. Firebase pending.`));
} else {
  initDb().then(() => app.listen(PORT, () => { console.log(`Server on ${PORT}`); telegramPollLoop(); })).catch(err => { console.error('Init failed:', err); app.listen(PORT, () => console.log(`Server on ${PORT}, Firebase failed.`)); });
}
