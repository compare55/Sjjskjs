const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 5000;
const DATABASE_URL = process.env.FIREBASE_DATABASE_URL || 'https://comparex-cebd8-default-rtdb.asia-southeast1.firebasedatabase.app/';

function initFirebase() {
  if (admin.apps.length) return admin.app();
  let credential;
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    let raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
    try { raw = raw.replace(/\\n/g, '\n'); } catch (_) {}
    const serviceAccount = JSON.parse(raw);
    credential = admin.credential.cert(serviceAccount);
  } else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
    credential = admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
    });
  } else {
    throw new Error('Firebase credentials are not configured. Set FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_PROJECT_ID/FIREBASE_CLIENT_EMAIL/FIREBASE_PRIVATE_KEY.');
  }
  return admin.initializeApp({ credential, databaseURL: DATABASE_URL });
}

let firebaseApp;
let firebaseDb;
try {
  firebaseApp = initFirebase();
  firebaseDb = admin.database(firebaseApp);
} catch (e) {
  console.error('Firebase init failed:', e.message);
}

function requireDb() {
  if (!firebaseDb) throw new Error('Firebase is not configured on the server.');
  return firebaseDb;
}

const usersRef = () => requireDb().ref('users');
const depositsRef = () => requireDb().ref('deposits');
const withdrawalsRef = () => requireDb().ref('withdrawals');
const metaRef = () => requireDb().ref('meta');

function cleanUser(u) {
  if (!u) return null;
  return {
    id: Number(u.id), name: u.name, mobile: String(u.mobile),
    balance: Number(u.balance || 0), is_blocked: !!u.is_blocked,
    created_at: u.created_at || new Date().toISOString(), password_hash: u.password_hash
  };
}

function publicUser(u) {
  return { name: u.name, mobile: u.mobile, balance: Number(u.balance || 0), isBlocked: !!u.is_blocked };
}

async function getUser(mobile) {
  const snap = await usersRef().child(String(mobile)).once('value');
  return snap.exists() ? cleanUser(snap.val()) : null;
}

async function nextId(type) {
  const ref = metaRef().child(`next_${type}_id`);
  const result = await ref.transaction(v => (Number(v) || 0) + 1);
  return Number(result.snapshot.val());
}

async function initDb() {
  const db = requireDb();
  const meta = await metaRef().once('value');
  if (!meta.exists()) await metaRef().set({ next_deposit_id: 0, next_withdrawal_id: 0 });
  const demo = await getUser('9876543210');
  if (!demo) {
    const hash = await bcrypt.hash('123', 10);
    await usersRef().child('9876543210').set({
      id: 1, name: 'Player 1', mobile: '9876543210', password_hash: hash,
      balance: 1000, is_blocked: false, created_at: new Date().toISOString()
    });
  }
}

function adminAuth(req, res, next) {
  const key = process.env.ADMIN_KEY;
  if (!key) return res.status(500).json({success:false,message:'ADMIN_KEY is not configured on server.'});
  if (req.headers['x-admin-key'] !== key) return res.status(401).json({success:false,message:'Unauthorized'});
  next();
}

async function sendTelegramMessage(text, replyMarkup=null) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return false;
  try {
    const body = { chat_id: chatId, text, parse_mode: 'HTML' };
    if (replyMarkup) body.reply_markup = replyMarkup;
    const response = await fetch(`https://api.telegram.org/bot${encodeURIComponent(token)}/sendMessage`, {
      method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)
    });
    return response.ok;
  } catch (e) { console.error('Telegram notification error:', e.message); return false; }
}

function telegramAdminId() { return String(process.env.TELEGRAM_ADMIN_ID || '6930997805').trim(); }
async function telegramApi(method, payload={}) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  if (!token) return null;
  try {
    const response = await fetch(`https://api.telegram.org/bot${encodeURIComponent(token)}/${method}`, {
      method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)
    });
    return await response.json();
  } catch(e) { console.error('Telegram API request error:',e.message); return null; }
}
async function editTelegramDepositMessage(chatId,messageId,text){ return telegramApi('editMessageText',{chat_id:chatId,message_id:messageId,text,parse_mode:'HTML'}); }

let telegramOffset = 0, telegramPolling = false;
async function handleTelegramUpdate(update) {
  const callback = update.callback_query;
  if (!callback) return;
  if (String(callback.from?.id || '') !== telegramAdminId()) {
    await telegramApi('answerCallbackQuery',{callback_query_id:callback.id,text:'Unauthorized admin.',show_alert:true}); return;
  }
  const match = String(callback.data || '').match(/^deposit:(approve|reject):(\d+)$/);
  if (!match) return;
  const action = match[1], depositId = Number(match[2]);
  try {
    const ref = depositsRef().child(String(depositId));
    const snap = await ref.once('value');
    if (!snap.exists()) { await telegramApi('answerCallbackQuery',{callback_query_id:callback.id,text:'Deposit not found.',show_alert:true}); return; }
    const dep = snap.val();
    if (dep.status !== 'PENDING') { await telegramApi('answerCallbackQuery',{callback_query_id:callback.id,text:`Already ${dep.status}.`,show_alert:true}); return; }
    if (action === 'approve') {
      const userRef = usersRef().child(String(dep.mobile));
      const userSnap = await userRef.once('value');
      if (!userSnap.exists()) throw new Error('User not found');
      await userRef.transaction(u => { if (!u) return u; return {...u, balance:Number(u.balance||0)+Number(dep.amount||0)}; });
      await ref.update({status:'APPROVED', processed_at:new Date().toISOString()});
    } else {
      await ref.update({status:'REJECTED', processed_at:new Date().toISOString()});
    }
    const statusText = action === 'approve' ? '✅ APPROVED' : '❌ REJECTED';
    const text = `<b>📥 Deposit Request #${depositId}</b>\n\n<b>User:</b> ${String(dep.name).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}\n<b>Mobile:</b> ${dep.mobile}\n<b>Amount:</b> ₹${Number(dep.amount).toFixed(2)}\n<b>UTR:</b> ${String(dep.utr_number||'-')}\n<b>Status:</b> ${statusText}`;
    if (callback.message) await editTelegramDepositMessage(callback.message.chat.id,callback.message.message_id,text);
    await telegramApi('answerCallbackQuery',{callback_query_id:callback.id,text:action==='approve'?'Approved — wallet credited.':'Rejected — wallet not credited.'});
  } catch(e) { console.error('Telegram deposit action error:',e.message); await telegramApi('answerCallbackQuery',{callback_query_id:callback.id,text:'Action failed.',show_alert:true}); }
}
async function telegramPollLoop() {
  if (telegramPolling || !process.env.TELEGRAM_BOT_TOKEN || !firebaseDb) return;
  telegramPolling=true;
  while(true){
    try{const data=await telegramApi('getUpdates',{offset:telegramOffset,timeout:25,allowed_updates:['callback_query']});if(data?.ok&&Array.isArray(data.result)){for(const u of data.result){telegramOffset=Math.max(telegramOffset,u.update_id+1);await handleTelegramUpdate(u);}}}
    catch(e){console.error('Telegram polling error:',e.message)}
    await new Promise(r=>setTimeout(r,500));
  }
}

let currentRound={roundId:Date.now(),timeLeft:30,status:'OPEN'};
let currentBets=[];
let winningColor='GREEN', winningNumber=5;

async function calculateAndPayResults(){
  const colors=['GREEN','RED','VIOLET'];
  winningColor=colors[Math.floor(Math.random()*colors.length)];
  winningNumber=Math.floor(Math.random()*10);
  await Promise.all(currentBets.map(async bet=>{
    try{
      const userRef=usersRef().child(String(bet.userId));
      const snap=await userRef.once('value'); if(!snap.exists()) return;
      let winAmount=0;
      if(bet.betType==='COLOR'&&bet.betValue===winningColor) winAmount=bet.amount*2;
      if(bet.betType==='NUMBER'&&parseInt(bet.betValue)===winningNumber) winAmount=bet.amount*9;
      if(winAmount) await userRef.transaction(u=>u?{...u,balance:Number(u.balance||0)+winAmount}:u);
    }catch(e){console.error('Payout error:',e.message)}
  }));
}
setInterval(()=>{currentRound.timeLeft--;if(currentRound.timeLeft<=5&&currentRound.status==='OPEN')currentRound.status='CLOSED';if(currentRound.timeLeft<=0){calculateAndPayResults();currentRound={roundId:Date.now(),timeLeft:30,status:'OPEN'};currentBets=[];}},1000);

app.post('/api/register',async(req,res)=>{
  try{
    const {name,mobile,password}=req.body;
    if(!name||!mobile||!password)return res.status(400).json({success:false,message:'Name, mobile and password are required!'});
    const m=String(mobile); if(!/^\d{10}$/.test(m))return res.status(400).json({success:false,message:'Enter a valid 10-digit mobile number!'});
    if(await getUser(m))return res.status(400).json({success:false,message:'Mobile number already registered!'});
    const hash=await bcrypt.hash(String(password),10);
    const snap=await usersRef().once('value');
    let maxId=0;snap.forEach(c=>{maxId=Math.max(maxId,Number(c.val()?.id)||0)});
    const user={id:maxId+1,name:String(name),mobile:m,password_hash:hash,balance:1000,is_blocked:false,created_at:new Date().toISOString()};
    await usersRef().child(m).set(user);
    res.json({success:true,message:'Registration Successful! ₹1000 Bonus added.',user:publicUser(user)});
  }catch(e){console.error('Registration failed:',e);res.status(500).json({success:false,message:'Registration failed!'});}
});

app.post('/api/login',async(req,res)=>{try{const {mobile,password}=req.body;const user=await getUser(String(mobile||''));if(!user||!(await bcrypt.compare(String(password||''),user.password_hash)))return res.status(400).json({success:false,message:'Invalid Mobile or Password!'});if(user.is_blocked)return res.status(403).json({success:false,message:'Your account is blocked by admin.'});res.json({success:true,message:'Login Successful!',user:publicUser(user)});}catch(e){console.error(e);res.status(500).json({success:false,message:'Login failed!'});}});
app.get('/api/game-status',(req,res)=>res.json({roundId:currentRound.roundId,timeLeft:currentRound.timeLeft,status:currentRound.status,lastWinningColor:winningColor,lastWinningNumber:winningNumber}));
app.get('/api/user/:userId',async(req,res)=>{try{const user=await getUser(req.params.userId);if(!user)return res.status(404).json({success:false,message:'User not found'});res.json({success:true,balance:Number(user.balance),userId:user.mobile,name:user.name});}catch(e){res.status(500).json({success:false,message:'Server error'});}});

app.post('/api/place-bet',async(req,res)=>{try{const {userId,betType,betValue,amount}=req.body;const value=Number(amount);if(currentRound.status!=='OPEN')return res.status(400).json({success:false,message:'Betting closed!'});if(!Number.isFinite(value)||value<10)return res.status(400).json({success:false,message:'Minimum Bet Amount ₹10 honi chahiye!'});const ref=usersRef().child(String(userId));let remaining=null;const tx=await ref.transaction(u=>{if(!u||u.is_blocked||Number(u.balance||0)<value)return;remaining=Number(u.balance)-value;return {...u,balance:remaining};});if(!tx.committed)return res.status(400).json({success:false,message:'Insufficient Balance!'});currentBets.push({userId,betType,betValue,amount:value});res.json({success:true,message:'Bet Placed Successfully!',remainingBalance:remaining});}catch(e){res.status(500).json({success:false,message:'Bet failed!'});}});

app.post('/api/add-money',async(req,res)=>{try{const {userId,amount,utrNumber}=req.body;const value=Number(amount);const user=await getUser(userId);if(!user)return res.status(404).json({success:false,message:'User not found!'});if(!Number.isFinite(value)||value<100)return res.status(400).json({success:false,message:'Minimum Deposit is ₹100!'});if(!utrNumber||!String(utrNumber).trim())return res.status(400).json({success:false,message:'Please enter UTR Transaction Number!'});const id=await nextId('deposit');const deposit={id,user_id:user.id,mobile:user.mobile,name:user.name,amount:value,utr_number:String(utrNumber).trim(),status:'PENDING',created_at:new Date().toISOString()};await depositsRef().child(String(id)).set(deposit);await sendTelegramMessage(`<b>📥 New Deposit Request</b>\n\n<b>Request ID:</b> #${id}\n<b>User:</b> ${String(user.name).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}\n<b>Mobile:</b> ${user.mobile}\n<b>Amount:</b> ₹${value.toFixed(2)}\n<b>UTR:</b> ${String(utrNumber).trim()}\n<b>Status:</b> PENDING\n<b>Time:</b> ${new Date().toLocaleString('en-IN')}`,{inline_keyboard:[[{text:'✅ APPROVE',callback_data:`deposit:approve:${id}`},{text:'❌ REJECT',callback_data:`deposit:reject:${id}`}]]});res.json({success:true,message:`₹${value} Deposit Request Submitted! Admin approval ke baad amount wallet mein add hoga.`,newBalance:Number(user.balance),status:'PENDING',depositId:id});}catch(e){console.error('Deposit request error:',e);res.status(500).json({success:false,message:'Deposit failed!'});}});

app.post('/api/withdraw',async(req,res)=>{try{const {userId,amount,upiId,accountDetails}=req.body;const value=Number(amount);if(value<110)return res.status(400).json({success:false,message:'Minimum Withdrawal is ₹110!'});const userRef=usersRef().child(String(userId));let remaining=null;const tx=await userRef.transaction(u=>{if(!u||Number(u.balance||0)<value)return;remaining=Number(u.balance)-value;return {...u,balance:remaining};});if(!tx.committed)return res.status(400).json({success:false,message:'Insufficient Wallet Balance!'});const id=await nextId('withdrawal');await withdrawalsRef().child(String(id)).set({id,user_id:tx.snapshot.val().id,mobile:String(userId),name:tx.snapshot.val().name,amount:value,upi_id:upiId||null,account_details:accountDetails||null,status:'PENDING',created_at:new Date().toISOString()});res.json({success:true,message:`Withdrawal request of ₹${value} submitted successfully!`,newBalance:remaining});}catch(e){res.status(500).json({success:false,message:'Withdrawal request failed!'});}});

app.get('/api/admin/users',adminAuth,async(req,res)=>{try{const snap=await usersRef().once('value');const users=[];snap.forEach(c=>{const u=cleanUser(c.val());if(u)users.push({...u,password_hash:undefined});});users.sort((a,b)=>b.id-a.id);res.json({success:true,users});}catch(e){res.status(500).json({success:false,message:'Failed to load users'});}});
app.post('/api/admin/users/:id/block',adminAuth,async(req,res)=>{try{const snap=await usersRef().once('value');let key=null;snap.forEach(c=>{if(Number(c.val()?.id)===Number(req.params.id))key=c.key});if(!key)return res.status(404).json({success:false,message:'User not found'});await usersRef().child(key).update({is_blocked:true});res.json({success:true});}catch(e){res.status(500).json({success:false,message:'Failed'});}});
app.post('/api/admin/users/:id/unblock',adminAuth,async(req,res)=>{try{const snap=await usersRef().once('value');let key=null;snap.forEach(c=>{if(Number(c.val()?.id)===Number(req.params.id))key=c.key});if(!key)return res.status(404).json({success:false,message:'User not found'});await usersRef().child(key).update({is_blocked:false});res.json({success:true});}catch(e){res.status(500).json({success:false,message:'Failed'});}});
app.delete('/api/admin/users/:id',adminAuth,async(req,res)=>{try{const snap=await usersRef().once('value');let key=null;snap.forEach(c=>{if(Number(c.val()?.id)===Number(req.params.id))key=c.key});if(!key)return res.status(404).json({success:false,message:'User not found'});await usersRef().child(key).remove();res.json({success:true});}catch(e){res.status(500).json({success:false,message:'Failed'});}});

async function listDeposits(){const snap=await depositsRef().once('value');const a=[];snap.forEach(c=>a.push(c.val()));return a.sort((x,y)=>Number(y.id)-Number(x.id));}
async function listWithdrawals(){const snap=await withdrawalsRef().once('value');const a=[];snap.forEach(c=>a.push(c.val()));return a.sort((x,y)=>Number(y.id)-Number(x.id));}
app.get('/api/admin/deposits',adminAuth,async(req,res)=>{try{res.json({success:true,deposits:await listDeposits()});}catch(e){res.status(500).json({success:false,message:'Failed'});}});
app.post('/api/admin/deposits/:id/approve',adminAuth,async(req,res)=>{try{const ref=depositsRef().child(String(req.params.id));const snap=await ref.once('value');if(!snap.exists()||snap.val().status!=='PENDING')return res.json({success:false,message:'Already processed'});const d=snap.val();const uref=usersRef().child(String(d.mobile));const tx=await uref.transaction(u=>u?{...u,balance:Number(u.balance||0)+Number(d.amount||0)}:u);if(!tx.committed)return res.status(404).json({success:false,message:'User not found'});await ref.update({status:'APPROVED',processed_at:new Date().toISOString()});await sendTelegramMessage(`<b>✅ Deposit Approved</b>\n\n<b>Request ID:</b> #${d.id}\n<b>Amount:</b> ₹${Number(d.amount).toFixed(2)}\n<b>Status:</b> APPROVED`);res.json({success:true,message:'Deposit approved and wallet credited.'});}catch(e){res.status(500).json({success:false,message:'Failed'});}});
app.post('/api/admin/deposits/:id/reject',adminAuth,async(req,res)=>{try{const ref=depositsRef().child(String(req.params.id));const snap=await ref.once('value');if(!snap.exists()||snap.val().status!=='PENDING')return res.json({success:false,message:'Already processed'});await ref.update({status:'REJECTED',processed_at:new Date().toISOString()});res.json({success:true,message:'Deposit rejected.'});}catch(e){res.status(500).json({success:false,message:'Failed'});}});
app.get('/api/admin/withdrawals',adminAuth,async(req,res)=>{try{res.json({success:true,withdrawals:await listWithdrawals()});}catch(e){res.status(500).json({success:false,message:'Failed'});}});
app.post('/api/admin/withdrawals/:id/approve',adminAuth,async(req,res)=>{try{const ref=withdrawalsRef().child(String(req.params.id));const snap=await ref.once('value');if(!snap.exists()||snap.val().status!=='PENDING')return res.json({success:false,message:'Already processed'});await ref.update({status:'APPROVED',processed_at:new Date().toISOString()});res.json({success:true,message:'Approved'});}catch(e){res.status(500).json({success:false,message:'Failed'});}});
app.post('/api/admin/withdrawals/:id/reject',adminAuth,async(req,res)=>{try{const ref=withdrawalsRef().child(String(req.params.id));const snap=await ref.once('value');if(!snap.exists()||snap.val().status!=='PENDING')return res.json({success:false,message:'Already processed'});const w=snap.val();const uref=usersRef().child(String(w.mobile));const tx=await uref.transaction(u=>u?{...u,balance:Number(u.balance||0)+Number(w.amount||0)}:u);if(!tx.committed)return res.status(404).json({success:false,message:'User not found'});await ref.update({status:'REJECTED',processed_at:new Date().toISOString()});res.json({success:true});}catch(e){res.status(500).json({success:false,message:'Failed'});}});

app.get('/api/user/:userId/deposits',async(req,res)=>{try{const user=await getUser(req.params.userId);if(!user)return res.status(404).json({success:false,message:'User not found'});const a=(await listDeposits()).filter(x=>String(x.mobile)===String(user.mobile)).slice(0,100).map(x=>({id:x.id,amount:Number(x.amount),utr_number:x.utr_number,status:x.status,created_at:x.created_at}));res.json({success:true,deposits:a});}catch(e){res.status(500).json({success:false,message:'Failed to load deposit history'});}});
app.get('/api/user/:userId/withdrawals',async(req,res)=>{try{const user=await getUser(req.params.userId);if(!user)return res.status(404).json({success:false,message:'User not found'});const a=(await listWithdrawals()).filter(x=>String(x.mobile)===String(user.mobile)).slice(0,100).map(x=>({id:x.id,amount:Number(x.amount),upi_id:x.upi_id,status:x.status,created_at:x.created_at}));res.json({success:true,withdrawals:a});}catch(e){res.status(500).json({success:false,message:'Failed to load withdrawal history'});}});

app.get('/api/health',(req,res)=>res.json({success:true,database:!!firebaseDb,firebase:!!firebaseDb}));
app.use(express.static(__dirname));
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'admin.html')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'index.html')));

if (!firebaseDb) {
  app.listen(PORT,()=>console.log(`Server running on port ${PORT}. Waiting for Firebase credentials.`));
} else {
  initDb().then(()=>app.listen(PORT,()=>{console.log(`Server running on port ${PORT}`);telegramPollLoop();})).catch(err=>{console.error('Firebase init failed:',err);app.listen(PORT,()=>console.log(`Server running on port ${PORT}, but Firebase initialization failed.`));});
}
