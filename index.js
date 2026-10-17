const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { onSchedule } = require('firebase-functions/v2/scheduler');
const { defineSecret, defineString } = require('firebase-functions/params');
const logger = require('firebase-functions/logger');
const admin = require('firebase-admin');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

admin.initializeApp();
const db = admin.firestore();
const FV = admin.firestore.FieldValue;

const SMTP_URL = defineSecret('SMTP_URL');          // smtps://user:pass@smtp.host:465
const RZP_KEY = defineSecret('RAZORPAY_KEY');
const RZP_SECRET = defineSecret('RAZORPAY_SECRET');
const DEMO = defineString('DEMO_MODE', { default: 'false' });
const MAIL_FROM = defineString('MAIL_FROM', { default: 'Kameti <no-reply@example.com>' });
const opt = { region: 'asia-south1', secrets: [SMTP_URL, RZP_KEY, RZP_SECRET] };

/* ---------- helpers ---------- */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const bad = (m, c = 'failed-precondition') => { throw new HttpsError(c, m); };
const authed = r => { if (!r.auth) bad('Pehle login karein.', 'unauthenticated'); return r.auth.uid; };
const okUpi = u => /^[\w.\-]{2,}@[a-zA-Z]{2,}$/.test(u);
const okMail = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const okMobile = m => /^[6-9]\d{9}$/.test(m);
const isDemo = () => DEMO.value() === 'true';
const DAY = 864e5;
const todayIST = () => { const d = new Date(Date.now() + 19800000); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()); };
const isoOf = ms => new Date(ms).toISOString().slice(0, 10);
const dueOf = g => { const [y, m, d] = g.start.split('-').map(Number); return Date.UTC(y, m - 1 + g.month - 1, d); };
const dayNo = g => Math.floor((todayIST() - dueOf(g)) / DAY) + 1;
const pct = n => (n >= 10 ? 5 : n >= 6 ? 3 : 0);          // din 1-5: 0%, 6-9: 3%, 10+: 5%
const amtNow = g => Math.round(g.amount * (1 + pct(dayNo(g)) / 100));
const isDone = g => g.month > g.members.length;
const isLocked = g => g.month > 1 || Object.keys(g.paid || {}).length > 0 || (g.history || []).length > 0;
const complete = u => !!(u && u.name && u.aadhaar4 && u.addr && u.addr.line && u.mobile);

async function send(kind, to, text) {
  // Sirf email (free SMTP). Mobile OTP Firebase Phone Auth khud bhejta hai.
  if (isDemo()) { logger.info(`DEMO message to ${to}: ${text}`); return; }
  await nodemailer.createTransport(SMTP_URL.value()).sendMail({ from: MAIL_FROM.value(), to, subject: 'Kameti', text });
}

function cleanIdentity(d) {
  const kind = d.kind, v = String(d.id || '').trim().toLowerCase();
  if (!['mobile', 'email'].includes(kind)) bad('Galat tareeka.');
  if (kind === 'mobile' ? !okMobile(v) : !okMail(v)) bad('Sahi mobile/email daalein.');
  return { kind, v, key: sha(kind + ':' + v) };
}

async function loadGroup(r, gid, ownerOnly) {
  const uid = authed(r);
  const ref = db.doc('groups/' + String(gid));
  const s = await ref.get();
  if (!s.exists) bad('Group nahi mila.', 'not-found');
  const g = s.data();
  if (!g.memberUids.includes(uid)) bad('Aap is group ke member nahi hain.', 'permission-denied');
  if (ownerOnly && g.owner !== uid) bad('Ye kaam sirf group ka admin kar sakta hai.', 'permission-denied');
  return { uid, ref, g };
}

/* ---------- OTP login (2 minute expiry) ---------- */
exports.sendOtp = onCall(opt, async r => {
  const { kind, v, key } = cleanIdentity(r.data || {});
  if (kind !== 'email') bad('Mobile OTP Firebase Phone Auth se hota hai.');
  const tab = (r.data || {}).tab;
  const exists = (await db.doc('identities/' + key).get()).exists;
  if (tab === 'login' && !exists) bad('Ye account registered nahi hai. Pehle Register karein.');
  if (tab === 'register' && exists) bad('Ye pehle se registered hai. Login karein.');
  const ref = db.doc('otps/' + key), s = await ref.get(), now = Date.now(), o = s.exists ? s.data() : null;
  if (o && now - o.sent < 30000) bad('30 second baad dobara try karein.', 'resource-exhausted');
  const inHour = o && now - o.hourStart < 3600000;
  if (inHour && o.count >= 5) bad('Bahut zyada OTP maange gaye. Thodi der baad try karein.', 'resource-exhausted');
  const code = String(crypto.randomInt(100000, 1000000));
  await ref.set({ h: sha(code + key), exp: now + 120000, tries: 0, sent: now, hourStart: inHour ? o.hourStart : now, count: inHour ? o.count + 1 : 1 });
  await send(kind, v, `Kameti OTP: ${code}. Ye 2 minute tak valid hai. Kisi ko na batayein.`);
  return { ok: true };
});

exports.verifyOtp = onCall(opt, async r => {
  const { kind, v, key } = cleanIdentity(r.data || {});
  if (kind !== 'email') bad('Mobile OTP Firebase Phone Auth se hota hai.');
  const tab = (r.data || {}).tab, code = String((r.data || {}).code || '').trim();
  const ref = db.doc('otps/' + key), s = await ref.get();
  if (!s.exists) bad('Pehle OTP mangwayein.');
  const o = s.data();
  if (Date.now() > o.exp) { await ref.delete(); bad('OTP expire ho gaya. Naya OTP mangwayein.'); }
  if (o.tries >= 5) { await ref.delete(); bad('Bahut galat koshish. Naya OTP mangwayein.'); }
  if (sha(code + key) !== o.h) { await ref.update({ tries: o.tries + 1 }); bad('OTP galat hai.'); }
  await ref.delete();
  const idRef = db.doc('identities/' + key), ids = await idRef.get();
  let uid;
  if (ids.exists) {
    uid = ids.data().uid;
  } else {
    if (tab === 'login') bad('Ye account registered nahi hai. Pehle Register karein.');
    uid = (await admin.auth().createUser({})).uid;
    await idRef.create({ uid, kind, v });
    await db.doc('users/' + uid).set({ [kind]: v, verifiedKind: kind, upiOk: false, createdAt: FV.serverTimestamp() });
  }
  return { token: await admin.auth().createCustomToken(uid) };
});

// Mobile OTP bhejne se pehle jaanch (Login/Register ke galat tab par SMS kharch na ho)
exports.checkIdentity = onCall(opt, async r => {
  const { kind, key } = cleanIdentity(r.data || {});
  const tab = (r.data || {}).tab, exists = (await db.doc('identities/' + key).get()).exists;
  if (tab === 'login' && !exists) bad('Ye account registered nahi hai. Pehle Register karein.');
  if (tab === 'register' && exists) bad('Ye pehle se registered hai. Login karein.');
  return { ok: true, kind };
});

// Firebase Phone Auth se login hone ke baad account banata/jaanchta hai
exports.phoneEnter = onCall(opt, async r => {
  const uid = authed(r), tab = (r.data || {}).tab, pn = String(r.auth.token.phone_number || '');
  const m = /^\+91([6-9]\d{9})$/.exec(pn);
  if (!m) bad('Abhi sirf India (+91) mobile numbers chalte hain.');
  const mobile = m[1], idRef = db.doc('identities/' + sha('mobile:' + mobile));
  const [ids, us] = await Promise.all([idRef.get(), db.doc('users/' + uid).get()]);
  if (ids.exists && ids.data().uid !== uid) bad('Ye number kisi aur account se juda hai.');
  if (tab === 'login' && !us.exists) bad('Ye account registered nahi hai. Pehle Register karein.');
  if (tab === 'register' && us.exists) bad('Pehle se registered hai. Login karein.');
  if (!us.exists) {
    await idRef.create({ uid, kind: 'mobile', v: mobile });
    await db.doc('users/' + uid).set({ mobile, verifiedKind: 'mobile', upiOk: false, createdAt: FV.serverTimestamp() });
  }
  return { ok: true };
});

exports.googleEnter = onCall(opt, async r => {
  const uid = authed(r), t = r.auth.token, tab = (r.data || {}).tab;
  if (!t.email || !t.email_verified) bad('Google email verified nahi hai.');
  const email = t.email.toLowerCase(), idRef = db.doc('identities/' + sha('email:' + email));
  const [ids, us] = await Promise.all([idRef.get(), db.doc('users/' + uid).get()]);
  if (ids.exists && ids.data().uid !== uid) bad('Ye email pehle doosre tareeke se registered hai. Email OTP se login karein.');
  if (tab === 'login' && !us.exists) bad('Ye account registered nahi hai. Pehle Register karein.');
  if (tab === 'register' && us.exists) bad('Ye pehle se registered hai. Login karein.');
  if (!us.exists) {
    await idRef.create({ uid, kind: 'email', v: email });
    await db.doc('users/' + uid).set({ email, name: t.name || '', verifiedKind: 'email', upiOk: false, createdAt: FV.serverTimestamp() });
  }
  return { ok: true };
});

/* ---------- Profile & UPI ---------- */
exports.saveProfile = onCall(opt, async r => {
  const uid = authed(r), d = r.data || {}, ref = db.doc('users/' + uid), us = await ref.get();
  if (!us.exists) bad('Account nahi mila.');
  const u = us.data(), a = d.addr || {};
  const name = String(d.name || '').trim().slice(0, 80);
  // Login wali verified mobile/email badli nahi ja sakti (squatting rokne ke liye)
  const mobile = u.verifiedKind === 'mobile' ? u.mobile : String(d.mobile || '').trim();
  const email = u.verifiedKind === 'email' ? u.email : String(d.email || '').trim().toLowerCase();
  const aadhaar4 = String(d.aadhaar4 || u.aadhaar4 || '');
  const addr = { line: String(a.line || '').trim().slice(0, 150), city: String(a.city || '').trim().slice(0, 60), state: String(a.state || '').trim().slice(0, 60), pin: String(a.pin || '').trim() };
  const upi = String(d.upi || '').trim();
  if (!name) bad('Naam likhein.');
  if (!okMobile(mobile)) bad('10 ank ka sahi mobile number daalein.');
  if (email && !okMail(email)) bad('Sahi email likhein.');
  if (!/^\d{4}$/.test(aadhaar4)) bad('Aadhaar ke aakhri 4 ank zaroori hain.');
  if (!addr.line || !addr.city || !addr.state) bad('Pura pata bharein.');
  if (!/^\d{6}$/.test(addr.pin)) bad('6 ank ka pincode daalein.');
  if (upi && !okUpi(upi)) bad('UPI ID sahi likhein.');
  const upd = { name, mobile, email, aadhaar4, addr };
  if (upi) { upd.upi = upi; if (upi !== u.upi) { upd.upiOk = false; upd.upiName = ''; } }
  await ref.update(upd);
  return { ok: true };
});

exports.verifyUpi = onCall(opt, async r => {
  const uid = authed(r), ref = db.doc('users/' + uid), u = (await ref.get()).data();
  if (!u || !u.upi || !okUpi(u.upi)) bad('Pehle UPI ID save karein.');
  let name = '';
  if (!isDemo()) {
    const res = await fetch('https://api.razorpay.com/v1/payments/validate/vpa', {
      method: 'POST',
      headers: { Authorization: 'Basic ' + Buffer.from(RZP_KEY.value() + ':' + RZP_SECRET.value()).toString('base64'), 'Content-Type': 'application/json' },
      body: JSON.stringify({ vpa: u.upi })
    });
    const j = await res.json().catch(() => ({}));
    if (!res.ok || !j.success) bad('Ye UPI ID verify nahi ho saki.');
    name = j.customer_name || '';
  }
  await ref.update({ upiOk: true, upiName: name });
  return { ok: true, name };
});

/* ---------- Groups ---------- */
exports.createGroup = onCall(opt, async r => {
  const uid = authed(r), d = r.data || {}, u = (await db.doc('users/' + uid).get()).data();
  if (!complete(u)) bad('Pehle profile poori karein.');
  if (!u.upiOk) bad('Pehle UPI verify karein.');
  const name = String(d.name || '').trim().slice(0, 80), amount = Math.round(Number(d.amount)), start = String(d.start || '');
  if (!name || !(amount > 0) || amount > 1000000) bad('Naam aur sahi kist bharein.');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(start)) bad('Sahi tareekh chunein.');
  const ref = await db.collection('groups').add({
    owner: uid, name, amount, start, month: 1, paid: {}, winner: null, payout: null, history: [],
    members: [{ uid, slot: 1, name: u.name, won: false }], memberUids: [uid], createdAt: FV.serverTimestamp()
  });
  return { id: ref.id };
});

exports.editGroup = onCall(opt, async r => {
  const { ref, g } = await loadGroup(r, (r.data || {}).gid, true);
  const name = String(r.data.name || '').trim().slice(0, 80), upd = {};
  if (!name) bad('Naam likhein.');
  upd.name = name;
  if (r.data.amount !== undefined && Math.round(Number(r.data.amount)) !== g.amount) {
    if (isLocked(g)) bad('Kameti shuru hone ke baad kist nahi badli ja sakti.');
    const a = Math.round(Number(r.data.amount)); if (!(a > 0) || a > 1000000) bad('Sahi kist bharein.');
    upd.amount = a;
  }
  await ref.update(upd); return { ok: true };
});

exports.deleteGroup = onCall(opt, async r => {
  const { ref } = await loadGroup(r, (r.data || {}).gid, true);
  await ref.delete(); return { ok: true };
});

exports.addMember = onCall(opt, async r => {
  const { ref, g } = await loadGroup(r, (r.data || {}).gid, true);
  if (isLocked(g)) bad('Kameti shuru hone ke baad member nahi jud sakte.');
  const q = String(r.data.query || '').trim().toLowerCase(), k = Math.max(1, Math.min(5, Math.round(Number(r.data.hisse) || 1)));
  const kind = okMobile(q) ? 'mobile' : okMail(q) ? 'email' : null;
  if (!kind) bad('Sahi mobile ya email likhein.');
  const ids = await db.doc('identities/' + sha(kind + ':' + q)).get();
  if (!ids.exists) bad('Ye number/email registered nahi hai. Unse pehle Register karne ko kahein.');
  const muid = ids.data().uid, u = (await db.doc('users/' + muid).get()).data();
  if (!complete(u)) bad('Is member ki profile poori nahi hai.');
  if (!u.upiOk) bad('Is member ka UPI verify nahi hai.');
  const have = g.members.filter(m => m.uid === muid).length;
  if (have + k > 5) bad('Ek person ke zyada se zyada 5 hisse ho sakte hain.');
  const add = Array.from({ length: k }, (_, i) => ({ uid: muid, slot: have + i + 1, name: u.name, won: false }));
  await ref.update({ members: [...g.members, ...add], memberUids: FV.arrayUnion(muid) });
  return { ok: true };
});

exports.markPaid = onCall(opt, async r => {
  const { ref, g } = await loadGroup(r, (r.data || {}).gid, true);
  const i = Number(r.data.idx);
  if (isDone(g) || g.winner !== null) bad('Is waqt kist badli nahi ja sakti.');
  if (!Number.isInteger(i) || i < 0 || i >= g.members.length) bad('Galat hissa.');
  await ref.update({ ['paid.' + i]: r.data.paid ? { amt: amtNow(g), on: isoOf(todayIST()) } : FV.delete() });
  return { ok: true };
});

exports.drawWinner = onCall(opt, async r => {
  const { ref, g } = await loadGroup(r, (r.data || {}).gid, true);
  const n = g.members.length;
  if (isDone(g) || g.winner !== null) bad('Is mahine ka draw ho chuka hai.');
  if (n < 3) bad('Kam se kam 3 hisse chahiye.');
  if (Object.keys(g.paid).length !== n) bad('Pehle sabki kist poori karein.');
  const pool = g.members.map((m, i) => (m.won ? -1 : i)).filter(i => i >= 0);
  const w = pool[crypto.randomInt(0, pool.length)];
  const wu = (await db.doc('users/' + g.members[w].uid).get()).data();
  if (!wu || !wu.upiOk) bad('Jeetne wale ka UPI verify nahi hai.');
  await ref.update({ winner: w, payout: { name: wu.name, upi: wu.upi, transferred: false } });
  return { winner: w };
});

exports.setPayout = onCall(opt, async r => {
  const { uid, ref, g } = await loadGroup(r, (r.data || {}).gid, false);
  if (g.winner === null || g.members[g.winner].uid !== uid) bad('Sirf jeetne wala pot transfer kar sakta hai.', 'permission-denied');
  if (r.data.reset) {
    const u = (await db.doc('users/' + uid).get()).data();
    await ref.update({ payout: { name: u.name, upi: u.upi, transferred: false } });
  } else {
    const name = String(r.data.name || '').trim().slice(0, 80), upi = String(r.data.upi || '').trim();
    if (!name) bad('Naam likhein.');
    if (!okUpi(upi)) bad('UPI ID sahi likhein.');
    await ref.update({ payout: { name, upi, transferred: true } });
  }
  return { ok: true };
});

exports.completeMonth = onCall(opt, async r => {
  const { ref, g } = await loadGroup(r, (r.data || {}).gid, true);
  if (g.winner === null) bad('Pehle draw karein.');
  const pot = Object.values(g.paid).reduce((s, p) => s + p.amt, 0);
  const members = g.members.map((m, i) => (i === g.winner ? { ...m, won: true } : m));
  const w = g.members[g.winner];
  await ref.update({
    members, month: g.month + 1, paid: {}, winner: null, payout: null,
    history: FV.arrayUnion({ m: g.month, name: w.name + (w.slot > 1 ? ` (hissa ${w.slot})` : ''), to: `${g.payout.name} · ${g.payout.upi}`, amt: pot, on: isoOf(todayIST()) })
  });
  return { ok: true };
});

/* ---------- Daily reminders: kist se 1 din pehle aur usi din, subah 9 baje IST ---------- */
exports.dailyReminders = onSchedule({ ...opt, schedule: '0 9 * * *', timeZone: 'Asia/Kolkata' }, async () => {
  const snap = await db.collection('groups').get();
  for (const doc of snap.docs) {
    const g = doc.data();
    if (isDone(g)) continue;
    const diff = Math.round((dueOf(g) - todayIST()) / DAY);
    if (diff !== 0 && diff !== 1) continue;
    const unpaid = new Set(g.members.map((m, i) => (g.paid[i] ? null : m.uid)).filter(Boolean));
    for (const uid of unpaid) {
      const u = (await db.doc('users/' + uid).get()).data();
      if (!u) continue;
      const to = u.email; if (!to) continue;
      try { await send('email', to, `Kameti yaad: "${g.name}" ki kist ${diff ? 'kal' : 'aaj'} due hai (₹${g.amount}). 5 din tak koi extra charge nahi.`); }
      catch (e) { logger.error('reminder failed', e); }
    }
  }
});
