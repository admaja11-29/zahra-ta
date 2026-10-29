// FaceSecure AI — pengenalan wajah nyata (embedding 128-D via face-api.js) + liveness berbasis tantangan acak.
// Ganti MODEL ke './models/' jika Anda mengunduh berkas model sendiri (lihat README).
const MODEL = 'https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.12/model/';
const THRESHOLD = 0.5;           // jarak Euclidean maksimum agar dianggap orang yang sama
const KEY = 'fs_users';
const $ = s => document.querySelector(s);
const sleep = ms => new Promise(r => setTimeout(r, ms));
let users = {}; try { users = JSON.parse(localStorage.getItem(KEY) || '{}'); } catch (e) {}
let me = sessionStorage.getItem('fs_me'), stream = null, run = 0, ready = false, fails = 0, lockUntil = 0, retry = null;
const vid = $('#vid'), dlg = $('#dlg');
const store = () => { try { localStorage.setItem(KEY, JSON.stringify(users)); } catch (e) { toast('Penyimpanan penuh', 'err'); } };

function toast(m, t) { const e = document.createElement('div'); e.className = 'tt ' + (t || ''); e.textContent = m; $('#toast').append(e); setTimeout(() => e.remove(), 3500); }
function view(n) { document.querySelectorAll('.view').forEach(v => v.classList.add('hidden')); $('#v-' + n).classList.remove('hidden'); if (n === 'home') home(); }
const say = m => $('#say').textContent = m, prog = p => $('#prog').style.width = Math.round(p * 100) + '%';

// ---------- Kata sandi: PBKDF2 + salt acak ----------
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function hash(pw, salt) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  return b64(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' }, k, 256));
}
function enter(u) { me = u; sessionStorage.setItem('fs_me', u); view('home'); }
$('#to-reg').onclick = e => { e.preventDefault(); view('reg'); };
$('#to-login').onclick = e => { e.preventDefault(); view('login'); };
$('#f-reg').onsubmit = async e => {
  e.preventDefault(); const u = $('#ru').value.trim(), p = $('#rp').value;
  if (u.length < 3 || p.length < 8) return toast('Nama min. 3 karakter, kata sandi min. 8 karakter', 'err');
  if (users[u]) return toast('Nama pengguna sudah dipakai', 'err');
  if (!window.crypto || !crypto.subtle) return toast('Fitur keamanan memerlukan HTTPS atau localhost', 'err');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  users[u] = { salt: b64(salt), hash: await hash(p, salt), desc: null, faceOn: false }; store(); toast('Akun dibuat'); enter(u);
};
$('#f-login').onsubmit = async e => {
  e.preventDefault(); const u = users[$('#lu').value.trim()];
  if (!u || await hash($('#lp').value, unb64(u.salt)) !== u.hash) return toast('Nama pengguna atau kata sandi salah', 'err');
  enter($('#lu').value.trim()); $('#lp').value = '';
};

// ---------- Izin, kamera, model ----------
function consent(withStore) {
  return new Promise(res => {
    $('#cs').classList.toggle('hidden', !withStore); $('#ck').checked = false; dlg.showModal();
    $('#ok').onclick = () => { if (withStore && !$('#ck').checked) return toast('Centang persetujuan dahulu', 'err'); dlg.close('y'); res(true); };
    $('#no').onclick = () => { dlg.close('n'); res(false); };
    dlg.addEventListener('close', () => res(false), { once: true });
  });
}
async function openCam() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) throw new Error('INSECURE');
  stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } }, audio: false });
  vid.srcObject = stream; await vid.play();
}
function closeCam() { run++; if (stream) stream.getTracks().forEach(t => t.stop()); stream = null; vid.srcObject = null; }
async function loadModels() {
  if (ready) return; say('Memuat model AI…');
  if (typeof faceapi === 'undefined') throw new Error('LIB');
  await Promise.all([faceapi.nets.tinyFaceDetector, faceapi.nets.faceLandmark68Net, faceapi.nets.faceRecognitionNet].map(n => n.loadFromUri(MODEL)));
  ready = true;
}
function errMsg(e) {
  const n = e && (e.name || e.message);
  if (n === 'NotAllowedError') return 'Izin kamera ditolak. Izinkan kamera di pengaturan browser, atau masuk dengan kata sandi.';
  if (n === 'NotFoundError') return 'Kamera tidak ditemukan. Gunakan login kata sandi.';
  if (n === 'INSECURE') return 'Kamera memerlukan HTTPS atau localhost.';
  if (n === 'LIB' || /fetch|load|network/i.test(String(e && e.message))) return 'Model AI gagal dimuat. Periksa koneksi internet lalu coba lagi.';
  return 'Terjadi kesalahan: ' + (e && e.message || e);
}

// ---------- Deteksi wajah, liveness ----------
const d2 = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
const ear = (p, i) => (d2(p[i + 1], p[i + 5]) + d2(p[i + 2], p[i + 4])) / (2 * d2(p[i], p[i + 3]));
const mar = p => d2(p[62], p[66]) / d2(p[60], p[64]);
const yaw = p => (p[30].x - p[0].x) / (p[16].x - p[0].x);   // ~0.5 = menghadap lurus
async function look(id, strict) {
  const opt = new faceapi.TinyFaceDetectorOptions({ inputSize: 320, scoreThreshold: 0.5 });
  const all = await faceapi.detectAllFaces(vid, opt).withFaceLandmarks().withFaceDescriptors();
  if (id !== run) return null;
  if (!all.length) { say('Wajah tidak terdeteksi. Posisikan wajah di tengah'); return null; }
  if (all.length > 1) { say('Pastikan hanya satu wajah di kamera'); return null; }
  const r = all[0], b = r.detection.box, cx = (b.x + b.width / 2) / vid.videoWidth;
  if (strict && (b.width / vid.videoWidth < 0.28 || cx < 0.3 || cx > 0.7)) { say('Dekatkan dan pusatkan wajah di bingkai'); return null; }
  return r;
}
async function grab(id, n) {            // kumpulkan n templat wajah menghadap lurus, lalu rata-ratakan
  const ds = [], t0 = Date.now(); say('Pindai wajah Anda — tatap lurus ke kamera');
  while (id === run && ds.length < n && Date.now() - t0 < 25000) {
    const r = await look(id, true);
    if (r) { const y = yaw(r.landmarks.positions); if (y > 0.4 && y < 0.6) { ds.push(r.descriptor); prog(ds.length / n); } else say('Hadapkan wajah lurus ke kamera'); }
    await sleep(250);
  }
  if (ds.length < n) return null;
  return ds[0].map((_, i) => ds.reduce((s, d) => s + d[i], 0) / n);
}
const CH = { blink: 'Kedipkan mata Anda', left: 'Tengok ke kiri', right: 'Tengok ke kanan', mouth: 'Buka mulut Anda' };
async function challenge(id, name) {
  const t0 = Date.now(); let closed = false; say(CH[name]);
  while (id === run && Date.now() - t0 < 12000) {
    const r = await look(id, false);
    if (r) {
      const p = r.landmarks.positions, y = yaw(p);
      if (name === 'blink') { const e = (ear(p, 36) + ear(p, 42)) / 2; if (e < 0.2) closed = true; else if (closed && e > 0.25) return true; }
      if (name === 'left' && y > 0.65) return true;
      if (name === 'right' && y < 0.35) return true;
      if (name === 'mouth' && mar(p) > 0.4) return true;
    }
    await sleep(50);
  }
  return false;
}

// ---------- Alur: daftar wajah & masuk dengan wajah ----------
function result(ok, title, msg, b1, f1, b2, f2) {
  $('#res-i').textContent = ok ? '✅' : '⚠️'; $('#res-t').textContent = title; $('#res-m').textContent = msg;
  $('#res-1').textContent = b1; $('#res-1').onclick = f1; $('#res-2').textContent = b2; $('#res-2').onclick = f2; view('res');
}
const toLogin = () => view('login');
async function enroll() {
  if (!(await consent(true))) return;
  $('#cam-t').textContent = 'Daftarkan wajah'; prog(0); view('cam'); const id = ++run;
  try {
    await openCam(); await loadModels(); const d = await grab(id, 5), gone = id !== run; closeCam();
    if (gone) return;
    if (!d) return result(false, 'Pendaftaran gagal', 'Wajah tidak terbaca dengan jelas. Coba lagi di tempat yang lebih terang.', 'Coba lagi', enroll, 'Kembali', () => view('home'));
    users[me].desc = d; users[me].faceOn = true; store(); toast('Wajah berhasil didaftarkan'); view('home');
  } catch (e) { closeCam(); result(false, 'Tidak dapat memulai', errMsg(e), 'Coba lagi', enroll, 'Kembali', () => view('home')); }
}
async function faceLogin() {
  const cands = Object.entries(users).filter(([, u]) => u.faceOn && u.desc);
  if (!cands.length) return toast('Belum ada Face ID terdaftar. Masuk dengan kata sandi lalu aktifkan Face ID.', 'err');
  if (Date.now() < lockUntil) return toast('Terlalu banyak percobaan. Tunggu ' + Math.ceil((lockUntil - Date.now()) / 1000) + ' detik.', 'err');
  if (!(await consent(false))) return;
  $('#cam-t').textContent = 'Pemindaian wajah'; prog(0); view('cam'); const id = ++run, fail = (t, m) => result(false, t, m, 'Coba lagi', faceLogin, 'Masuk dengan kata sandi', toLogin);
  try {
    await openCam(); await loadModels();
    const picks = Object.keys(CH).sort(() => Math.random() - 0.5).slice(0, 2);   // tantangan acak → sulit dipalsukan dengan foto
    for (let i = 0; i < picks.length; i++) {
      if (!(await challenge(id, picks[i]))) { const gone = id !== run; closeCam(); return gone ? null : fail('Wajah Tidak Dikenali', 'Tes gerakan (liveness) tidak lolos atau wajah tidak terdeteksi.'); }
      prog((i + 1) / 4);
    }
    const d = await grab(id, 3), gone = id !== run; closeCam();
    if (gone) return;
    if (!d) return fail('Wajah Tidak Dikenali', 'Wajah tidak terdeteksi dengan jelas.');
    let best = { n: null, dist: 9 };
    for (const [n, u] of cands) { const dist = faceapi.euclideanDistance(d, Float32Array.from(u.desc)); if (dist < best.dist) best = { n, dist }; }
    if (best.dist < THRESHOLD) { fails = 0; me = best.n; sessionStorage.setItem('fs_me', me); $('#frame').classList.add('ok'); result(true, 'Verifikasi Berhasil', 'Selamat datang, ' + me + '.', 'Ke halaman utama', () => view('home'), 'Keluar', logout); setTimeout(() => !$('#v-res').classList.contains('hidden') && view('home'), 1800); }
    else { if (++fails >= 5) { lockUntil = Date.now() + 30000; fails = 0; } fail('Wajah Tidak Dikenali', 'Wajah tidak cocok dengan data yang terdaftar.'); }
  } catch (e) { closeCam(); fail('Tidak dapat memulai', errMsg(e)); }
}
$('#b-face').onclick = faceLogin;
$('#cam-x').onclick = () => { closeCam(); view(me ? 'home' : 'login'); };

// ---------- Halaman utama ----------
function home() {
  const u = users[me]; if (!u) return logout();
  $('#frame').classList.remove('ok'); $('#h-u').textContent = me;
  $('#h-f').textContent = u.faceOn ? '✔ Aktif' : '✖ Belum aktif';
  $('#h-s').textContent = u.faceOn ? 'Tinggi' : 'Sedang';
  $('#h-d').textContent = u.faceOn ? 'Face ID aktif dengan tes liveness. Kata sandi disimpan sebagai hash PBKDF2.' : 'Aktifkan Face ID agar login lebih cepat dan aman.';
  $('#h-en').textContent = u.faceOn ? 'Daftarkan ulang wajah' : 'Aktifkan Face ID'; $('#h-off').classList.toggle('hidden', !u.faceOn);
}
$('#h-en').onclick = enroll;
$('#h-off').onclick = () => { if (confirm('Hapus data wajah dan nonaktifkan Face ID?')) { users[me].desc = null; users[me].faceOn = false; store(); toast('Data wajah dihapus'); home(); } };
$('#h-del').onclick = () => { if (confirm('Hapus akun ini beserta semua datanya?')) { delete users[me]; store(); toast('Akun dihapus'); logout(); } };
function logout() { closeCam(); me = null; sessionStorage.removeItem('fs_me'); view('login'); }
$('#h-out').onclick = logout;
view(me && users[me] ? 'home' : 'login');