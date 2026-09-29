'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SRC = path.resolve(__dirname, '..', 'zts-map.html');
const OUT_INDEX = path.join(__dirname, 'index.html');
const OUT_MAP = path.join(__dirname, 'zts-map.html');
const PASS_FILE = path.join(__dirname, '..', '.publish-passphrase');

const ITERATIONS = 600000;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function generatePassphrase() {
  const bytes = crypto.randomBytes(20);
  const chars = [...bytes].map((b) => ALPHABET[b % ALPHABET.length]);
  return [0, 5, 10, 15].map((i) => chars.slice(i, i + 5).join('')).join('-');
}

function loadPassphrase() {
  if (fs.existsSync(PASS_FILE)) {
    const mode = fs.statSync(PASS_FILE).mode & 0o777;
    if (mode !== 0o600) {
      fs.chmodSync(PASS_FILE, 0o600);
      console.log(`passphrase file mode tightened to 0600 (was 0${mode.toString(8)})`);
    }
    return fs.readFileSync(PASS_FILE, 'utf8').trim();
  }
  const pass = generatePassphrase();
  fs.writeFileSync(PASS_FILE, pass + '\n', { mode: 0o600 });
  console.log('generated new passphrase -> ' + PASS_FILE + ' (mode 0600)');
  return pass;
}

function extractData(html) {
  const lineStart = html.indexOf('\nconst DATA = ');
  if (lineStart < 0) throw new Error('DATA line not found');
  const contentStart = lineStart + '\nconst DATA = '.length;
  const lineEnd = html.indexOf('\n', contentStart);
  if (lineEnd < 0) throw new Error('DATA line has no terminator');
  const statement = html.slice(contentStart, lineEnd);
  const json = statement.replace(/;\s*$/, '');
  JSON.parse(json);
  return { lineStart, lineEnd, json };
}

function seal(pass, json) {
  const salt = crypto.randomBytes(SALT_BYTES);
  const nonce = crypto.randomBytes(NONCE_BYTES);
  const key = crypto.pbkdf2Sync(pass, salt, ITERATIONS, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(json, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const blob = Buffer.concat([salt, nonce, ciphertext, tag]);
  return {
    blob: blob.toString('base64'),
    verify: () => {
      const raw = Buffer.from(blob.toString('base64'), 'base64');
      const saltLen = SALT_BYTES;
      const nonceLen = NONCE_BYTES;
      const dKey = crypto.pbkdf2Sync(pass, raw.subarray(0, saltLen), ITERATIONS, 32, 'sha256');
      const d = crypto.createDecipheriv('aes-256-gcm', dKey, raw.subarray(saltLen, saltLen + nonceLen));
      d.setAuthTag(raw.subarray(raw.length - TAG_BYTES));
      return Buffer.concat([d.update(raw.subarray(saltLen + nonceLen, raw.length - TAG_BYTES)), d.final()]).toString('utf8');
    }
  };
}

const CSS = `
<style id="lock-style">
  #lock { position: fixed; inset: 0; z-index: 99999; background: #0b1c30;
          display: flex; align-items: center; justify-content: center; padding: 20px; }
  #lock .card { background: #11263f; border: 1px solid #23486f; border-radius: 12px;
                padding: 26px 22px; width: 100%; max-width: 380px; text-align: center; }
  #lock h1 { margin: 0 0 6px; font-size: 19px; color: #eaf2fb; }
  #lock p { margin: 0 0 18px; font-size: 12.5px; color: #9fc0e0; line-height: 1.5; }
  #lock input { width: 100%; box-sizing: border-box; padding: 11px 12px; font-size: 16px;
                letter-spacing: 1px; text-transform: uppercase; text-align: center;
                background: #08172a; color: #eaf2fb; border: 1px solid #2d5a86; border-radius: 7px; }
  #lock input:focus { outline: none; border-color: #4b90d9; }
  #lock button { margin-top: 12px; width: 100%; padding: 11px; font-size: 15px; font-weight: 600;
                 color: #fff; background: #1668b3; border: 0; border-radius: 7px; cursor: pointer; }
  #lock button:hover { background: #1b7ad0; }
  #lock .msg { min-height: 17px; margin-top: 11px; font-size: 12.5px; color: #ff8f8f; }
  #lock .hint { margin-top: 14px; font-size: 11px; color: #6f92b4; }
</style>`;

const MARKUP = `
<div id="lock">
  <form class="card" id="lockForm" autocomplete="off">
    <h1>Fleet Map</h1>
    <p>Dane floty są zaszyfrowane.<br>Wpisz hasło, aby odblokować mapę.</p>
    <input type="password" id="lockPass" placeholder="HASŁO" inputmode="latin" autocapitalize="characters" autocorrect="off" spellcheck="false" required>
    <button type="submit">Odblokuj</button>
    <div class="msg" id="lockMsg"></div>
    <div class="hint">Połączenie szyfrowane (HTTPS) &middot; 600 000 iteracji PBKDF2 / AES-256-GCM</div>
  </form>
</div>`;

function buildUnlockJs(blob) {
  return `
const ZTS_BLOB = "${blob}";
const ZTS_ITER = ${ITERATIONS};
function ztsBytes(b64) {
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
async function ztsDecrypt(pass) {
  const raw = ztsBytes(ZTS_BLOB);
  const salt = raw.subarray(0, 16);
  const nonce = raw.subarray(16, 28);
  const sealed = raw.subarray(28);
  const material = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: ZTS_ITER, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, sealed);
  return JSON.parse(new TextDecoder().decode(plain));
}
`;
}

function buildUnlockHandlers() {
  return `
(function () {
  const form = document.getElementById('lockForm');
  const input = document.getElementById('lockPass');
  const msg = document.getElementById('lockMsg');
  if (window.crypto && crypto.subtle) {
    form.addEventListener('submit', async function (ev) {
      ev.preventDefault();
      msg.textContent = '';
      msg.style.color = '#9fc0e0';
      const pass = input.value.trim().toUpperCase();
      if (!pass) return;
      const btn = form.querySelector('button');
      btn.disabled = true;
      btn.textContent = 'Sprawdzam…';
      try {
        const data = await ztsDecrypt(pass);
        document.getElementById('lock').remove();
        boot(data);
      } catch (err) {
        msg.style.color = '#ff8f8f';
        msg.textContent = 'Nieprawidłowe hasło';
        input.select();
      } finally {
        btn.disabled = false;
        btn.textContent = 'Odblokuj';
      }
    });
  } else {
    msg.style.color = '#ff8f8f';
    msg.textContent = 'Ta przeglądarka nie udostępnia WebCrypto — otwórz mapę przez HTTPS.';
  }
  input.focus();
})();
`;
}

function main() {
  const pass = loadPassphrase();
  const html = fs.readFileSync(SRC, 'utf8');

  const headClosed = html.indexOf('</head>');
  if (headClosed < 0) throw new Error('</head> not found');
  const bodyOpen = html.indexOf('<body>');
  if (bodyOpen < 0) throw new Error('<body> not found');

  const { lineStart, lineEnd, json } = extractData(html);
  const { blob, verify } = seal(pass, json);
  if (verify() !== json) throw new Error('round-trip verification failed');

  const scriptOpen = html.lastIndexOf('<script>', lineStart);
  const scriptClose = html.indexOf('</script>', lineEnd);
  if (scriptOpen < 0 || scriptClose < 0) throw new Error('map script block not found');

  const preamble = html.slice(0, scriptOpen);
  const rest = html.slice(lineEnd + 1, scriptClose);
  const tail = html.slice(scriptClose + '</script>'.length);
  if (preamble.trimEnd().endsWith('<script>')) throw new Error('preamble still holds an open <script> tag');
  if (rest.includes('</script')) throw new Error('script body contains an early </script>');

  const locked =
    preamble.replace('</head>', CSS + '</head>')
      .replace('<body>', MARKUP + '<body>') +
    '<script>\n' + buildUnlockJs(blob) + '</script>\n' +
    '<script>\nfunction boot(DATA) {\n' + rest + '\n}\n' + buildUnlockHandlers() + '</script>\n' + tail;

  if (!/function boot\(/.test(locked)) throw new Error('boot() wrapper missing');
  if (/const DATA = \{/.test(locked)) throw new Error('plaintext DATA still present');
  if (/drogomir|arcelormittal|cookie/i.test(locked)) throw new Error('unexpected upstream reference');

  const out = locked.replace('<head>', '<head>\n<meta name="robots" content="noindex, nofollow">');
  fs.writeFileSync(OUT_MAP, out, 'utf8');
  fs.writeFileSync(OUT_INDEX,
    '<!doctype html>\n<html lang="pl">\n<head>\n<meta charset="utf-8">\n' +
    '<meta name="robots" content="noindex, nofollow">\n' +
    '<title>Fleet Map</title>\n<meta http-equiv="refresh" content="0; url=zts-map.html">\n' +
    '</head>\n<body><p><a href="zts-map.html">Fleet Map</a></p></body>\n</html>\n', 'utf8');

  console.log('locked build written');
  console.log('  plaintext DATA : ' + (json.length / 1024).toFixed(0) + ' KB');
  console.log('  ciphertext     : ' + (blob.length / 1024).toFixed(0) + ' KB base64');
  console.log('  zts-map.html   : ' + (out.length / 1024).toFixed(0) + ' KB');
  console.log('  passphrase     : ' + PASS_FILE + ' (not printed)');
}

main();
