import crypto from 'crypto';
import fetch from 'node-fetch';
import { DEVICE, APP, UA_NATIVE } from './config.js';
import { computeTokenSnMac, computeXSign } from './crypto.js';

// ─── Utilities ───

export const generateUUID = () => crypto.randomUUID().toUpperCase();

export const nowISO = () => {
  const d = new Date();
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? '+' : '-';
  const hh = String(Math.floor(Math.abs(off) / 60)).padStart(2, '0');
  const mm = String(Math.abs(off) % 60).padStart(2, '0');
  return (
    d
      .toISOString()
      .replace('Z', '')
      .replace(/\.\d{3}/, `.${String(d.getMilliseconds()).padStart(3, '0')}`) +
    sign +
    hh +
    mm
  );
};

// ─── Cookie builder ───

export const entranceCookie = (extraUserToken) => {
  let c = `deviceId=${DEVICE.deviceId}; installId=${DEVICE.installId}; is_mobile_app=true; locale=${APP.locale}; ma_bld=${APP.build}; ma_platform_type=${APP.platform}; ma_platform_ver=${APP.platformVer}; ma_ver=${APP.version}; pk=${DEVICE.pk}; pkTag=${DEVICE.pkTag}; xs=R:0|E:0|RH:0|N:0`;
  if (extraUserToken) c += `; user_token=${extraUserToken}`;
  return c;
};

// ─── Extract user_token from set-cookie ───

export const extractUserToken = (resp) => {
  const raw = resp.headers.raw()['set-cookie'] || [];
  for (const c of raw) {
    const m = c.match(/user_token=([^;]+)/);
    if (m) return m[1];
  }
  return null;
};

// ─── Redaction ───
// Логи моста собираются pm2/docker/облаком, поэтому подписи и токены кассира в
// stdout попадать не должны (carwash_crm-yrbz). Маскируем по имени ключа.

const SECRET_KEY_RE =
  /(token|secret|password|sign|signature|auth|cookie|session|vtoken|mac|key|pin|otp|code|qr)/i;
const SAFE_KEY_RE = /^(x-request-id|x-call|x-sv|x-sh|x-locale|x-time)$/i;

export const redactSecrets = (value, depth = 0) => {
  if (value === null || value === undefined) return value;
  if (depth > 6) return '[deep]';
  if (Array.isArray(value)) return value.map((v) => redactSecrets(v, depth + 1));
  if (typeof value !== 'object') return value;
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = !SAFE_KEY_RE.test(k) && SECRET_KEY_RE.test(k) ? '***' : redactSecrets(v, depth + 1);
  }
  return out;
};

/** URL без значений «секретных» query-параметров. */
export const redactUrl = (url) => {
  try {
    const u = new URL(url);
    for (const key of [...u.searchParams.keys()]) {
      if (SECRET_KEY_RE.test(key)) u.searchParams.set(key, '***');
    }
    return u.toString();
  } catch {
    return String(url).split('?')[0];
  }
};

// ─── Logged fetch wrapper ───
// Печатаем метод/URL/статус и замаскированные тела; заголовки (X-Kb-TokenSn,
// X-Kb-TokenSnMac, X-Sign, Cookie с user_token) в лог не идут вовсе.

export const loggedFetch = async (url, options = {}) => {
  const method = (options.method || 'GET').toUpperCase();
  console.log(`\n>>> ${method} ${redactUrl(url)}`);
  if (options.body) {
    try {
      console.log('>>> Body:', JSON.stringify(redactSecrets(JSON.parse(options.body))));
    } catch {
      console.log('>>> Body: [raw, not logged]');
    }
  }

  const resp = await fetch(url, options);
  const cloned = resp.clone();
  let body;
  try {
    body = await cloned.json();
  } catch {
    try {
      body = await cloned.text();
    } catch {
      body = '[unreadable]';
    }
  }
  console.log(`<<< ${resp.status} ${resp.statusText}`);
  console.log(
    '<<< Response:',
    typeof body === 'object' ? JSON.stringify(redactSecrets(body), null, 2) : '[text, not logged]',
  );
  return resp;
};

// ─── Signed QR-pay headers (session passed as parameter) ───

export const signedQrPayHeaders = (url, session, body) => {
  const xsh =
    'url,X-Install-ID,X-PI,X-App-Bld,X-Platform-Ver,X-Locale,X-App-Ver,X-Device-ID,X-SV,X-Time,X-Platform-Type,X-Call,X-Kb-TokenSnMac,X-Kb-TokenSn';
  const headers = {
    'X-Kb-TokenSn': session.tokenSN,
    'X-Kb-TokenSnMac': computeTokenSnMac(session.tokenSN, session.decryptedSecret),
    'X-PI': session.profileId != null ? String(session.profileId) : '',
    'X-Install-ID': DEVICE.installId,
    'X-Device-ID': DEVICE.deviceId,
    'X-App-Ver': APP.version,
    'X-App-Bld': APP.build,
    'X-Platform-Type': APP.platform,
    'X-Platform-Ver': APP.platformVer,
    'X-Locale': APP.locale,
    'X-Time': nowISO(),
    'X-Request-ID': generateUUID(),
    'X-Call': 'notConnected',
    'X-SV': '2',
    'X-SH': xsh,
    'User-Agent': UA_NATIVE,
    Accept: '*/*',
    'Accept-Language': 'ru',
    'Accept-Encoding': 'gzip, deflate, br',
  };
  headers['X-Sign'] = computeXSign(url, headers, xsh, body);
  return headers;
};
