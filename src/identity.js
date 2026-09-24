// Личность устройства на кассира (graks, 2026-09-25).
//
// Kaspi видит каждый вход кассира как отдельный телефон: свои deviceId/installId,
// pinHash, ECDSA-ключ (pk/pkTag/X-Sign) и ECDH-ключ (vtoken). Раньше все кассиры
// делили одну личность из device.json/keypair.json, и вход одного кассира
// вытеснял сессию другого (StatusCode -101001).
//
// Личность рождается в POST /api/auth/init { newIdentity: true }, после входа
// отдаётся вызывающему зашифрованной строкой (тем же AES-256-GCM, что и
// vtokenSecret) и возвращается на каждом запросе в заголовке x-device-identity.
// Без заголовка мост работает на глобальной личности из файлов — старые сессии
// не ломаются.

import crypto from 'crypto';
import { DEVICE, ecKeyPair } from './config.js';
import { encryptSecret, decryptSecret } from './crypto.js';

export const IDENTITY_HEADER = 'x-device-identity';

const IDENTITY_VERSION = 1;
const DEFAULT_CLIENT_IP = '192.168.1.96';

const exportPair = (pair) => ({
  privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  publicKey: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
});

const importPrivate = (b64) =>
  crypto.createPrivateKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'pkcs8' });
const importPublic = (b64) => crypto.createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });

const publicKeyFields = (publicKey) => {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const pk = der.subarray(der.length - 65).toString('base64');
  return { pk, x509: der.toString('base64'), pkTag: crypto.createHash('md5').update(pk).digest('hex') };
};

/**
 * Рабочая форма личности: всё, что нужно для cookie, заголовков и подписи.
 * `stored` — хранимая форма (null у глобальной личности из файлов).
 */
const materialize = (stored) => {
  const ecPublicKey = importPublic(stored.ecdsa.publicKey);
  return {
    deviceId: stored.deviceId,
    installId: stored.installId,
    pinHash: stored.pinHash,
    clientIp: stored.clientIp || DEFAULT_CLIENT_IP,
    ...publicKeyFields(ecPublicKey),
    ecPrivateKey: importPrivate(stored.ecdsa.privateKey),
    ecPublicKey,
    ecdhPrivateKey: stored.ecdh ? importPrivate(stored.ecdh.privateKey) : null,
    ecdhX509: stored.ecdh ? stored.ecdh.publicKey : null,
    stored,
  };
};

/** Новый «телефон»: те же правила, что у первого запуска (config.js, scripts/regen-*.js). */
export const generateIdentity = () => {
  const stored = {
    v: IDENTITY_VERSION,
    deviceId: crypto.randomUUID().toUpperCase(),
    installId: crypto.randomUUID().toUpperCase(),
    pinHash: crypto.createHash('md5').update(crypto.randomBytes(16)).digest('hex'),
    clientIp: `192.168.1.${crypto.randomInt(2, 254)}`,
    ecdsa: exportPair(crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })),
    ecdh: exportPair(crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })),
  };
  return materialize(stored);
};

/** Личность → непрозрачная зашифрованная строка для хранения на стороне приложения. */
export const sealIdentity = (identity) => encryptSecret(Buffer.from(JSON.stringify(identity.stored), 'utf8'));

/** Обратное sealIdentity. Бросает на чужом ключе, порче или неизвестном формате. */
export const openIdentity = (sealed) => {
  const stored = JSON.parse(decryptSecret(String(sealed)).toString('utf8'));
  if (stored?.v !== IDENTITY_VERSION || !stored.deviceId || !stored.installId || !stored.ecdsa?.privateKey) {
    throw new Error('Unsupported device identity');
  }
  return materialize(stored);
};

/** Общая личность из device.json + keypair.json — поведение апстрима. */
export const GLOBAL_IDENTITY = Object.freeze({
  deviceId: DEVICE.deviceId,
  installId: DEVICE.installId,
  pinHash: DEVICE.pinHash,
  clientIp: DEFAULT_CLIENT_IP,
  pk: DEVICE.pk,
  x509: DEVICE.x509,
  pkTag: DEVICE.pkTag,
  ecPrivateKey: ecKeyPair.privateKey,
  ecPublicKey: ecKeyPair.publicKey,
  ecdhPrivateKey: null,
  ecdhX509: null,
  stored: null,
});

/**
 * Личность запроса: из x-device-identity или глобальная, если заголовка нет.
 * Испорченный заголовок — ошибка (молча подписывать чужой личностью нельзя:
 * Kaspi вытеснит сессию).
 */
export const identityFromHeaders = (req) => {
  const raw = req?.headers?.[IDENTITY_HEADER];
  if (!raw) return GLOBAL_IDENTITY;
  return openIdentity(raw);
};
