import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.env.TOKEN_SECRET_KEY = 'a'.repeat(64);
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kaspi-identity-'));
process.env.KASPI_TRACKED_FILE = path.join(tmpDir, 'tracked.json');
process.env.KASPI_RETRY_FILE = path.join(tmpDir, 'retries.json');

const { generateIdentity, sealIdentity, openIdentity, identityFromHeaders, GLOBAL_IDENTITY, IDENTITY_HEADER } =
  await import('../src/identity.js');
const { DEVICE, ecKeyPair } = await import('../src/config.js');
const { signedQrPayHeaders, entranceCookie } = await import('../src/helpers.js');
const { encryptSecret } = await import('../src/crypto.js');
const { trackPayment, sessionFromTracked, getTrackedPayments } = await import('../src/polling.js');

after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

const XSH_NAMES = [
  'url',
  'X-Install-ID',
  'X-PI',
  'X-App-Bld',
  'X-Platform-Ver',
  'X-Locale',
  'X-App-Ver',
  'X-Device-ID',
  'X-SV',
  'X-Time',
  'X-Platform-Type',
  'X-Call',
  'X-Kb-TokenSnMac',
  'X-Kb-TokenSn',
];

const verifyXSign = (publicKey, url, h, body) => {
  const text =
    XSH_NAMES.map((n) => (n === 'url' ? `url:${url.toLowerCase()}` : `${n.toLowerCase()}:${h[n] || ''}`)).join('\n') +
    (body ? '\n' + body : '');
  const hash = crypto.createHash('sha256').update(text, 'utf8').digest();
  const v = crypto.createVerify('SHA256');
  v.update(hash);
  v.end();
  return v.verify(publicKey, Buffer.from(h['X-Sign'], 'base64'));
};

const session = (extra = {}) => ({ tokenSN: 'TSN1', decryptedSecret: Buffer.alloc(16, 1), profileId: '42', ...extra });

describe('generateIdentity', () => {
  it('каждый вызов — новый телефон: свои deviceId, installId, pinHash, ключи', () => {
    const a = generateIdentity();
    const b = generateIdentity();
    for (const k of ['deviceId', 'installId', 'pinHash', 'pk', 'pkTag', 'x509', 'ecdhX509']) {
      assert.notEqual(a[k], b[k], k);
    }
    assert.match(a.deviceId, /^[0-9A-F-]{36}$/);
    assert.match(a.pinHash, /^[0-9a-f]{32}$/);
    assert.equal(a.pkTag, crypto.createHash('md5').update(a.pk).digest('hex'));
    assert.equal(Buffer.from(a.pk, 'base64').length, 65, 'несжатая точка P-256');
    assert.notEqual(a.deviceId, DEVICE.deviceId);
  });
});

describe('sealIdentity / openIdentity', () => {
  it('шифрованная строка возвращает ту же личность', () => {
    const id = generateIdentity();
    const sealed = sealIdentity(id);
    assert.ok(!sealed.includes(id.deviceId), 'в открытом виде личность не видна');
    const back = openIdentity(sealed);
    for (const k of ['deviceId', 'installId', 'pinHash', 'pk', 'pkTag', 'x509', 'ecdhX509', 'clientIp']) {
      assert.equal(back[k], id[k], k);
    }
    const sig = crypto.sign('SHA256', Buffer.from('x'), back.ecPrivateKey);
    assert.ok(crypto.verify('SHA256', Buffer.from('x'), id.ecPublicKey, sig), 'ключ подписи сохранился');
  });

  it('испорченная или чужая строка не открывается', () => {
    const buf = Buffer.from(sealIdentity(generateIdentity()), 'base64');
    buf[40] ^= 0xff;
    assert.throws(() => openIdentity(buf.toString('base64')));
    assert.throws(() => openIdentity(encryptSecret(Buffer.from('{"v":1}'))));
  });
});

describe('identityFromHeaders', () => {
  it('без заголовка — общая личность из файлов', () => {
    assert.equal(identityFromHeaders({ headers: {} }), GLOBAL_IDENTITY);
    assert.equal(GLOBAL_IDENTITY.pkTag, DEVICE.pkTag);
  });

  it('с заголовком — личность кассира', () => {
    const id = generateIdentity();
    const got = identityFromHeaders({ headers: { [IDENTITY_HEADER]: sealIdentity(id) } });
    assert.equal(got.deviceId, id.deviceId);
    assert.equal(got.pkTag, id.pkTag);
  });

  it('мусор в заголовке — ошибка, а не молчаливый откат на общую личность', () => {
    assert.throws(() => identityFromHeaders({ headers: { [IDENTITY_HEADER]: 'garbage' } }));
  });
});

describe('подпись запросов личностью кассира', () => {
  const url = 'https://qrpay.kaspi.kz/v01/remote/create';
  const body = JSON.stringify({ Amount: 5 });

  it('с личностью: её deviceId/installId и X-Sign её ключом', () => {
    const id = generateIdentity();
    const h = signedQrPayHeaders(url, session({ identity: id }), body);
    assert.equal(h['X-Device-ID'], id.deviceId);
    assert.equal(h['X-Install-ID'], id.installId);
    assert.ok(verifyXSign(id.ecPublicKey, url, h, body));
    assert.ok(!verifyXSign(ecKeyPair.publicKey, url, h, body), 'не общим ключом');
  });

  it('без личности: общий deviceId и общий ключ', () => {
    const h = signedQrPayHeaders(url, session(), body);
    assert.equal(h['X-Device-ID'], DEVICE.deviceId);
    assert.ok(verifyXSign(ecKeyPair.publicKey, url, h, body));
  });

  it('cookie входа несёт pk/pkTag личности', () => {
    const id = generateIdentity();
    const c = entranceCookie(null, id);
    assert.ok(c.includes(`deviceId=${id.deviceId}`));
    assert.ok(c.includes(`pkTag=${id.pkTag}`));
    assert.ok(entranceCookie().includes(`pkTag=${DEVICE.pkTag}`));
  });
});

describe('поллинг хранит личность платежа', () => {
  it('личность пишется в файл и после перезапуска подписывает статус тем же ключом', () => {
    const id = generateIdentity();
    const sealed = sealIdentity(id);
    const vtokenSecret = encryptSecret(Buffer.alloc(16, 2));
    trackPayment('9001', 'invoice', { tokenSN: 'TSN9', vtokenSecret, profileId: '7', deviceIdentity: sealed });

    const onDisk = JSON.parse(fs.readFileSync(process.env.KASPI_TRACKED_FILE, 'utf8'));
    assert.equal(onDisk['9001'].sessionHeaders.deviceIdentity, sealed);
    assert.ok(!JSON.stringify(onDisk).includes(id.deviceId), 'на диске только шифрованная форма');

    const restored = sessionFromTracked(onDisk['9001'].sessionHeaders);
    assert.equal(restored.identity.deviceId, id.deviceId);
    const statusUrl = 'https://qrpay.kaspi.kz/v02/remote/details?operationId=9001';
    const h = signedQrPayHeaders(statusUrl, restored);
    assert.ok(verifyXSign(id.ecPublicKey, statusUrl, h));
    assert.ok(getTrackedPayments()['9001']);
  });

  it('платёж старой сессии без личности — общая личность', () => {
    const restored = sessionFromTracked({
      tokenSN: 'T',
      vtokenSecret: encryptSecret(Buffer.alloc(16, 3)),
      profileId: '1',
    });
    assert.equal(restored.identity, undefined);
    assert.equal(signedQrPayHeaders('https://x/y', restored)['X-Device-ID'], DEVICE.deviceId);
  });
});
