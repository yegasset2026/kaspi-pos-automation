import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

process.env.TOKEN_SECRET_KEY = 'a'.repeat(64);

const { computeXSign } = await import('../src/crypto.js');
const { ecKeyPair, APP } = await import('../src/config.js');
const { signedQrPayHeaders } = await import('../src/helpers.js');

const verify = (signText, signatureB64) => {
  const hash = crypto.createHash('sha256').update(signText, 'utf8').digest();
  const v = crypto.createVerify('SHA256');
  v.update(hash);
  v.end();
  return v.verify(ecKeyPair.publicKey, Buffer.from(signatureB64, 'base64'));
};

describe('computeXSign (протокол апстрима 468668e)', () => {
  const url = 'https://qrpay.kaspi.kz/V01/Remote/Create';
  const headers = { 'X-Time': '2026-01-01T00:00:00+05:00', 'X-SV': '2' };
  const xsh = 'url,X-Time,X-SV,X-Missing';

  it('подписывает "имя:значение" построчно, url в нижнем регистре, без тела', () => {
    const sig = computeXSign(url, headers, xsh);
    const text = `url:${url.toLowerCase()}\nx-time:${headers['X-Time']}\nx-sv:2\nx-missing:`;
    assert.ok(verify(text, sig));
  });

  it('включает тело запроса последней строкой', () => {
    const body = JSON.stringify({ Amount: 100 });
    const sig = computeXSign(url, headers, xsh, body);
    const text = `url:${url.toLowerCase()}\nx-time:${headers['X-Time']}\nx-sv:2\nx-missing:\n${body}`;
    assert.ok(verify(text, sig));
    assert.ok(!verify(text.replace('100', '101'), sig));
  });
});

describe('signedQrPayHeaders', () => {
  const session = { tokenSN: 'TSN1', decryptedSecret: Buffer.alloc(16, 1), profileId: '42' };

  it('X-Sign покрывает перечисленные заголовки и тело', () => {
    const url = 'https://qrpay.kaspi.kz/v01/remote/create';
    const body = JSON.stringify({ Amount: 5 });
    const h = signedQrPayHeaders(url, session, body);
    const names = [
      'url', 'X-Install-ID', 'X-PI', 'X-App-Bld', 'X-Platform-Ver', 'X-Locale', 'X-App-Ver', 'X-Device-ID',
      'X-SV', 'X-Time', 'X-Platform-Type', 'X-Call', 'X-Kb-TokenSnMac', 'X-Kb-TokenSn',
    ];
    const text =
      names.map((n) => (n === 'url' ? `url:${url}` : `${n.toLowerCase()}:${h[n] || ''}`)).join('\n') + '\n' + body;
    assert.ok(verify(text, h['X-Sign']));
    assert.equal(h['X-App-Ver'], APP.version);
    assert.equal(h['X-App-Bld'], APP.build);
  });
});

describe('APP defaults — версия 26.0921 (Kaspi отсёк 4.112.1 25.09.2026)', () => {
  it('iPhone 15 Pro Max / iOS 18.4', { skip: !!process.env.APP_VERSION || !!process.env.APP_MODEL }, () => {
    assert.equal(APP.version, '26.0921');
    assert.equal(APP.build, '2609210');
    assert.equal(APP.model, 'iPhone16,2');
    assert.equal(APP.platformVer, '18.4');
    assert.equal(APP.screenW, '430.0');
    assert.equal(APP.screenH, '932.0');
    assert.equal(APP.darwin, 'Darwin/24.4.0');
  });
});
