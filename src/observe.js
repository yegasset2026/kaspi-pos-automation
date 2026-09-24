/**
 * Наблюдаемость моста Kaspi (carwash_crm-d1fp) — копия
 * services/whatsapp-bridge/src/observe.js, порт lib/observe.ts на чистый JS.
 *
 * ВНИМАНИЕ: services/kaspi-pos — сторонний репозиторий, подключённый gitlink-ом
 * без .gitmodules, пушить в него нельзя. Этот файл и правки к нему хранятся
 * патчами в services/kaspi-pos-patches/ (см. docs/DEPLOY.md).
 *
 * До сих пор ошибки мостов жили только в stdout: при падении WhatsApp никто не
 * узнавал об этом, пока не заглянул в docker logs. Здесь тот же минимальный
 * репортёр, что и в Next-приложении: если задан SENTRY_DSN — событие уходит
 * конвертом обычным fetch-ем, если нет — остаётся в консоли. Зависимостей нет
 * намеренно: мост не должен тянуть @sentry/node ради одного вызова.
 *
 * Значения «секретных» ключей маскируются: в логи моста попадают номера
 * телефонов и тексты сообщений, и отдавать их наружу вместе с токенами нельзя.
 */

const SECRET_KEY_RE =
  /(token|secret|password|passwd|pwd|sign|signature|auth|cookie|session|apikey|api_key|key|pin|otp|code)/i;
const SAFE_KEY_RE = /^(x-request-id|request_id|requestid|idempotency-key|keyword|codebase)$/i;

export function redactSecrets(value, depth = 0) {
  if (value === null || value === undefined) return value;
  if (depth > 6) return '[deep]';
  if (Array.isArray(value)) return value.map((v) => redactSecrets(v, depth + 1));
  if (value instanceof Error) return { message: value.message, type: value.name };
  if (typeof value !== 'object') return value;
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = !SAFE_KEY_RE.test(k) && SECRET_KEY_RE.test(k) ? '***' : redactSecrets(v, depth + 1);
  }
  return out;
}

/** `https://<key>@<host>/<projectId>` → адрес конверта. */
export function parseSentryDsn(dsn) {
  if (!dsn) return null;
  let url;
  try {
    url = new URL(dsn);
  } catch {
    return null;
  }
  const publicKey = url.username;
  const projectId = url.pathname.replace(/^\//, '').replace(/\/$/, '');
  if (!publicKey || !projectId) return null;
  return { publicKey, projectId, envelopeUrl: `${url.protocol}//${url.host}/api/${projectId}/envelope/` };
}

export function describeError(err) {
  if (err instanceof Error) return { message: err.message, stack: err.stack ?? null, type: err.name || 'Error' };
  if (typeof err === 'string') return { message: err, stack: null, type: 'Error' };
  if (err === undefined || err === null) return { message: String(err), stack: null, type: 'Error' };
  try {
    return { message: JSON.stringify(err), stack: null, type: 'Error' };
  } catch {
    return { message: String(err), stack: null, type: 'Error' };
  }
}

function randomEventId() {
  let out = '';
  for (let i = 0; i < 32; i += 1) out += Math.floor(Math.random() * 16).toString(16);
  return out;
}

export function sentryEnvelope({ level, message, described, context, service }) {
  const eventId = randomEventId();
  const header = JSON.stringify({ event_id: eventId, sent_at: new Date().toISOString() });
  const itemHeader = JSON.stringify({ type: 'event' });
  const event = {
    event_id: eventId,
    timestamp: Date.now() / 1000,
    platform: 'node',
    level,
    logger: service,
    environment: process.env.SENTRY_ENVIRONMENT ?? process.env.NODE_ENV ?? 'development',
    message: described ? undefined : { formatted: message },
    exception: described ? { values: [{ type: described.type, value: described.message }] } : undefined,
    extra: redactSecrets({ ...(context ?? {}), stack: described?.stack ?? undefined }),
  };
  return `${header}\n${itemHeader}\n${JSON.stringify(event)}\n`;
}

const SERVICE = process.env.OBSERVE_SERVICE ?? 'kaspi-pos';

function send(level, message, described, context) {
  const safe = redactSecrets(context ?? {});
  const line = `[observe:${level}] ${message}`;
  if (level === 'error') console.error(line, safe);
  else if (level === 'warning') console.warn(line, safe);
  else console.info(line, safe);

  const dsn = parseSentryDsn(process.env.SENTRY_DSN);
  if (!dsn) return;
  // Fire-and-forget: наблюдаемость не должна ронять или задерживать отправку.
  fetch(dsn.envelopeUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-sentry-envelope',
      'X-Sentry-Auth': `Sentry sentry_version=7, sentry_client=graks/1.0, sentry_key=${dsn.publicKey}`,
    },
    body: sentryEnvelope({ level, message, described, context, service: SERVICE }),
    signal: AbortSignal.timeout(4000),
  }).catch(() => {});
}

export const observe = {
  error: (where, err, context) => {
    const described = describeError(err);
    send('error', `${where}: ${described.message}`, described, { where, ...context });
  },
  warn: (where, err, context) => {
    send('warning', `${where}: ${describeError(err).message}`, null, { where, ...context });
  },
  info: (where, context) => send('info', where, null, context),
};

/** Ставит обработчики, чтобы падение процесса тоже попадало в Sentry. */
export function installProcessHandlers() {
  process.on('unhandledRejection', (err) => observe.error('process:unhandledRejection', err));
  process.on('uncaughtException', (err) => {
    observe.error('process:uncaughtException', err);
    // Не выходим: единичный сбой запроса к Kaspi не повод ронять мост —
    // супервизор перезапустит по /health, если всё действительно плохо.
  });
}
