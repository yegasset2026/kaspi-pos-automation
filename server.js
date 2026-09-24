import express from 'express';
import path from 'path';
import { PORT, ROOT_DIR } from './src/config.js';
import authRoutes from './src/routes/auth.js';
import invoiceRoutes from './src/routes/invoice.js';
import qrRoutes from './src/routes/qr.js';
import historyRoutes from './src/routes/history.js';
import refundRoutes from './src/routes/refund.js';
import sessionRoutes from './src/routes/session.js';
import { startPolling } from './src/polling.js';
import { installProcessHandlers } from './src/observe.js';
import 'dotenv/config';

// Ошибки моста уходят в Sentry (SENTRY_DSN), а не только в stdout
// (carwash_crm-d1fp).
installProcessHandlers();

const app = express();

app.use(express.json());
app.use(express.static(path.join(ROOT_DIR, 'public')));

const startedAt = Date.now();

// Health-check для супервизора (docker HEALTHCHECK / pm2 / Caddy).
app.get('/health', (req, res) => res.json({
  status:    'ok',
  service:   'kaspi-pos',
  uptimeSec: Math.round((Date.now() - startedAt) / 1000),
}));

app.use('/api/auth', authRoutes);
app.use('/api/invoice', invoiceRoutes);
app.use('/api/qr', qrRoutes);
app.use('/api/history', historyRoutes);
app.use('/api/refund', refundRoutes);
app.use('/api/session', sessionRoutes);

// В проде мост слушает только петлю: наружу его выпускать нельзя (carwash_crm-7cls).
const HOST = process.env.KASPI_BRIDGE_HOST ?? '0.0.0.0';

const server = app.listen(PORT, HOST, () => {
  console.log(`\n  🟢 Kaspi Pay App running at http://${HOST}:${PORT}\n`);
  startPolling();
});

let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n  ⏹  Kaspi bridge: ${signal} — завершаем работу…`);
  const force = setTimeout(() => process.exit(0), 10_000);
  force.unref();
  server.close(() => process.exit(0));
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
