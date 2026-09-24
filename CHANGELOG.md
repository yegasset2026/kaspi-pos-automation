# Changelog

Все заметные изменения в проекте документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/),
проект придерживается [Semantic Versioning](https://semver.org/lang/ru/).

## [graks] - 2026-09-24 — ветка Teper поверх апстрима 28c9167

Форк `yegasset2026/kaspi-pos-automation`, ветка `graks` = апстрим
`tapter-dev/kaspi-pos-automation@28c9167` (2026-07-24) + наши правки.
Подключён к `teper` как подмодуль `services/kaspi-pos`. Обновление от автора:
`git fetch upstream && git rebase upstream/main`.

Апстрим 28c9167 принёс: отпечаток iPhone16,2 / iOS 18.4, версию `4.112.1`/`1107`
(вход кассира падал с `OldVersionToUpdate`), подпись `X-Sign` с телом запроса,
поллинг счёта по `Data.QrOperationId`, Unified QR, вебхук `payment.lost`,
удалён `POST /api/auth/refresh`. Живой вход, счета, отмены проверены 2026-09-24.

### Наши правки

- `src/config.js` — версия приложения `26.0921`, сборка `2609210` (2026-09-25): Kaspi перешёл на нумерацию
  год.ММДД и отсёк `4.112.1` ответом «Обновите приложение, чтобы войти». Подбор: `POST /api/auth/init`
  с новыми `APP_VERSION`/`APP_BUILD` в env до ответа `sn: EnterPhoneNumber`.

- `src/observe.js` + `installProcessHandlers` — ошибки в Sentry по `SENTRY_DSN`, без зависимостей.
- `server.js` — расширенный `/health`, `KASPI_BRIDGE_HOST`, мягкое завершение по SIGTERM/SIGINT.
- `src/helpers.js` — маскирование секретов в логах `loggedFetch`.
- `.env.example` — актуальные значения устройства.
- `test/xsign.test.js` — формат подписи `computeXSign`, `signedQrPayHeaders` с телом, константы устройства.

## [1.0.0] - 2025-05-09

### Добавлено

- Серверное приложение на Express для автоматизации Kaspi Pay POS.
- 3-шаговая SMS-авторизация (init → send-phone → verify-otp).
- Создание счетов и генерация QR-кодов.
- Просмотр истории транзакций.
- Оформление возвратов.
- Веб-интерфейс (SPA) в `public/`.
- ECDH/ECDSA криптография и TOTP-генерация.
- AES-256-GCM шифрование `vtokenSecret`.
- Поллинг статусов платежей с вебхук-уведомлениями.
- Скрипты ротации ключей (`regen:keypair`, `regen:device`).
- Файловое и консольное логирование.
- Подготовка к open source: SECURITY.md, CONTRIBUTING.md, LICENSE (MIT), GitHub-шаблоны, ESLint, Prettier, EditorConfig, CI.
