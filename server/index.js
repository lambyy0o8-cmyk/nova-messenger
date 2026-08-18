const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Server } = require('socket.io');
const { loadState, saveState, saveStateNow, STICKERS_DIR, APPS_DIR, useRemoteStore } = require('./store');
const { registerCallHandlers } = require('./calls');

const app = express();
const server = http.createServer(app);
// По умолчанию Socket.IO режет любое сообщение крупнее ~1MB — этого не
// хватит для пересылки файлов/документов (до 15MB, см. message:send).
// Поднимаем лимit движка до 20MB (с запасом на base64-раздувание ~+33%).
const io = new Server(server, { maxHttpBufferSize: 20 * 1024 * 1024 });

app.use(express.static(path.join(__dirname, '..', 'public')));
// Файлы кастомных стикеров лежат вне папки проекта (см. store.js,
// STICKERS_DIR рядом со store.json), поэтому раздаём их отдельным
// статическим маршрутом, а не из public/.
app.use('/stickers', express.static(STICKERS_DIR));
// HTML мини-приложений — тоже вне папки проекта (см. store.js, APPS_DIR).
// Клиент всегда открывает эти файлы только внутри
// <iframe sandbox="allow-scripts"> без allow-same-origin (см. app.js) —
// поэтому даже раздача с того же origin не даёт коду приложения доступ
// к cookie/localStorage/DOM самого мессенджера.
//
// Раньше это была простая express.static(APPS_DIR) — но на хостингах с
// эфемерным диском (например, бесплатный план Render) файл на диске не
// переживает передеплой/перезапуск контейнера, даже если сам стор в
// удалённом режиме (Upstash) и карточка приложения в чате не потерялась.
// Получался 404 на уже отправленные ранее приложения.
//
// Поэтому теперь: (1) при создании приложения его HTML дублируется в
// appMeta.html, который уходит в общий стор (persist()) — в удалённом
// режиме это значит, что HTML тоже лежит в Redis и переживает передеплой;
// (2) при запросе файла сперва пробуем отдать его с диска (быстрый путь,
// без похода в память), а если файла нет — отдаём HTML из appMeta и заодно
// восстанавливаем файл на диске (самовосстановление кэша на диске).
app.get('/apps/:id.html', (req, res) => {
  const { id } = req.params;
  const filePath = path.join(APPS_DIR, `${id}.html`);
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
    return;
  }
  const appMeta = miniApps.get(id);
  if (!appMeta || typeof appMeta.html !== 'string') {
    res.status(404).send('Приложение не найдено.');
    return;
  }
  res.type('html').send(appMeta.html);
  // Восстанавливаем файл на диске "по требованию", чтобы следующий запрос
  // пошёл быстрым путём выше. Ошибку (например, диск снова эфемерный и
  // доступен только на чтение в рантайме) просто игнорируем — не критично.
  try {
    fs.mkdirSync(APPS_DIR, { recursive: true });
    fs.writeFileSync(filePath, appMeta.html, 'utf8');
  } catch (err) { /* диск может быть недоступен для записи — не страшно */ }
});
// JSON-тело для HTTP API ботов (см. раздел "Bot API" ниже).
app.use(express.json({ limit: '256kb' }));

// ------------------------------------------------------------------
// In-memory state (без базы данных, как и в исходном проекте)
// ------------------------------------------------------------------

// accounts: accountId (= novaId) -> { id, name, username, novaId, color, passwordHash }
// Аккаунт живёт, пока жив процесс сервера (без БД). Идентичность аккаунта
// теперь — юзернейм + пароль, а не браузер/устройство: войти в аккаунт
// можно с любого устройства, если знаешь логин и пароль (как в обычном
// мессенджере), а не только с того браузера, где он был создан.
const accounts = new Map();
const usedNovaIds = new Set();
const usedUsernames = new Map(); // normalized (lowercase) username -> accountId
// Email обязателен при регистрации и тоже уникален на весь сервер — им
// можно пользоваться как альтернативным логином вместо юзернейма (см.
// auth:login). Ключ — нормализованный (lowercase, без пробелов) email.
const usedEmails = new Map(); // normalized email -> accountId

const USERNAME_RE = /^[A-Za-z][A-Za-z0-9_]{4,31}$/; // 5-32 символа, начинается с буквы
const NAME_MAX = 24;
const BIO_MAX = 140;
// Намеренно простая, не RFC-полная проверка формата — она отсекает явный
// мусор, а окончательное подтверждение того, что адрес существует и
// принадлежит пользователю, даёт переход по ссылке из письма.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function normalizeUsername(u) {
  return (u || '').toString().trim().replace(/^@/, '').toLowerCase();
}

function normalizeEmail(e) {
  return (e || '').toString().trim().toLowerCase();
}

function validateEmail(rawEmail) {
  const trimmed = (rawEmail || '').toString().trim();
  if (!trimmed) return { error: 'Укажи email.' };
  if (trimmed.length > 254 || !EMAIL_RE.test(trimmed)) {
    return { error: 'Похоже, это не email. Проверь формат (например, name@example.com).' };
  }
  return { value: trimmed, normalized: normalizeEmail(trimmed) };
}

// Идентификатор для входа (auth:login) может быть либо юзернеймом, либо
// email — определяем по наличию "@": в юзернеймах, в отличие от email,
// он невозможен (см. USERNAME_RE), так что путаницы не возникает.
function looksLikeEmail(raw) {
  return (raw || '').toString().includes('@');
}

// Юзернеймы, которые всегда получают галочку "подтверждён" — служебные/
// тестовые аккаунты (@admin, @tester). Сверяем по normalizeUsername,
// так что регистр значения не имеет.
const AUTO_VERIFIED_USERNAMES = new Set(['admin', 'tester']);

const socketToAccount = new Map(); // socket.id -> accountId (текущее соединение)
const accountSockets = new Map();  // accountId -> Set<socket.id> (для статуса "в сети", вход с нескольких устройств)

// ------------------------------------------------------------------
// Сессии для "остаться в аккаунте": при входе/регистрации выдаём
// случайный токен, клиент хранит его в cookie (не в localStorage) и
// при следующем открытии страницы присылает обратно — так аккаунт
// не слетает после перезагрузки/закрытия вкладки. Токен живёт, пока
// жив процесс сервера (без БД), либо до явного выхода из аккаунта.
// ------------------------------------------------------------------
const sessions = new Map(); // token -> accountId
const socketToToken = new Map(); // socket.id -> token (для logout текущей сессии)

// Незавершённая настройка 2FA: accountId -> base32-секрет. Живёт только
// в памяти (не персистится) — если сервер перезапустится посреди
// настройки, человек просто откроет экран настройки заново, ничего
// страшного. Секрет попадает в постоянное хранилище (account.twoFactorSecret)
// только после успешного подтверждения кодом с телефона.
const pending2FASetup = new Map();

// Промежуточный шаг логина для аккаунтов с включённой 2FA: пароль уже
// верный, но сессию ещё не выдаём, пока не введён код из приложения.
// challengeToken -> { accountId, attempts, expiresAt }.
const pending2FALogin = new Map();
const TWOFA_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const TWOFA_MAX_ATTEMPTS = 6;

function issueSession(accountId) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, accountId);
  return token;
}

// Аннулирует ВСЕ активные сессии (токены) аккаунта — используется при бане
// и при сбросе пароля админом, чтобы старый пароль/доступ переставал
// работать сразу, а не только при следующей естественной переустановке.
function revokeAllSessions(accountId) {
  for (const [token, accId] of sessions) {
    if (accId === accountId) sessions.delete(token);
  }
}

// Немедленно отключает все активные сокеты аккаунта (все открытые вкладки/
// устройства), предварительно уведомив клиента причиной — используется для
// админского бана и принудительного разлогина. Сама очистка socketToAccount/
// accountSockets/lastSeen происходит в уже существующем обработчике
// 'disconnect', это лишь инициирует его.
function forceLogoutAccount(accountId, message) {
  const sockets = accountSockets.get(accountId);
  if (!sockets) return;
  for (const sid of Array.from(sockets)) {
    const s = io.sockets.sockets.get(sid);
    if (!s) continue;
    s.emit('account:kicked', { message });
    // Небольшая задержка перед фактическим разрывом — гарантирует, что
    // событие 'account:kicked' успеет уйти клиенту (особенно на транспорте
    // polling) до того, как соединение закроется и emit выше станет
    // бессмысленным.
    setTimeout(() => s.disconnect(true), 50);
  }
}

// Временный бан: account.banned=true + account.bannedUntil=<timestamp>.
// Если срок истёк, тихо снимает бан и возвращает true (значит, состояние
// аккаунта изменилось и стоит сохранить/разослать админам свежие данные).
// Бессрочный бан — bannedUntil остаётся null, эта функция его не трогает.
function checkBanExpiry(account) {
  if (account && account.banned && account.bannedUntil && Date.now() >= account.bannedUntil) {
    account.banned = false;
    account.bannedUntil = null;
    return true;
  }
  return false;
}

// contacts: accountId -> Set<accountId> — список контактов пользователя.
// Хранится так же в памяти сервера, без БД.
const contacts = new Map();

// blockedUsers: accountId -> Set<accountId> — кого этот пользователь
// заблокировал (личная блокировка, отдельно от бана через админку).
// Заблокированный не может писать заблокировавшему, и наоборот, пока
// блокировка не снята — см. isBlockedBy() и проверку в message:send.
const blockedUsers = new Map();
function isBlockedBy(blockerId, targetId) {
  const set = blockedUsers.get(blockerId);
  return !!(set && set.has(targetId));
}
function isBlockedEitherWay(aId, bId) {
  return isBlockedBy(aId, bId) || isBlockedBy(bId, aId);
}

// Динамические админ-аккаунты, созданные прямо из админ-консоли (в
// отличие от ADMIN_ACCOUNTS/ADMIN_PASSWORD, которые задаются только
// переменными окружения при старте сервера). id -> { id, name,
// passwordHash, createdAt, createdBy }. Пароль хранится только как
// scrypt-хеш (см. hashPassword ниже), никогда в открытом виде — как и
// пароли обычных аккаунтов. У любого такого админа ровно те же права,
// что и у "встроенных" — отдельной системы разрешений нет, управление
// админами доступно любому уже вошедшему админу.
const dynamicAdmins = new Map();

// Архивация чатов — персональная для каждого участника (у Алисы чат
// в архиве, у Боба тот же чат — нет), поэтому это отдельная структура
// на аккаунт, а не поле на самом чате: accountId -> Set<chatId>.
const archivedChats = new Map();
function isArchivedFor(accountId, chatId) {
  const set = archivedChats.get(accountId);
  return !!(set && set.has(chatId));
}

// Последнее прочитанное сообщение на чат, персонально на пользователя —
// нужно, чтобы считать бейдж непрочитанных и не учитывать в нём чаты,
// которые сейчас в архиве. accountId -> Map<chatId, messageId>.
const lastRead = new Map();
function getLastReadId(accountId, chatId) {
  const map = lastRead.get(accountId);
  return map ? map.get(chatId) || null : null;
}
function setLastRead(accountId, chatId, messageId) {
  if (!lastRead.has(accountId)) lastRead.set(accountId, new Map());
  lastRead.get(accountId).set(chatId, messageId);
}
// Считает непрочитанные сообщения в чате после lastReadId (для accountId).
// Системные сообщения и собственные сообщения пользователя в счётчик не
// идут — их не нужно "прочитывать" отдельно.
function unreadCountFor(chat, accountId) {
  const lastId = getLastReadId(accountId, chat.id);
  let count = 0;
  for (let i = chat.messages.length - 1; i >= 0; i--) {
    const m = chat.messages[i];
    if (m.id === lastId) break;
    if (m.type === 'system' || m.senderId === accountId || m.deleted) continue;
    count++;
  }
  return count;
}

// Кастомные стикеры пользователя: accountId -> [{ id, ext, mime, createdAt }].
// Сами файлы картинок лежат на диске (STICKERS_DIR/<accountId>/<id>.<ext>),
// здесь только метаданные — см. store.js.
const customStickers = new Map();
function customStickersPublicList(accountId) {
  const list = customStickers.get(accountId) || [];
  return list.map((s) => ({ id: s.id, url: `/stickers/${accountId}/${s.id}.${s.ext}`, createdAt: s.createdAt }));
}

// Мини-приложения (HTML, отправляемые как обычное сообщение): appId ->
// { id, ownerId, ownerName, name, createdAt, html }. HTML пишется и
// файлом на диске в APPS_DIR/<id>.html (быстрый путь раздачи), и прямо
// в это поле метаданных — второе нужно, чтобы приложение не терялось
// на хостингах с эфемерным диском при удалённом сторе (см. store.js и
// app.get('/apps/:id.html', ...) выше). Карта общая на всех
// (не accountId -> list), потому что запустить/переслать чужое уже
// отправленное приложение может любой участник чата, а не только автор —
// поэтому id должен резолвиться глобально.
const miniApps = new Map();
function myAppsPublicList(accountId) {
  return Array.from(miniApps.values())
    .filter((a) => a.ownerId === accountId)
    .sort((a, b) => b.createdAt - a.createdAt)
    .map((a) => ({ id: a.id, name: a.name, createdAt: a.createdAt }));
}

function isOnline(accountId) {
  const sockets = accountSockets.get(accountId);
  return !!(sockets && sockets.size);
}

function contactsPublicList(myId) {
  const set = contacts.get(myId);
  if (!set) return [];
  return Array.from(set)
    .map((id) => accounts.get(id))
    .filter(Boolean)
    .map((a) => ({ ...publicAccount(a), online: isOnline(a.id) }));
}

// Список тех, кого я лично заблокировал (для экрана «Заблокированные» в
// настройках) — отдельно от контактов, потому что заблокировать можно и
// не-контакта.
function blockedPublicList(myId) {
  const set = blockedUsers.get(myId);
  if (!set) return [];
  return Array.from(set)
    .map((id) => accounts.get(id))
    .filter(Boolean)
    .map((a) => ({ ...publicAccount(a), online: isOnline(a.id) }));
}

function addContact(myId, otherId) {
  if (myId === otherId) return;
  if (!contacts.has(myId)) contacts.set(myId, new Set());
  contacts.get(myId).add(otherId);
}

const chats = new Map(); // chatId -> { id, name, isGroup, members:Set<accountId>, messages:[] }

const DEFAULT_CHAT_ID = 'general';
chats.set(DEFAULT_CHAT_ID, {
  id: DEFAULT_CHAT_ID,
  name: 'Общий чат',
  isGroup: true,
  members: new Set(),
  admins: new Set(),
  owner: null,
  pinnedMessageIds: [],
  messages: [],
});

function isChatAdmin(chat, accountId) {
  if (!chat.isGroup) return true;
  return chat.owner === accountId || (chat.admins && chat.admins.has(accountId));
}

function isChatOwner(chat, accountId) {
  return !chat.isGroup || chat.owner === accountId;
}

function systemMessage(chat, text) {
  const message = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    chatId: chat.id,
    senderId: null,
    senderName: '',
    type: 'system',
    text,
    time: Date.now(),
    read: true,
    reactions: {},
  };
  chat.messages.push(message);
  if (chat.messages.length > 500) chat.messages.shift();
  io.to(chat.id).emit('message:new', message);
  return message;
}

// Рассылает каждому участнику чата его персональную версию карточки чата
// (важно для личных чатов, где name/peer* зависят от того, кто смотрит,
// а также для archived/unread — они у каждого свои).
function broadcastChatUpsert(chat) {
  for (const memberId of chat.members) sendChatUpsertTo(memberId, chat);
}

// То же самое, но только одному конкретному участнику — нужно, когда
// меняется что-то персональное (архивация, прочитанное), а не общее
// для всех состояние чата.
function sendChatUpsertTo(accountId, chat) {
  const sockets = accountSockets.get(accountId);
  if (!sockets) return;
  const entry = chatListEntry(chat, accountId);
  for (const sid of sockets) io.to(sid).emit('chat:upsert', entry);
}

// Несколько закреплённых сообщений на чат (как в Telegram) — храним
// массив id в порядке закрепления (новые в конец), отдаём клиенту
// список карточек для отображения/переключения.
const MAX_PINNED = 20; // лимит закреплённых сообщений на чат, см. chat:pin/admin:pin-message
function pinnedInfoList(chat) {
  if (!chat.pinnedMessageIds || !chat.pinnedMessageIds.length) return [];
  return chat.pinnedMessageIds
    .map((id) => chat.messages.find((m) => m.id === id))
    .filter((m) => m && !m.deleted)
    .map((msg) => ({ id: msg.id, senderName: msg.senderName, preview: summarize(msg) }));
}

// ------------------------------------------------------------------
// Персистентность (без БД): всё, что должно переживать перезапуск
// сервера — аккаунты, пароли (хеши), контакты, чаты и сообщения —
// сохраняется в data/store.json и подгружается обратно при старте.
// Сессии (sessions) намеренно НЕ сохраняются — после перезапуска
// сервера все токены становятся невалидными, и это ок: пользователю
// нужно будет один раз заново войти по юзернейму/паролю, а сами
// аккаунты и переписка при этом никуда не денутся.
// ------------------------------------------------------------------
const persistedState = { accounts, usedNovaIds, usedUsernames, usedEmails, contacts, chats, archivedChats, lastRead, customStickers, blockedUsers, dynamicAdmins, miniApps };
// loadState теперь асинхронная (удалённый режим делает сетевой запрос
// к Upstash), поэтому дожидаемся её через промис — server.listen ниже
// по файлу стартует только после того, как dataReady разрешится, чтобы
// никто не успел подключиться раньше, чем данные будут на месте.
const dataReady = loadState(persistedState).then((restored) => {
  if (restored) {
    console.log('[store] Данные восстановлены');
    // Миграция старых аккаунтов (созданных до появления бана/даты
    // регистрации) — значения по умолчанию, чтобы админка и логика бана
    // не спотыкались об undefined.
    for (const account of accounts.values()) {
      if (typeof account.banned !== 'boolean') account.banned = false;
      // Временный бан (см. admin:set-banned) — момент, когда бан снимается
      // сам по себе. null/отсутствует = бан бессрочный (если account.banned).
      if (typeof account.bannedUntil !== 'number') account.bannedUntil = null;
      // Точечные ограничения возможностей аккаунта, не требующие полного
      // бана — сейчас только запрет на создание групп, см. chat:create.
      if (!account.restrictions || typeof account.restrictions !== 'object') account.restrictions = {};
      if (typeof account.restrictions.canCreateGroups !== 'boolean') account.restrictions.canCreateGroups = true;
      if (!account.createdAt) account.createdAt = 0; // неизвестно — "с самого начала"
      // Если @admin/@tester уже были зарегистрированы до появления
      // автоматической галочки — проставляем её и для них.
      if (AUTO_VERIFIED_USERNAMES.has(normalizeUsername(account.username))) account.verified = true;
    }
    // Миграция старых групп (созданных до появления ролей/владельца):
    // назначаем владельцем первого участника, чтобы группой можно было
    // управлять (без этого никто не считался бы админом).
    for (const chat of chats.values()) {
      if (chat.isGroup && chat.id !== DEFAULT_CHAT_ID && !chat.owner) {
        const first = Array.from(chat.members)[0] || null;
        chat.owner = first;
        if (first) chat.admins.add(first);
      }
      // Миграция старых чатов (созданных до этих полей).
      if (!chat.pinnedMessageIds) {
        chat.pinnedMessageIds = chat.pinnedMessageId ? [chat.pinnedMessageId] : [];
      }
      if (chat.isGroup && chat.id !== DEFAULT_CHAT_ID) {
        if (typeof chat.description !== 'string') chat.description = '';
        if (!chat.inviteCode) chat.inviteCode = crypto.randomBytes(6).toString('hex');
      }
    }
  } else {
    console.log('[store] Сохранённых данных не найдено — стартуем с чистого состояния');
  }
}).catch((err) => {
  console.error('[store] Ошибка при загрузке данных, стартуем с чистого состояния:', err.message);
});

function persist() {
  saveState(persistedState);
}

// Сохраняем и при штатной, и при принудительной остановке процесса
// (Ctrl+C, перезапуск через nodemon/PM2, деплой), чтобы не потерять
// последние секунды изменений, которые ещё не долетели до хранилища.
// saveStateNow теперь асинхронная (удалённый режим — это сетевой
// запрос), поэтому дожидаемся её перед фактическим завершением процесса.
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    saveStateNow(persistedState)
      .catch((err) => console.error('[store] Не удалось сохранить данные при остановке:', err.message))
      .finally(() => process.exit(0));
  });
}


function avatarColor(name) {
  const colors = ['#e17076', '#7bc862', '#65aadd', '#a695e7', '#ee7aae', '#6ec9cb', '#faa774', '#4f95d1'];
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash);
  return colors[Math.abs(hash) % colors.length];
}

// ------------------------------------------------------------------
// Пароль аккаунта: хранится только как salt+scrypt-хеш, никогда в
// открытом виде и никогда не логируется.
// ------------------------------------------------------------------
const PASSWORD_MIN = 4;
const PASSWORD_MAX = 64;

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored) return false;
  const [salt, hashHex] = stored.split(':');
  if (!salt || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(password, salt, 64);
  if (expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(expected, actual);
}

// ------------------------------------------------------------------
// Подтверждение email через HTTP API Resend (https://resend.com).
//
// ВАЖНО: раньше здесь использовался SMTP (nodemailer), но начиная с
// 26 сентября 2025 Render блокирует исходящие соединения с бесплатных
// (Free) веб-сервисов на SMTP-порты 25/465/587 — именно поэтому в
// логах была "Connection timeout" при каждой попытке отправки, а не
// баг в коде. Обход — не открывать сырое SMTP-соединение, а слать
// письма через обычный HTTPS-запрос к REST API провайдера, как уже
// сделано для Upstash в store.js.
//
// Нужна одна переменная окружения: RESEND_API_KEY (значение из
// dashboard.resend.com → API Keys; это тот же ключ, который раньше
// использовался как SMTP_PASS — можно скопировать его же). SMTP_FROM
// по-прежнему задаёт адрес и имя отправителя.
//
// Если ключ не задан (например, при локальном запуске), сервер
// НЕ падает и НЕ блокирует регистрацию — вместо реальной отправки
// ссылка на подтверждение просто печатается в консоль сервера, чтобы
// разработчик мог перейти по ней вручную. Так же ведёт себя и в случае,
// если реальная отправка неожиданно завершилась ошибкой — аккаунт
// всё равно создаётся, письмо можно будет отправить повторно из
// Настроек.
// ------------------------------------------------------------------
const RESEND_API_KEY = process.env.RESEND_API_KEY || process.env.SMTP_PASS || '';
const SMTP_FROM = process.env.SMTP_FROM || 'Nova Messenger <no-reply@nova-messenger.local>';

if (RESEND_API_KEY) {
  console.log('[mail] Режим отправки: Resend HTTP API');
} else {
  console.log('[mail] RESEND_API_KEY не задан — ссылки на подтверждение email будут просто печататься в консоль.');
}

// Публичный адрес сервера, чтобы собрать кликабельную ссылку в письме.
// Если не задан — берётся первый Origin, с которым реально подключился
// хоть один клиент (см. io.on('connection')), либо localhost как запасной
// вариант для локальной разработки.
let inferredPublicUrl = process.env.PUBLIC_URL ? process.env.PUBLIC_URL.replace(/\/+$/, '') : '';

// token -> { accountId, expiresAt }. Намеренно НЕ persist'ится вместе с
// остальным стейтом (как и loginAttempts/pending2FALogin) — это
// короткоживущие данные, при перезапуске сервера просто попросим
// отправить письмо ещё раз.
const emailVerificationTokens = new Map();
const EMAIL_VERIFY_TTL_MS = 24 * 60 * 60 * 1000; // 24 часа
const emailResendCooldowns = new Map(); // accountId -> timestamp следующей попытки
const EMAIL_RESEND_COOLDOWN_MS = 60 * 1000;

function issueEmailVerification(account) {
  // Старый токен (если был) больше не должен работать.
  for (const [tok, data] of emailVerificationTokens) {
    if (data.accountId === account.id) emailVerificationTokens.delete(tok);
  }
  const token = crypto.randomBytes(24).toString('hex');
  emailVerificationTokens.set(token, { accountId: account.id, expiresAt: Date.now() + EMAIL_VERIFY_TTL_MS });
  sendVerificationEmail(account, token).catch((err) => {
    console.error(`[mail] Не удалось отправить письмо подтверждения на ${account.email}:`, err.message);
  });
  return token;
}

async function sendVerificationEmail(account, token) {
  const base = inferredPublicUrl || 'http://localhost:3000';
  const link = `${base}/?verify_email=${token}`;

  if (!RESEND_API_KEY) {
    console.log(`[mail] (dev) Ссылка для подтверждения ${account.email}: ${link}`);
    return;
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: SMTP_FROM,
      to: account.email,
      subject: 'Подтверди свой email — Nova Messenger',
      text: `Привет, ${account.name}!\n\nЧтобы подтвердить email в Nova Messenger, перейди по ссылке:\n${link}\n\nСсылка действительна 24 часа. Если ты не регистрировался(-ась) в Nova Messenger — просто проигнорируй это письмо.`,
      html: `<p>Привет, ${account.name}!</p><p>Чтобы подтвердить email в Nova Messenger, перейди по ссылке:</p><p><a href="${link}">${link}</a></p><p>Ссылка действительна 24 часа. Если ты не регистрировался(-ась) в Nova Messenger — просто проигнорируй это письмо.</p>`,
    }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Resend API вернул ${res.status}: ${body}`);
  }
}

// ------------------------------------------------------------------
// 2FA (TOTP, RFC 6238) — реализовано на голом crypto, без внешних
// библиотек типа otplib/speakeasy, чтобы не тянуть лишнюю зависимость
// ради десятка строк HMAC-арифметики. Совместимо с любым стандартным
// приложением-аутентификатором (Google Authenticator, Authy и т.п.),
// потому что формат (SHA1, 6 цифр, шаг 30 сек) — это ровно то, что
// используют они все по умолчанию.
// ------------------------------------------------------------------
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = '';
  for (const byte of buffer) bits += byte.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) out += BASE32_ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  const remainder = bits.length % 5;
  if (remainder) out += BASE32_ALPHABET[parseInt(bits.slice(bits.length - remainder).padEnd(5, '0'), 2)];
  return out;
}

function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20)); // 160 бит — стандартная длина для TOTP-секрета
}

function hotp(secretBuffer, counter) {
  const counterBuf = Buffer.alloc(8);
  // Старшие 4 байта счётчика на практике всегда 0 (счётчик времени не
  // переполнит 32 бита ещё много тысяч лет), но пишем честно по RFC.
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac('sha1', secretBuffer).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
}

// Проверяет 6-значный код с окном ±1 шаг (±30 сек) — компенсирует
// небольшое рассинхронирование часов телефона с сервером, как делают
// все нормальные реализации TOTP.
function verifyTotpToken(secretBase32, token) {
  const clean = (token || '').toString().replace(/\s+/g, '');
  if (!/^\d{6}$/.test(clean)) return false;
  const secretBuffer = base32Decode(secretBase32);
  const counter = Math.floor(Date.now() / 1000 / 30);
  for (let errorWindow = -1; errorWindow <= 1; errorWindow++) {
    if (crypto.timingSafeEqual(Buffer.from(hotp(secretBuffer, counter + errorWindow)), Buffer.from(clean))) return true;
  }
  return false;
}

function buildOtpauthUrl(username, secretBase32) {
  const label = encodeURIComponent(`Nova Messenger:${username}`);
  const issuer = encodeURIComponent('Nova Messenger');
  return `otpauth://totp/${label}?secret=${secretBase32}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}

function generateRecoveryCodes(count = 8) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    // Формат xxxx-xxxx (без похожих символов 0/O/1/I/L), читается легко,
    // если придётся вводить руками с листка бумаги.
    const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let j = 0; j < 8; j++) {
      if (j === 4) code += '-';
      code += alphabet[crypto.randomBytes(1)[0] % alphabet.length];
    }
    codes.push(code);
  }
  return codes;
}

// ------------------------------------------------------------------
// Bot API — HTTP-доступ для ботов (в духе Telegram Bot API), отдельно
// от обычного Socket.IO-протокола пользователей.
//
// Бот — обычная запись в accounts с isBot:true, ownerId (кто создал) и
// botTokenHash (хеш токена, как и пароль — сам токен нигде не хранится
// и показывается создателю ровно один раз, в момент создания).
//
// Апдейты боту доставляются двумя способами на выбор владельца бота:
//   - long polling (GET /bot<TOKEN>/getUpdates?offset=&timeout=) —
//     сервер держит запрос открытым до timeout секунд или до первого
//     нового сообщения;
//   - webhook (POST /bot<TOKEN>/setWebhook {url}) — сервер сам шлёт
//     каждый апдейт POST-запросом на этот url; тогда очередь для
//     long-polling для этого бота просто не копится.
//
// Бот получает апдейты ТОЛЬКО из чатов, где он уже состоит участником
// (chat.members). У бота нет своего HTTP-эндпоинта "создать чат" или
// "написать первым в личку" — единственный способ попасть в личный чат
// с ботом — это человеку самому открыть с ним диалог (как и с любым
// другим пользователем, через getOrCreateDirectChat). Так естественным
// образом соблюдается правило "бот не пишет первым тем, кто не начал
// диалог сам".
// ------------------------------------------------------------------
const BOT_TOKEN_PREFIX = 'nova_bot_';
const botUpdateQueues = new Map(); // botAccountId -> { queue:[{update_id,message}], nextUpdateId, waiters:[fn] }
const BOT_RATE_LIMIT_PER_MIN = 20;
const botRateLimits = new Map(); // botAccountId -> { count, resetAt }

function generateBotToken() {
  return BOT_TOKEN_PREFIX + crypto.randomBytes(24).toString('hex');
}

// Токен хешируется той же функцией, что и пароли (соль+scrypt) — поиск
// бота по токену перебирает ботов и сверяет через verifyPassword, т.к.
// соль у каждого своя и по хешу нельзя построить прямой индекс. При
// разумном числе ботов на сервере это не проблема.
function findBotByToken(token) {
  if (!token || !token.startsWith(BOT_TOKEN_PREFIX)) return null;
  for (const account of accounts.values()) {
    if (account.isBot && verifyPassword(token, account.botTokenHash)) return account;
  }
  return null;
}

function checkBotRateLimit(botId) {
  const now = Date.now();
  let rl = botRateLimits.get(botId);
  if (!rl || now >= rl.resetAt) {
    rl = { count: 0, resetAt: now + 60 * 1000 };
    botRateLimits.set(botId, rl);
  }
  if (rl.count >= BOT_RATE_LIMIT_PER_MIN) return false;
  rl.count += 1;
  return true;
}

function getBotQueue(botId) {
  let q = botUpdateQueues.get(botId);
  if (!q) {
    q = { queue: [], nextUpdateId: 1, waiters: [] };
    botUpdateQueues.set(botId, q);
  }
  return q;
}

// Апдейт в формате, который видит бот — не наш внутренний объект
// message, а компактное представление (как Telegram Bot API).
function botUpdateFromMessage(message) {
  const sender = accounts.get(message.senderId);
  return {
    message_id: message.id,
    chat_id: message.chatId,
    date: Math.floor(message.time / 1000),
    from: sender ? { id: sender.id, username: sender.username, name: sender.name, is_bot: !!sender.isBot } : null,
    // Зашифрованные (E2E) личные сообщения серверу не видны — боту
    // соответственно тоже, text будет null.
    text: message.encrypted ? null : (message.text || null),
    type: message.type,
  };
}

// ------------------------------------------------------------------
// Консоль бота — обычный личный чат между владельцем и ботом (та же
// getOrCreateDirectChat, что и для людей), но им нельзя писать боту
// напрямую как человеку: сообщения владельца в этом чате обрабатывает
// bot:console-send, а входящие/исходящие сообщения бота из ДРУГИХ
// чатов зеркалируются сюда системными заметками, чтобы владелец видел
// всю активность бота в одном месте.
// ------------------------------------------------------------------
function getBotConsoleChat(botAccount) {
  return getOrCreateDirectChat(botAccount.ownerId, botAccount.id);
}

function chatLabel(chat) {
  if (chat.isGroup) return chat.name || 'Группа';
  return 'личке';
}

// Кладёт от имени бота служебную заметку (📥 входящее / 📤 исходящее) в
// его консоль-чат — не проходит через pushBotUpdates повторно, это
// просто обычное сообщение для отображения владельцу.
function postBotConsoleNote(botAccount, text) {
  const consoleChat = getBotConsoleChat(botAccount);
  const note = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    chatId: consoleChat.id,
    senderId: botAccount.id,
    senderName: botAccount.name,
    senderVerified: false,
    type: 'text',
    encrypted: false,
    text: text.slice(0, 4000),
    ciphertext: null, iv: null, header: null,
    stickerEmoji: null, stickerUrl: null, gifUrl: null,
    voiceData: null, voiceDuration: null,
    fileData: null, fileName: null, fileSize: null, fileMime: null,
    replyTo: null, forwardedFrom: null,
    reactions: {}, edited: false, deleted: false,
    time: Date.now(), read: false,
  };
  consoleChat.messages.push(note);
  if (consoleChat.messages.length > 500) consoleChat.messages.shift();
  io.to(consoleChat.id).emit('message:new', note);
}

// Кладёт апдейт во все очереди ботов, состоящих в чате (кроме самого
// отправителя, если отправитель — тоже бот), будит зависшие long-polling
// запросы и, если у бота настроен webhook, пушит апдейт туда. Также
// зеркалирует входящее сообщение в консоль-чат владельца бота (кроме
// случая, когда сообщение и так пришло из самой консоли).
function pushBotUpdates(chat, message) {
  for (const memberId of chat.members) {
    if (memberId === message.senderId) continue;
    const account = accounts.get(memberId);
    if (!account || !account.isBot) continue;
    const q = getBotQueue(account.id);
    const update = { update_id: q.nextUpdateId++, message: botUpdateFromMessage(message) };
    q.queue.push(update);
    if (q.queue.length > 200) q.queue.shift();
    const waiters = q.waiters.splice(0);
    for (const resolve of waiters) resolve();
    if (account.webhookUrl) {
      fetch(account.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(update),
      }).catch((err) => console.error(`[bot] Не удалось доставить webhook @${account.username}:`, err.message));
    }

    const consoleChat = getBotConsoleChat(account);
    if (chat.id !== consoleChat.id && !message.deleted) {
      const sender = accounts.get(message.senderId);
      const senderLabel = sender ? sender.name : 'Кто-то';
      const bodyText = message.encrypted ? '🔒 зашифрованное сообщение' : (summarize(message) || '');
      postBotConsoleNote(account, `📥 ${senderLabel} (в ${chatLabel(chat)}): ${bodyText}`);
    }
  }
}

// Отправка сообщения от имени бота — используется HTTP-эндпоинтом
// sendMessage и консолью владельца (bot:console-send). Бот пишет всегда
// открытым текстом (без E2E, у него нет браузерных ключей), поэтому
// доступно только в группах и в личных чатах, уже созданных человеком.
function botSendMessage(botAccount, chatId, text) {
  const chat = chats.get(String(chatId || ''));
  if (!chat) return { error: 'chat not found', status: 404 };
  if (!chat.members.has(botAccount.id)) return { error: 'bot is not a member of this chat', status: 403 };
  if (!checkBotRateLimit(botAccount.id)) return { error: 'rate limit exceeded (20 messages/min)', status: 429 };
  const cleanText = (text || '').toString().slice(0, 4000).trim();
  if (!cleanText) return { error: 'text is required', status: 400 };

  const message = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    chatId: chat.id,
    senderId: botAccount.id,
    senderName: botAccount.name,
    senderVerified: !!botAccount.verified,
    type: 'text',
    encrypted: false,
    text: cleanText,
    ciphertext: null,
    iv: null,
    header: null,
    stickerEmoji: null,
    stickerUrl: null,
    gifUrl: null,
    voiceData: null,
    voiceDuration: null,
    fileData: null,
    fileName: null,
    fileSize: null,
    fileMime: null,
    replyTo: null,
    forwardedFrom: null,
    reactions: {},
    edited: false,
    deleted: false,
    time: Date.now(),
    read: false,
  };

  chat.messages.push(message);
  if (chat.messages.length > 500) chat.messages.shift();
  persist();

  io.to(chat.id).emit('message:new', message);
  pushBotUpdates(chat, message);

  const consoleChat = getBotConsoleChat(botAccount);
  if (chat.id !== consoleChat.id) {
    postBotConsoleNote(botAccount, `📤 отправлено в ${chatLabel(chat)}: ${cleanText}`);
    persist();
  }
  return { message };
}

function requireBot(req, res, next) {
  const bot = findBotByToken(req.params.token);
  if (!bot) return res.status(401).json({ ok: false, error: 'invalid bot token' });
  if (bot.banned) return res.status(403).json({ ok: false, error: 'bot is banned' });
  req.bot = bot;
  next();
}

// GET /bot<TOKEN>/getUpdates?offset=&timeout=  — long polling.
app.get('/bot:token/getUpdates', requireBot, async (req, res) => {
  const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
  const timeout = Math.min(50, Math.max(0, parseInt(req.query.timeout, 10) || 0));
  const q = getBotQueue(req.bot.id);
  const pending = () => q.queue.filter((u) => u.update_id > offset);

  let ready = pending();
  if (ready.length === 0 && timeout > 0) {
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        const idx = q.waiters.indexOf(wrapped);
        if (idx !== -1) q.waiters.splice(idx, 1);
        resolve();
      }, timeout * 1000);
      const wrapped = () => { clearTimeout(timer); resolve(); };
      q.waiters.push(wrapped);
    });
    ready = pending();
  }
  res.json({ ok: true, result: ready });
});

// POST /bot<TOKEN>/sendMessage { chat_id, text }
app.post('/bot:token/sendMessage', requireBot, (req, res) => {
  const { chat_id, text } = req.body || {};
  if (!chat_id) return res.status(400).json({ ok: false, error: 'chat_id is required' });
  const result = botSendMessage(req.bot, chat_id, text);
  if (result.error) return res.status(result.status || 400).json({ ok: false, error: result.error });
  res.json({ ok: true, result: { message_id: result.message.id, chat_id: result.message.chatId, date: Math.floor(result.message.time / 1000) } });
});

// POST /bot<TOKEN>/setWebhook { url } — url:null или '' снимает вебхук.
app.post('/bot:token/setWebhook', requireBot, (req, res) => {
  const url = req.body && typeof req.body.url === 'string' ? req.body.url.trim() : '';
  req.bot.webhookUrl = url || null;
  persist();
  res.json({ ok: true, result: true, webhookUrl: req.bot.webhookUrl });
});

// GET /bot<TOKEN>/getMe — базовая информация о самом боте.
app.get('/bot:token/getMe', requireBot, (req, res) => {
  res.json({ ok: true, result: publicAccount(req.bot) });
});

// Простая защита от подбора пароля: после нескольких неверных попыток
// подряд для конкретного юзернейма — временная блокировка попыток входа
// в этот аккаунт. Не замена нормальному rate-limiting по IP, но закрывает
// самый очевидный сценарий перебора.
// Rate-limiting на отправку сообщений: защита от флуда одним аккаунтом
// (не путать с login-lockout ниже — это про частоту message:send после
// того, как человек уже вошёл). Скользящее окно на аккаунт: не больше
// MESSAGE_RATE_LIMIT сообщений за MESSAGE_RATE_WINDOW_MS.
const messageRateState = new Map(); // accountId -> { count, windowStart }
const MESSAGE_RATE_LIMIT = 15;
const MESSAGE_RATE_WINDOW_MS = 10 * 1000;

function isMessageRateLimited(accountId) {
  const now = Date.now();
  let state = messageRateState.get(accountId);
  if (!state || now - state.windowStart >= MESSAGE_RATE_WINDOW_MS) {
    state = { count: 0, windowStart: now };
    messageRateState.set(accountId, state);
  }
  state.count += 1;
  return state.count > MESSAGE_RATE_LIMIT;
}

const loginAttempts = new Map(); // normalized username -> { count, lockedUntil }
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MS = 30 * 1000;

function registerFailedAttempt(key) {
  const attempt = loginAttempts.get(key) || { count: 0, lockedUntil: 0 };
  attempt.count += 1;
  if (attempt.count >= MAX_LOGIN_ATTEMPTS) {
    attempt.lockedUntil = Date.now() + LOCKOUT_MS;
    attempt.count = 0;
  }
  loginAttempts.set(key, attempt);
}

function getLockoutSecondsLeft(key) {
  const attempt = loginAttempts.get(key);
  if (!attempt || !attempt.lockedUntil) return 0;
  const msLeft = attempt.lockedUntil - Date.now();
  return msLeft > 0 ? Math.ceil(msLeft / 1000) : 0;
}

// ------------------------------------------------------------------
// Админ-консоль (/admin.html): отдельный вход по паролю, не связанный
// с обычными аккаунтами. Задавай пароль через переменную окружения
// ADMIN_PASSWORD — иначе используется пароль по умолчанию (только для
// локального теста, для реального использования обязательно смени).
// ------------------------------------------------------------------
// Именованные админ-аккаунты: ADMIN_ACCOUNTS='[{"name":"Алиса","password":"..."},{"name":"Боб","password":"..."}]'
// (JSON-массив в переменной окружения). Так действия в журнале можно
// приписать конкретному человеку, а не только IP. Для обратной
// совместимости с более простой настройкой одним паролем — если
// ADMIN_ACCOUNTS не задан, используется старая переменная ADMIN_PASSWORD
// как один аккаунт с именем "admin".
let ADMIN_ACCOUNTS = [];
if (process.env.ADMIN_ACCOUNTS) {
  try {
    const parsed = JSON.parse(process.env.ADMIN_ACCOUNTS);
    if (Array.isArray(parsed)) {
      ADMIN_ACCOUNTS = parsed
        .filter((a) => a && typeof a.name === 'string' && typeof a.password === 'string' && a.password.length > 0)
        .map((a) => ({ name: a.name.trim().slice(0, 40) || 'admin', password: a.password }));
    }
  } catch (err) {
    console.error('[admin] Не удалось разобрать ADMIN_ACCOUNTS (ожидается JSON-массив), см. README:', err.message);
  }
}
if (!ADMIN_ACCOUNTS.length) {
  const legacyPassword = process.env.ADMIN_PASSWORD || 'admin123';
  if (!process.env.ADMIN_PASSWORD && !process.env.ADMIN_ACCOUNTS) {
    console.warn('[admin] ADMIN_ACCOUNTS/ADMIN_PASSWORD не заданы в окружении — используется пароль по умолчанию "admin123". Задай свой перед реальным использованием.');
  }
  ADMIN_ACCOUNTS = [{ name: 'admin', password: legacyPassword }];
}
function findAdminAccountByPassword(password) {
  const envMatch = ADMIN_ACCOUNTS.find((a) => a.password === password);
  if (envMatch) return { name: envMatch.name, source: 'env' };
  for (const admin of dynamicAdmins.values()) {
    if (verifyPassword(password, admin.passwordHash)) return { name: admin.name, id: admin.id, source: 'dynamic' };
  }
  return null;
}

// Список всех админов (и заданных через ADMIN_ACCOUNTS/ADMIN_PASSWORD,
// и созданных прямо в консоли) для экрана управления админами. У
// "встроенных" (source: 'env') нет id и их нельзя удалить из UI — они
// заданы окружением сервера и живут, пока живёт эта переменная.
function adminAdminsList() {
  const envList = ADMIN_ACCOUNTS.map((a) => ({ id: null, name: a.name, source: 'env', createdAt: null }));
  const dynamicList = Array.from(dynamicAdmins.values())
    .map((a) => ({ id: a.id, name: a.name, source: 'dynamic', createdAt: a.createdAt, createdBy: a.createdBy }))
    .sort((a, b) => a.createdAt - b.createdAt);
  return [...envList, ...dynamicList];
}

function isAdminNameTaken(name) {
  const normalized = name.trim().toLowerCase();
  if (ADMIN_ACCOUNTS.some((a) => a.name.toLowerCase() === normalized)) return true;
  for (const admin of dynamicAdmins.values()) {
    if (admin.name.toLowerCase() === normalized) return true;
  }
  return false;
}

const adminAttempts = new Map(); // socket.id -> { count, lockedUntil }
const ADMIN_MAX_ATTEMPTS = 5;
const ADMIN_LOCKOUT_MS = 30 * 1000;

function adminLockoutSecondsLeft(key) {
  const attempt = adminAttempts.get(key);
  if (!attempt || !attempt.lockedUntil) return 0;
  const msLeft = attempt.lockedUntil - Date.now();
  return msLeft > 0 ? Math.ceil(msLeft / 1000) : 0;
}
function adminRegisterFailedAttempt(key) {
  const attempt = adminAttempts.get(key) || { count: 0, lockedUntil: 0 };
  attempt.count += 1;
  if (attempt.count >= ADMIN_MAX_ATTEMPTS) {
    attempt.lockedUntil = Date.now() + ADMIN_LOCKOUT_MS;
    attempt.count = 0;
  }
  adminAttempts.set(key, attempt);
}

function adminAccountList() {
  return Array.from(accounts.values()).map((a) => ({
    id: a.id,
    name: a.name,
    username: a.username,
    novaId: a.novaId,
    verified: !!a.verified,
    banned: !!a.banned,
    bannedUntil: a.bannedUntil || null,
    canCreateGroups: a.restrictions ? a.restrictions.canCreateGroups !== false : true,
    createdAt: a.createdAt || null,
    online: !!(accountSockets.get(a.id) && accountSockets.get(a.id).size > 0),
    lastSeen: a.lastSeen || null,
    twoFactorEnabled: !!a.twoFactorEnabled,
  }));
}

// Сводка для шапки админки: сколько всего аккаунтов, сколько сейчас
// онлайн, сколько чатов (личных + групповых) и сообщений во всех чатах
// суммарно, сколько аккаунтов забанено.
function adminStats() {
  let onlineAccounts = 0;
  for (const a of accounts.values()) {
    if (accountSockets.get(a.id) && accountSockets.get(a.id).size > 0) onlineAccounts++;
  }
  let totalMessages = 0;
  let groupChats = 0;
  let dmChats = 0;
  for (const chat of chats.values()) {
    totalMessages += chat.messages.length;
    if (chat.isGroup) groupChats++; else dmChats++;
  }
  return {
    totalAccounts: accounts.size,
    onlineAccounts,
    bannedAccounts: Array.from(accounts.values()).filter((a) => a.banned).length,
    groupChats,
    dmChats,
    totalMessages,
  };
}

// Список групповых чатов для вкладки модерации — включая общий чат
// (DEFAULT_CHAT_ID), его тоже может понадобиться посмотреть/почистить.
function adminGroupList() {
  return Array.from(chats.values())
    .filter((c) => c.isGroup)
    .map((c) => {
      const owner = c.owner ? accounts.get(c.owner) : null;
      return {
        id: c.id,
        name: c.name,
        memberCount: c.members.size,
        messageCount: c.messages.length,
        ownerName: owner ? owner.name : null,
        createdAt: c.createdAt || null,
        isDefault: c.id === DEFAULT_CHAT_ID,
      };
    })
    .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
}

// Юзернеймы, у которых сейчас действует временная блокировка входа
// (после нескольких неверных попыток пароля) — чтобы админ мог снять её
// вручную, если уверен, что это не подбор пароля со стороны.
function adminLockedLogins() {
  const now = Date.now();
  const out = [];
  for (const [key, attempt] of loginAttempts) {
    const secondsLeft = attempt.lockedUntil ? Math.ceil((attempt.lockedUntil - now) / 1000) : 0;
    if (secondsLeft > 0) out.push({ username: key, secondsLeft });
  }
  return out;
}

// Внутренний "Nova ID" — не настоящий телефонный номер. Уникальный ярлык
// аккаунта, по формату похожий на номер; также используется как внутренний
// ключ аккаунта (accountId).
function generateNovaId() {
  let id;
  do {
    const digits = String(Math.floor(100000 + Math.random() * 900000));
    id = `NOVA-${digits}`;
  } while (usedNovaIds.has(id));
  usedNovaIds.add(id);
  return id;
}

function publicAccount(account) {
  return {
    id: account.id,
    name: account.name,
    username: account.username,
    novaId: account.novaId,
    color: account.color,
    bio: account.bio || '',
    verified: !!account.verified,
    isBot: !!account.isBot,
    lastSeen: account.lastSeen || null,
    // Публичный ECDH-ключ для E2E-шифрования личных чатов. Это ОТКРЫТЫЙ
    // ключ — его можно свободно раздавать кому угодно, приватный ключ
    // никогда не покидает браузер владельца и сервер его не видит.
    publicKey: account.publicKey || null,
  };
}

// То же самое, но с полями, которые видны только самому владельцу
// аккаунта (никогда не рассылаются другим пользователям) — сейчас это
// только статус 2FA, нужный для бейджа в собственных Настройках.
function privateAccountView(account) {
  return {
    ...publicAccount(account),
    twoFactorEnabled: !!account.twoFactorEnabled,
    // Email и его статус подтверждения — приватные поля, видны только
    // самому владельцу (в отличие от остальных полей publicAccount,
    // которые видят и другие пользователи).
    email: account.email || null,
    emailVerified: !!account.emailVerified,
  };
}

// Личные (1-на-1) чаты между двумя аккаунтами: детерминированный id,
// чтобы при повторном открытии чата с тем же человеком переиспользовать
// один и тот же чат, а не плодить дубли.
function directChatId(a, b) {
  return 'dm-' + [a, b].sort().join('_');
}
function getOrCreateDirectChat(aId, bId) {
  const id = directChatId(aId, bId);
  let chat = chats.get(id);
  if (!chat) {
    chat = { id, name: null, isGroup: false, members: new Set([aId, bId]), admins: new Set(), owner: null, pinnedMessageIds: [], messages: [] };
    chats.set(id, chat);
  }
  return chat;
}

function chatListEntry(chat, accountId) {
  const last = chat.messages[chat.messages.length - 1];
  const entry = {
    id: chat.id,
    name: chat.name,
    isGroup: chat.isGroup,
    lastMessage: last ? summarize(last) : '',
    lastTime: last ? last.time : null,
    unread: accountId ? unreadCountFor(chat, accountId) : 0,
    archived: accountId ? isArchivedFor(accountId, chat.id) : false,
    pinnedMessages: pinnedInfoList(chat),
  };
  if (!chat.isGroup) {
    const peerId = Array.from(chat.members).find((id) => id !== accountId);
    const peer = peerId && accounts.get(peerId);
    entry.peerId = peerId || null;
    entry.name = peer ? peer.name : 'Пользователь';
    entry.peerUsername = peer ? peer.username : '';
    entry.peerVerified = peer ? !!peer.verified : false;
    entry.peerIsBot = peer ? !!peer.isBot : false;
    entry.peerOnline = peerId ? isOnline(peerId) : false;
    entry.peerLastSeen = peer ? peer.lastSeen || null : null;
    entry.peerPublicKey = peer ? peer.publicKey || null : null;
    // Блокировка — персональная в обе стороны: iBlockedPeer (я заблокировал
    // его — не могу писать) и peerBlockedMe (он заблокировал меня — тоже
    // не могу писать, даже если сам его не блокировал).
    entry.iBlockedPeer = peerId ? isBlockedBy(accountId, peerId) : false;
    entry.peerBlockedMe = peerId ? isBlockedBy(peerId, accountId) : false;
  } else {
    entry.memberCount = chat.members.size;
    entry.isAdmin = accountId ? isChatAdmin(chat, accountId) : false;
    entry.isOwner = accountId ? isChatOwner(chat, accountId) : false;
    entry.description = chat.description || '';
    entry.avatarEmoji = chat.avatarEmoji || null;
    // Код приглашения виден только тем, кто уже состоит в группе (не всему
    // серверу) — им можно поделиться ссылкой вида /?invite=КОД.
    entry.inviteCode = accountId && chat.members.has(accountId) ? (chat.inviteCode || null) : null;
  }
  return entry;
}

function publicChatList(accountId) {
  const list = [];
  for (const chat of chats.values()) {
    if (!chat.isGroup && !chat.members.has(accountId)) continue;
    list.push(chatListEntry(chat, accountId));
  }
  return list;
}

// Упоминания @username в тексте группового сообщения: находим все
// @token, сверяем с юзернеймами участников ИМЕННО этого чата (не всего
// сервера — упомянуть можно только того, кто состоит в группе) и
// возвращаем список accountId без дублей.
function extractMentions(text, chat) {
  const raw = (text || '').toString();
  const found = new Set();
  const re = /(^|[\s(])@([A-Za-z][A-Za-z0-9_]{2,31})\b/g;
  let match;
  while ((match = re.exec(raw))) {
    const uname = normalizeUsername(match[2]);
    const targetId = usedUsernames.get(uname);
    if (targetId && chat.members.has(targetId)) found.add(targetId);
  }
  return Array.from(found);
}

// Уведомление упомянутых участников группы (кроме автора) — лёгкое
// событие для их подключённых сокетов, если они сейчас онлайн; если нет —
// просто увидят упоминание, открыв чат позже (оно уже подсвечено в тексте).
function notifyMentions(chat, message, author) {
  if (!message.mentions || !message.mentions.length) return;
  for (const targetId of message.mentions) {
    if (targetId === author.id) continue;
    const sockets = accountSockets.get(targetId);
    if (!sockets) continue;
    for (const sid of sockets) {
      io.to(sid).emit('mention:notify', {
        chatId: chat.id,
        chatName: chat.name,
        messageId: message.id,
        senderName: author.name,
        preview: summarize(message).slice(0, 120),
      });
    }
  }
}

function summarize(msg) {
  if (msg.deleted) return 'Сообщение удалено';
  if (msg.type === 'system') return msg.text;
  // 'group-key' — служебная раздача sender key одному участнику через
  // личный DM-канал, не настоящая переписка — не показываем в превью.
  if (msg.type === 'group-key') return '';
  // Зашифрованные сообщения сервер прочитать не может (и не должен) —
  // показываем нейтральную заглушку вместо текста.
  if (msg.encrypted) return '\ud83d\udd12 Зашифрованное сообщение';
  if (msg.type === 'text') return msg.text;
  if (msg.type === 'sticker') return '\u2b50 Стикер';
  if (msg.type === 'custom-sticker') return '\u2b50 Стикер';
  if (msg.type === 'gif') return '\ud83c\udfac GIF';
  if (msg.type === 'voice') return '\ud83c\udfa4 Голосовое сообщение';
  if (msg.type === 'file') return `\ud83d\udcce ${msg.fileName || 'Файл'}`;
  if (msg.type === 'app') return `\ud83e\udde9 Приложение: ${msg.appName || ''}`;
  return '';
}

function validateUsername(rawUsername) {
  const trimmed = (rawUsername || '').toString().trim().replace(/^@/, '');
  if (!trimmed) return { error: 'Укажи юзернейм.' };
  if (!USERNAME_RE.test(trimmed)) {
    return { error: 'Юзернейм должен быть 5-32 символа: латинские буквы, цифры и _, начинаться с буквы.' };
  }
  return { value: trimmed, normalized: normalizeUsername(trimmed) };
}

function loginAccount(socket, account, isNewAccount, token) {
  const accountId = account.id;
  socketToAccount.set(socket.id, accountId);
  socketToToken.set(socket.id, token);
  if (!accountSockets.has(accountId)) accountSockets.set(accountId, new Set());
  const wasOffline = accountSockets.get(accountId).size === 0;
  accountSockets.get(accountId).add(socket.id);

  chats.get(DEFAULT_CHAT_ID).members.add(accountId);
  socket.join(DEFAULT_CHAT_ID);
  // Личные чаты, где я участник, — подключаемся к их "комнатам", чтобы
  // получать сообщения в реальном времени, даже если чат ещё не открыт.
  for (const chat of chats.values()) {
    if (!chat.isGroup && chat.members.has(accountId)) socket.join(chat.id);
  }

  socket.emit('auth:ok', {
    me: privateAccountView(account),
    isNewAccount,
    chats: publicChatList(accountId),
    session: token,
    customStickers: customStickersPublicList(accountId),
  });
  socket.emit('chat:history', {
    chatId: DEFAULT_CHAT_ID,
    messages: chats.get(DEFAULT_CHAT_ID).messages,
  });

  if (wasOffline) {
    socket.to(DEFAULT_CHAT_ID).emit('user:online', publicAccount(account));
    // Уведомляем и участников личных чатов со мной — чтобы у них в
    // профиле/списке контактов статус "в сети" обновился сразу.
    for (const chat of chats.values()) {
      if (!chat.isGroup && chat.members.has(accountId)) socket.to(chat.id).emit('user:online', publicAccount(account));
    }
    broadcastAdminAccounts();
  }
}

io.on('connection', (socket) => {
  // Если PUBLIC_URL не задан явно переменной окружения — запоминаем
  // Origin первого подключившегося клиента, чтобы ссылки в письмах
  // подтверждения email вели на реальный домен, а не на localhost.
  if (!inferredPublicUrl) {
    const origin = socket.handshake.headers && socket.handshake.headers.origin;
    if (origin) inferredPublicUrl = origin.replace(/\/+$/, '');
  }

  // Аудио/видеозвонки (WebRTC-сигналинг) — см. calls.js. Регистрируем
  // обработчики call:* на этом сокете; handleAccountFullyOffline вызываем
  // ниже из socket.on('disconnect', ...), когда у аккаунта не осталось
  // ни одного живого соединения.
  const callHandlers = registerCallHandlers(io, socket, { socketToAccount, accountSockets, accounts, chats, publicAccount });

  // ----------------------------------------------------------------
  // Регистрация нового аккаунта. Юзернейм обязателен и уникален на
  // весь сервер — он и есть логин, по которому потом входят.
  // ----------------------------------------------------------------
  socket.on('auth:register', (payload) => {
    const cleanName = ((payload && payload.name) || '').toString().trim().slice(0, NAME_MAX);
    const password = (payload && payload.password ? String(payload.password) : '');

    if (!cleanName) {
      socket.emit('auth:error', { message: 'Укажи имя.' });
      return;
    }
    if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
      socket.emit('auth:error', { message: `Пароль должен быть от ${PASSWORD_MIN} до ${PASSWORD_MAX} символов.` });
      return;
    }

    const usernameCheck = validateUsername(payload && payload.username);
    if (usernameCheck.error) {
      socket.emit('auth:error', { message: usernameCheck.error });
      return;
    }
    if (usedUsernames.has(usernameCheck.normalized)) {
      socket.emit('auth:error', { message: `Юзернейм @${usernameCheck.value} уже занят.` });
      return;
    }

    // Email обязателен при регистрации — это второй способ войти в
    // аккаунт (наравне с юзернеймом) и адрес, на который отправляется
    // письмо для подтверждения.
    const emailCheck = validateEmail(payload && payload.email);
    if (emailCheck.error) {
      socket.emit('auth:error', { message: emailCheck.error });
      return;
    }
    if (usedEmails.has(emailCheck.normalized)) {
      socket.emit('auth:error', { message: 'Этот email уже привязан к другому аккаунту.' });
      return;
    }

    const novaId = generateNovaId();
    const account = {
      id: novaId,
      name: cleanName,
      username: usernameCheck.value,
      novaId,
      email: emailCheck.value,
      emailVerified: false,
      color: avatarColor(cleanName),
      bio: '',
      passwordHash: hashPassword(password),
      verified: AUTO_VERIFIED_USERNAMES.has(usernameCheck.normalized),
      banned: false,
      bannedUntil: null,
      restrictions: { canCreateGroups: true },
      createdAt: Date.now(),
    };
    accounts.set(account.id, account);
    usedUsernames.set(usernameCheck.normalized, account.id);
    usedEmails.set(emailCheck.normalized, account.id);
    persist();
    issueEmailVerification(account);

    loginAccount(socket, account, true, issueSession(account.id));
  });

  // ----------------------------------------------------------------
  // Создание бота владельцем уже залогиненного аккаунта (Настройки →
  // "Создать бота"). Бот — отдельный account с isBot:true, у него нет
  // пароля (вход как обычный пользователь недоступен), только токен
  // Bot API, который показывается один раз в ответе и дальше хранится
  // лишь как хеш.
  // ----------------------------------------------------------------
  socket.on('account:create-bot', (payload) => {
    const accountId = socketToAccount.get(socket.id);
    const owner = accountId && accounts.get(accountId);
    if (!owner || owner.isBot) return;

    const cleanName = ((payload && payload.name) || '').toString().trim().slice(0, NAME_MAX);
    if (!cleanName) {
      socket.emit('bot:error', { message: 'Укажи имя бота.' });
      return;
    }
    const usernameCheck = validateUsername(payload && payload.username);
    if (usernameCheck.error) {
      socket.emit('bot:error', { message: usernameCheck.error });
      return;
    }
    if (usedUsernames.has(usernameCheck.normalized)) {
      socket.emit('bot:error', { message: `Юзернейм @${usernameCheck.value} уже занят.` });
      return;
    }

    const novaId = generateNovaId();
    const token = generateBotToken();
    const botAccount = {
      id: novaId,
      name: cleanName,
      username: usernameCheck.value,
      novaId,
      color: avatarColor(cleanName),
      // Случайный, никому не известный пароль — вход в бота через обычную
      // форму логина невозможен, доступ только через Bot API по токену.
      passwordHash: hashPassword(crypto.randomBytes(20).toString('hex')),
      verified: false,
      banned: false,
      createdAt: Date.now(),
      isBot: true,
      ownerId: owner.id,
      botTokenHash: hashPassword(token),
      webhookUrl: null,
    };
    accounts.set(botAccount.id, botAccount);
    usedUsernames.set(usernameCheck.normalized, botAccount.id);

    // Сразу создаём личный чат-консоль владелец↔бот и добавляем в
    // контакты — владелец увидит его в списке чатов и сможет управлять
    // ботом (отправлять от его имени, видеть входящие) прямо оттуда.
    const consoleChat = getBotConsoleChat(botAccount);
    socket.join(consoleChat.id);
    addContact(owner.id, botAccount.id);
    persist();

    // Токен отдаём ОДИН раз, только создателю, только в этом ответе —
    // дальше сервер помнит лишь его хеш, как и с обычными паролями.
    socket.emit('account:bot-created', { bot: publicAccount(botAccount), token, consoleChatId: consoleChat.id });
    socket.emit('chat:upsert', chatListEntry(consoleChat, owner.id));
    socket.emit('chat:history', { chatId: consoleChat.id, messages: consoleChat.messages });
  });

  // ----------------------------------------------------------------
  // Консоль бота: список чатов, куда бот может писать (для выпадающего
  // списка в UI), и сама отправка сообщения от имени бота из консоли.
  // Доступно только владельцу бота.
  // ----------------------------------------------------------------
  socket.on('bot:targets', ({ botId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const bot = botId && accounts.get(botId);
    if (!accountId || !bot || !bot.isBot || bot.ownerId !== accountId) return;
    const consoleChat = getBotConsoleChat(bot);
    const targets = [];
    for (const chat of chats.values()) {
      if (!chat.members.has(bot.id) || chat.id === consoleChat.id) continue;
      targets.push({ id: chat.id, name: chat.isGroup ? (chat.name || 'Группа') : 'Личка' });
    }
    socket.emit('bot:targets-list', { botId: bot.id, targets });
  });

  socket.on('bot:console-send', ({ botId, targetChatId, text } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const bot = botId && accounts.get(botId);
    if (!accountId || !bot || !bot.isBot || bot.ownerId !== accountId) return;
    const result = botSendMessage(bot, targetChatId, text);
    if (result.error) socket.emit('bot:error', { message: `Не удалось отправить: ${result.error}` });
  });

  // ----------------------------------------------------------------
  // Восстановление сессии по токену из cookie — чтобы после перезагрузки
  // страницы (или закрытия и повторного открытия вкладки) не нужно было
  // заново вводить пароль. Токен ни к чему, кроме аккаунта, не привязан.
  // ----------------------------------------------------------------
  socket.on('auth:session', (payload) => {
    const token = (payload && payload.token ? String(payload.token) : '');
    const accountId = token && sessions.get(token);
    const account = accountId && accounts.get(accountId);
    if (account && checkBanExpiry(account)) { persist(); broadcastAdminAccounts(); }
    if (!account || account.banned) {
      socket.emit('auth:session-invalid');
      return;
    }
    loginAccount(socket, account, false, token);
  });

  // Выход из аккаунта: аннулируем именно этот токен (остальные устройства,
  // если вход был с них, остаются в аккаунте).
  socket.on('auth:logout', (payload) => {
    const token = (payload && payload.token ? String(payload.token) : socketToToken.get(socket.id));
    if (token) sessions.delete(token);
  });

  // ----------------------------------------------------------------
  // Вход в существующий аккаунт — по юзернейму и паролю, с любого
  // устройства/браузера (никакой привязки к localStorage больше нет).
  // ----------------------------------------------------------------
  socket.on('auth:login', (payload) => {
    // Логин можно ввести и как юзернейм, и как email — определяем по
    // наличию "@" (в юзернеймах он невозможен, см. USERNAME_RE).
    const rawIdentifier = (payload && payload.username ? String(payload.username) : '');
    const password = (payload && payload.password ? String(payload.password) : '');
    const isEmailLogin = looksLikeEmail(rawIdentifier);

    const identifierCheck = isEmailLogin ? validateEmail(rawIdentifier) : validateUsername(rawIdentifier);
    if (identifierCheck.error) {
      socket.emit('auth:error', { message: isEmailLogin ? identifierCheck.error : 'Неверный юзернейм или пароль.' });
      return;
    }
    if (!password) {
      socket.emit('auth:error', { message: 'Введи пароль.' });
      return;
    }

    const lockKey = identifierCheck.normalized;
    const secondsLeft = getLockoutSecondsLeft(lockKey);
    if (secondsLeft > 0) {
      socket.emit('auth:error', { message: `Слишком много неверных попыток. Попробуй через ${secondsLeft} сек.` });
      return;
    }

    const accountId = isEmailLogin ? usedEmails.get(identifierCheck.normalized) : usedUsernames.get(identifierCheck.normalized);
    const account = accountId && accounts.get(accountId);

    if (!account || !verifyPassword(password, account.passwordHash)) {
      registerFailedAttempt(lockKey);
      socket.emit('auth:error', { message: 'Неверный юзернейм или пароль.' });
      return;
    }
    if (checkBanExpiry(account)) { persist(); broadcastAdminAccounts(); }
    if (account.banned) {
      // Намеренно НЕ трогаем счётчик неверных попыток — пароль был верный,
      // это не подбор, а забаненный аккаунт.
      socket.emit('auth:error', { message: 'Аккаунт заблокирован администратором.' });
      return;
    }

    loginAttempts.delete(lockKey);

    // Пароль верный, но если у аккаунта включена 2FA — сессию пока не
    // выдаём. Заводим короткоживущий "челлендж" и просим код из
    // приложения-аутентификатора отдельным запросом (auth:2fa-verify).
    if (account.twoFactorEnabled) {
      const challengeToken = crypto.randomBytes(24).toString('hex');
      pending2FALogin.set(challengeToken, { accountId: account.id, attempts: 0, expiresAt: Date.now() + TWOFA_CHALLENGE_TTL_MS });
      socket.emit('auth:2fa-required', { challengeToken });
      return;
    }

    loginAccount(socket, account, false, issueSession(account.id));
  });

  // ----------------------------------------------------------------
  // Второй шаг входа для аккаунтов с включённой 2FA — код из
  // приложения-аутентификатора (или резервный код, если телефон
  // недоступен). challengeToken выдаётся в auth:2fa-required и живёт
  // ограниченное время, чтобы его нельзя было подобрать не спеша.
  // ----------------------------------------------------------------
  socket.on('auth:2fa-verify', (payload) => {
    const challengeToken = (payload && payload.challengeToken ? String(payload.challengeToken) : '');
    const challenge = pending2FALogin.get(challengeToken);
    if (!challenge || challenge.expiresAt < Date.now()) {
      pending2FALogin.delete(challengeToken);
      socket.emit('auth:2fa-error', { message: 'Сессия входа истекла, попробуй войти заново.', expired: true });
      return;
    }
    const account = accounts.get(challenge.accountId);
    if (!account || !account.twoFactorEnabled) {
      pending2FALogin.delete(challengeToken);
      socket.emit('auth:2fa-error', { message: 'Что-то пошло не так, попробуй войти заново.', expired: true });
      return;
    }

    const token = (payload && payload.token ? String(payload.token) : '');
    const recoveryCode = (payload && payload.recoveryCode ? String(payload.recoveryCode).trim().toUpperCase() : '');

    let ok = false;
    if (recoveryCode) {
      const codes = account.twoFactorRecoveryCodes || [];
      const idx = codes.findIndex((hash) => verifyPassword(recoveryCode, hash));
      if (idx !== -1) {
        ok = true;
        codes.splice(idx, 1); // резервный код одноразовый
        persist();
      }
    } else {
      ok = verifyTotpToken(account.twoFactorSecret, token);
    }

    if (!ok) {
      challenge.attempts += 1;
      if (challenge.attempts >= TWOFA_MAX_ATTEMPTS) {
        pending2FALogin.delete(challengeToken);
        socket.emit('auth:2fa-error', { message: 'Слишком много неверных попыток, попробуй войти заново.', expired: true });
        return;
      }
      socket.emit('auth:2fa-error', { message: 'Неверный код.' });
      return;
    }

    pending2FALogin.delete(challengeToken);
    loginAccount(socket, account, false, issueSession(account.id));
  });

  // ----------------------------------------------------------------
  // E2E-шифрование: клиент присылает свой ПУБЛИЧНЫЙ ключ (ECDH,
  // JWK-формат) после генерации пары ключей в браузере. Приватный
  // ключ сервер никогда не получает и не хранит — только публичный,
  // который и так предназначен для раздачи всем.
  // ----------------------------------------------------------------
  socket.on('keys:register', (payload) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account) return;
    const jwk = payload && payload.publicKeyJwk;
    if (!jwk || typeof jwk !== 'object') return;
    account.publicKey = jwk;
    persist();

    // Раздаём обновлённый публичный ключ участникам личных чатов со мной,
    // чтобы они могли (пере)вычислить общий секрет, если я сменил ключ
    // (например, вошёл с нового устройства/браузера).
    for (const chat of chats.values()) {
      if (chat.isGroup || !chat.members.has(accountId)) continue;
      const peerId = Array.from(chat.members).find((id) => id !== accountId);
      const peerSockets = peerId && accountSockets.get(peerId);
      if (peerSockets) {
        for (const sid of peerSockets) {
          io.to(sid).emit('chat:upsert', chatListEntry(chat, peerId));
        }
      }
    }
  });

  socket.on('account:rename', (newName) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account) return;
    const clean = (newName || '').toString().trim().slice(0, NAME_MAX);
    if (!clean) return;
    account.name = clean;
    account.color = avatarColor(clean);
    persist();
    socket.emit('account:updated', publicAccount(account));
    socket.to(DEFAULT_CHAT_ID).emit('user:renamed', publicAccount(account));
  });

  // Смена юзернейма из Настроек. Юзернейм по-прежнему обязателен —
  // это логин аккаунта, снять его совсем нельзя, можно только сменить
  // на другой свободный.
  socket.on('account:set-username', (rawUsername) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account) return;

    const usernameCheck = validateUsername(rawUsername);
    if (usernameCheck.error) {
      socket.emit('account:username-error', { message: usernameCheck.error });
      return;
    }

    const owner = usedUsernames.get(usernameCheck.normalized);
    if (owner && owner !== accountId) {
      socket.emit('account:username-error', { message: `Юзернейм @${usernameCheck.value} уже занят.` });
      return;
    }

    usedUsernames.delete(normalizeUsername(account.username));
    usedUsernames.set(usernameCheck.normalized, accountId);
    account.username = usernameCheck.value;
    persist();

    socket.emit('account:updated', publicAccount(account));
    socket.to(DEFAULT_CHAT_ID).emit('user:renamed', publicAccount(account));
  });

  // Короткое "о себе" в профиле — чисто описательное поле, ни на что
  // в логике сервера не влияет, поэтому в отличие от имени/юзернейма
  // не требует проверки на уникальность, только на длину.
  socket.on('account:set-bio', (rawBio) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account) return;
    account.bio = (rawBio || '').toString().trim().slice(0, BIO_MAX);
    persist();
    socket.emit('account:updated', publicAccount(account));
    socket.to(DEFAULT_CHAT_ID).emit('user:renamed', publicAccount(account));
  });

  // ----------------------------------------------------------------
  // Email: смена/добавление из Настроек (для аккаунтов, заведённых до
  // появления этого поля, или чтобы сменить адрес). Email — приватное
  // поле, поэтому в отличие от юзернейма никуда, кроме этого сокета, не
  // рассылается. Каждая смена требует повторного подтверждения.
  // ----------------------------------------------------------------
  socket.on('account:set-email', (rawEmail) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account) return;

    const emailCheck = validateEmail(rawEmail);
    if (emailCheck.error) {
      socket.emit('account:email-error', { message: emailCheck.error });
      return;
    }
    if (account.email && emailCheck.normalized === normalizeEmail(account.email)) {
      socket.emit('account:email-error', { message: 'Это уже твой текущий email.' });
      return;
    }
    const owner = usedEmails.get(emailCheck.normalized);
    if (owner && owner !== accountId) {
      socket.emit('account:email-error', { message: 'Этот email уже привязан к другому аккаунту.' });
      return;
    }

    if (account.email) usedEmails.delete(normalizeEmail(account.email));
    usedEmails.set(emailCheck.normalized, accountId);
    account.email = emailCheck.value;
    account.emailVerified = false;
    persist();
    issueEmailVerification(account);

    socket.emit('account:updated', privateAccountView(account));
  });

  // Переход по ссылке из письма подтверждения. Намеренно не требует
  // текущей сессии на этом сокете — ссылку можно открыть в любом
  // браузере/на любом устройстве, токен сам по себе однозначно
  // указывает на аккаунт.
  socket.on('auth:verify-email', (payload) => {
    const token = (payload && payload.token ? String(payload.token) : '');
    const entry = token && emailVerificationTokens.get(token);
    if (!entry || entry.expiresAt < Date.now()) {
      emailVerificationTokens.delete(token);
      socket.emit('auth:email-verify-error', { message: 'Ссылка недействительна или истекла. Запроси новую в Настройках.' });
      return;
    }
    const account = accounts.get(entry.accountId);
    emailVerificationTokens.delete(token);
    if (!account) {
      socket.emit('auth:email-verify-error', { message: 'Аккаунт не найден.' });
      return;
    }

    account.emailVerified = true;
    persist();
    socket.emit('auth:email-verified', {});

    // Если ссылку открыли в том же браузере, где сейчас залогинен именно
    // этот аккаунт — сразу обновляем бейдж в интерфейсе, без перезахода.
    if (socketToAccount.get(socket.id) === account.id) {
      socket.emit('account:updated', privateAccountView(account));
    }
  });

  // Повторная отправка письма подтверждения (кнопка в Настройках) — с
  // простым троттлингом, чтобы нельзя было засыпать чей-то ящик.
  socket.on('auth:resend-verification', () => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account || !account.email) return;
    if (account.emailVerified) {
      socket.emit('account:email-error', { message: 'Email уже подтверждён.' });
      return;
    }
    const cooldownUntil = emailResendCooldowns.get(accountId) || 0;
    const secondsLeft = Math.ceil((cooldownUntil - Date.now()) / 1000);
    if (secondsLeft > 0) {
      socket.emit('account:email-error', { message: `Подожди ${secondsLeft} сек. и попробуй снова.` });
      return;
    }
    issueEmailVerification(account);
    emailResendCooldowns.set(accountId, Date.now() + EMAIL_RESEND_COOLDOWN_MS);
    socket.emit('account:email-resent', {});
  });

  // ----------------------------------------------------------------
  // 2FA (TOTP) — включение/выключение из Настроек. Три шага: начать
  // настройку (получить секрет и QR), подтвердить кодом с телефона
  // (после этого 2FA реально включается), при необходимости выключить.
  // ----------------------------------------------------------------
  socket.on('2fa:setup-start', () => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account) return;
    if (account.twoFactorEnabled) {
      socket.emit('2fa:error', { message: '2FA уже включена. Сначала отключи её, если хочешь настроить заново.' });
      return;
    }
    const secret = generateTotpSecret();
    pending2FASetup.set(accountId, secret);
    socket.emit('2fa:setup-data', { secret, otpauthUrl: buildOtpauthUrl(account.username, secret) });
  });

  socket.on('2fa:setup-confirm', ({ token } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account) return;
    const secret = pending2FASetup.get(accountId);
    if (!secret) {
      socket.emit('2fa:error', { message: 'Сначала начни настройку — секрет не найден или уже истёк.' });
      return;
    }
    if (!verifyTotpToken(secret, token)) {
      socket.emit('2fa:error', { message: 'Неверный код. Проверь время на телефоне и попробуй ещё раз.' });
      return;
    }
    pending2FASetup.delete(accountId);
    account.twoFactorSecret = secret;
    account.twoFactorEnabled = true;
    const recoveryCodes = generateRecoveryCodes();
    account.twoFactorRecoveryCodes = recoveryCodes.map((c) => hashPassword(c));
    persist();
    socket.emit('2fa:setup-ok', { recoveryCodes });
    socket.emit('account:updated', privateAccountView(account));
  });

  socket.on('2fa:disable', ({ token, password } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account || !account.twoFactorEnabled) return;
    // Разрешаем отключить либо текущим TOTP-кодом, либо паролем аккаунта —
    // пароль как более доступный вариант, если телефон с приложением
    // недоступен, но сам аккаунт под рукой.
    const okByToken = token && verifyTotpToken(account.twoFactorSecret, token);
    const okByPassword = password && verifyPassword(String(password), account.passwordHash);
    if (!okByToken && !okByPassword) {
      socket.emit('2fa:error', { message: 'Неверный код или пароль.' });
      return;
    }
    account.twoFactorEnabled = false;
    account.twoFactorSecret = null;
    account.twoFactorRecoveryCodes = [];
    persist();
    socket.emit('2fa:disable-ok');
    socket.emit('account:updated', privateAccountView(account));
  });

  // Новый набор резервных кодов — старые (если остались) перестают
  // работать. Требует подтверждения текущим кодом, как и всё вокруг 2FA.
  socket.on('2fa:regenerate-recovery-codes', ({ token } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account || !account.twoFactorEnabled) return;
    if (!verifyTotpToken(account.twoFactorSecret, token)) {
      socket.emit('2fa:error', { message: 'Неверный код.' });
      return;
    }
    const recoveryCodes = generateRecoveryCodes();
    account.twoFactorRecoveryCodes = recoveryCodes.map((c) => hashPassword(c));
    persist();
    socket.emit('2fa:setup-ok', { recoveryCodes });
  });

  socket.on('chat:join', (chatId) => {
    const chat = chats.get(chatId);
    if (!chat) return;
    if (!chat.isGroup) {
      const accountId = socketToAccount.get(socket.id);
      if (!accountId || !chat.members.has(accountId)) return;
    }
    socket.join(chatId);
    socket.emit('chat:history', { chatId, messages: chat.messages });
  });

  // ----------------------------------------------------------------
  // Контакты: поиск людей по юзернейму, список контактов, открытие
  // личного чата и просмотр профиля.
  // ----------------------------------------------------------------
  socket.on('contacts:search', (rawQuery) => {
    const accountId = socketToAccount.get(socket.id);
    if (!accountId) return;
    const q = normalizeUsername(rawQuery);
    if (!q) { socket.emit('contacts:search-results', []); return; }
    const results = Array.from(accounts.values())
      .filter((a) => a.id !== accountId && a.username.toLowerCase().includes(q))
      .slice(0, 20)
      .map((a) => ({ ...publicAccount(a), online: isOnline(a.id) }));
    socket.emit('contacts:search-results', results);
  });

  socket.on('contacts:list', () => {
    const accountId = socketToAccount.get(socket.id);
    if (!accountId) return;
    socket.emit('contacts:list', contactsPublicList(accountId));
  });

  socket.on('contacts:add', ({ accountId: targetId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    if (!accountId || !targetId || !accounts.has(targetId)) return;
    addContact(accountId, targetId);
    persist();
    socket.emit('contacts:list', contactsPublicList(accountId));
  });

  socket.on('contacts:remove', ({ accountId: targetId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    if (!accountId) return;
    const set = contacts.get(accountId);
    if (set) set.delete(targetId);
    persist();
    socket.emit('contacts:list', contactsPublicList(accountId));
  });

  // Открыть (или создать) личный чат с другим аккаунтом — доступно и
  // без предварительного добавления в контакты (как в обычных
  // мессенджерах: начать переписку можно сразу, контакт добавляется
  // автоматически для обеих сторон).
  socket.on('contacts:open-chat', ({ accountId: targetId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const targetAccount = targetId && accounts.get(targetId);
    if (!accountId || !targetAccount || targetId === accountId) return;

    const chat = getOrCreateDirectChat(accountId, targetId);
    socket.join(chat.id);
    addContact(accountId, targetId);
    addContact(targetId, accountId);
    persist();

    const myEntry = chatListEntry(chat, accountId);
    socket.emit('chat:upsert', myEntry);
    socket.emit('contacts:list', contactsPublicList(accountId));
    socket.emit('chat:history', { chatId: chat.id, messages: chat.messages });
    // Ответ именно на этот запрос — чтобы клиент сразу переключился на чат.
    socket.emit('contacts:chat-opened', myEntry);

    // Второй участник тоже сразу получает этот чат в списке, если он
    // сейчас онлайн (не нужно ждать первого сообщения или перезахода).
    const targetSockets = accountSockets.get(targetId);
    if (targetSockets) {
      for (const sid of targetSockets) {
        io.sockets.sockets.get(sid)?.join(chat.id);
        io.to(sid).emit('chat:upsert', chatListEntry(chat, targetId));
        io.to(sid).emit('contacts:list', contactsPublicList(targetId));
      }
    }
  });

  socket.on('profile:get', ({ accountId: targetId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const account = targetId && accounts.get(targetId);
    if (!accountId || !account) { socket.emit('profile:error', { message: 'Аккаунт не найден.' }); return; }
    const myContacts = contacts.get(accountId);
    socket.emit('profile:data', {
      ...publicAccount(account),
      online: isOnline(account.id),
      isContact: !!(myContacts && myContacts.has(account.id)),
      isSelf: account.id === accountId,
      isBlocked: isBlockedBy(accountId, account.id),
    });
  });

  // Личная блокировка другого пользователя (не путать с админ-баном):
  // после блокировки ни один из вас не может писать другому в личном
  // чате (см. проверку в message:send), пока блокировка не снята.
  function notifyBlockStateChanged(accountId, targetId) {
    const directChat = chats.get(directChatId(accountId, targetId));
    if (!directChat) return;
    for (const [uid] of [[accountId], [targetId]]) {
      const sockets = accountSockets.get(uid);
      if (!sockets) continue;
      for (const sid of sockets) io.to(sid).emit('chat:upsert', chatListEntry(directChat, uid));
    }
  }

  // Рассылает свежий список заблокированных пользователей во все сессии
  // accountId (у человека может быть открыто несколько вкладок/устройств).
  function pushBlockedList(accountId) {
    const sockets = accountSockets.get(accountId);
    if (!sockets) return;
    const list = blockedPublicList(accountId);
    for (const sid of sockets) io.to(sid).emit('blocked:list', list);
  }

  socket.on('user:block', ({ accountId: targetId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    if (!accountId || !targetId || targetId === accountId || !accounts.has(targetId)) return;
    if (!blockedUsers.has(accountId)) blockedUsers.set(accountId, new Set());
    blockedUsers.get(accountId).add(targetId);
    persist();
    socket.emit('profile:data', { ...publicAccount(accounts.get(targetId)), online: isOnline(targetId), isContact: !!(contacts.get(accountId) && contacts.get(accountId).has(targetId)), isSelf: false, isBlocked: true });
    notifyBlockStateChanged(accountId, targetId);
    pushBlockedList(accountId);
  });

  socket.on('user:unblock', ({ accountId: targetId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    if (!accountId || !targetId) return;
    const set = blockedUsers.get(accountId);
    if (set) set.delete(targetId);
    persist();
    const target = accounts.get(targetId);
    notifyBlockStateChanged(accountId, targetId);
    pushBlockedList(accountId);
    if (!target) return;
    socket.emit('profile:data', { ...publicAccount(target), online: isOnline(targetId), isContact: !!(contacts.get(accountId) && contacts.get(accountId).has(targetId)), isSelf: false, isBlocked: false });
  });

  // Экран «Заблокированные» в настройках запрашивает список отдельно от
  // профиля — чтобы открыть его, не нужно заходить в профиль каждого.
  socket.on('blocked:list', () => {
    const accountId = socketToAccount.get(socket.id);
    if (!accountId) return;
    socket.emit('blocked:list', blockedPublicList(accountId));
  });

  socket.on('message:send', (payload) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account) return;

    if (isMessageRateLimited(accountId)) {
      socket.emit('message:error', { message: 'Слишком много сообщений подряд. Подожди немного.' });
      return;
    }

    const chat = chats.get(payload.chatId) || chats.get(DEFAULT_CHAT_ID);

    // Личный чат с кем-то, кто заблокирован (мной) или заблокировал меня —
    // сообщение не доставляется. Групповые чаты блокировка не затрагивает.
    if (!chat.isGroup) {
      const otherId = Array.from(chat.members).find((id) => id !== accountId);
      if (otherId && isBlockedEitherWay(accountId, otherId)) {
        socket.emit('message:error', { message: 'Нельзя отправить сообщение: один из вас заблокировал другого.' });
        return;
      }
    }

    // Личные (1-на-1) сообщения — текст, стикеры и GIF — приходят уже
    // зашифрованными на клиенте (AES-GCM, ключ выведен через ECDH и
    // серверу не известен). Сервер в этом случае просто хранит и
    // пересылает непрозрачный блоб — ciphertext/iv — и НЕ должен и не
    // может прочитать text/stickerEmoji/gifUrl. Групповые чаты пока идут
    // как раньше, открытым текстом (см. ограничения E2E-раздела в app.js).
    const isEncrypted = !chat.isGroup && ['text', 'sticker', 'custom-sticker', 'gif', 'voice', 'group-key'].includes(payload.type) && payload.encrypted === true
      && typeof payload.ciphertext === 'string' && typeof payload.iv === 'string'
      && payload.header && typeof payload.header === 'object';

    // reply/forward — метаданные, серверу не нужно (и для зашифрованных
    // чатов невозможно) понимать содержимое исходного сообщения, поэтому
    // просто доверяем клиенту id/имя отправителя для отображения цитаты.
    let replyTo = null;
    if (payload.replyTo && payload.replyTo.id) {
      const original = chat.messages.find((m) => m.id === payload.replyTo.id);
      if (original && !original.deleted) {
        replyTo = { id: original.id, senderName: original.senderName, preview: original.encrypted ? '' : summarize(original).slice(0, 120) };
      }
    }
    const forwardedFrom = payload.forwardedFrom && typeof payload.forwardedFrom.senderName === 'string'
      ? { senderName: payload.forwardedFrom.senderName.slice(0, 24) } : null;

    // Мини-приложения: сообщение — это просто ссылка на уже сохранённое
    // приложение (appId), не новая копия HTML. Денормализуем name/автора
    // прямо в сообщение, чтобы карточка в чате рендерилась без
    // дополнительного запроса — и продолжала показывать корректное имя,
    // даже если автор потом переименует/удалит своё приложение (у уже
    // отправленных карточек имя уже "запечено"). Если appId не существует
    // (удалено или опечатка) — сообщение не создаём.
    let appMeta = null;
    if (payload.type === 'app') {
      appMeta = miniApps.get(payload.appId);
      if (!appMeta) {
        socket.emit('message:error', { message: 'Это приложение больше не существует.' });
        return;
      }
    }

    const message = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      chatId: chat.id,
      senderId: account.id,
      senderName: account.name,
      senderVerified: !!account.verified,
      type: payload.type || 'text', // text | sticker | custom-sticker | gif | voice
      encrypted: isEncrypted,
      text: isEncrypted ? '' : (payload.text || '').toString().slice(0, 4000),
      ciphertext: isEncrypted ? payload.ciphertext : null,
      iv: isEncrypted ? payload.iv : null,
      // header — часть протокола Double Ratchet (публичный ratchet-ключ
      // отправителя + номер сообщения в его цепочке). Сервер не обязан
      // и не пытается понимать его смысл — просто хранит и пересылает
      // как есть, вместе с шифротекстом.
      header: isEncrypted ? payload.header : null,
      stickerEmoji: payload.stickerEmoji || null,
      // Кастомный стикер (загруженная пользователем картинка) — как и
      // gifUrl, это просто URL (свой /stickers/... или чужой), не бинарные
      // данные; в незашифрованных группах шлём как есть, в личных чатах
      // шифруется целиком вместе с остальным telом сообщения (см. gifUrl).
      stickerUrl: (!isEncrypted && payload.type === 'custom-sticker') ? (payload.stickerUrl || '').toString().slice(0, 300) : null,
      gifUrl: payload.gifUrl || null,
      voiceData: (!isEncrypted && payload.type === 'voice') ? (payload.voiceData || null) : null,
      voiceDuration: payload.type === 'voice' ? Math.min(600, Math.max(0, Number(payload.voiceDuration) || 0)) : null,
      // Файлы/документы: приходят как data URL (base64) с клиента, как и
      // голосовые. Ограничение размера — на клиенте (см. app.js), но
      // сервер тоже режет строку на всякий случай, чтобы не раздувать
      // JSON-хранилище одним чрезмерно большим файлом.
      fileData: (!isEncrypted && payload.type === 'file') ? (payload.fileData || null) : null,
      fileName: payload.type === 'file' ? (payload.fileName || 'файл').toString().slice(0, 180) : null,
      fileSize: payload.type === 'file' ? Math.max(0, Number(payload.fileSize) || 0) : null,
      fileMime: payload.type === 'file' ? (payload.fileMime || '').toString().slice(0, 100) : null,
      appId: appMeta ? appMeta.id : null,
      appName: appMeta ? appMeta.name : null,
      appOwnerName: appMeta ? appMeta.ownerName : null,
      replyTo,
      forwardedFrom,
      reactions: {},
      edited: false,
      deleted: false,
      time: Date.now(),
      read: false,
      // Упоминания @username: имеют смысл только в открытых (не E2E)
      // групповых текстовых сообщениях — в личных чатах сервер не видит
      // текст (он зашифрован), а групповые пока идут открытым текстом.
      mentions: (!isEncrypted && chat.isGroup && payload.type === 'text') ? extractMentions(payload.text, chat) : [],
    };

    // Простая защита от переполнения store.json одним огромным файлом
    // (клиент уже ограничивает выбор файла, это подстраховка на сервере).
    const MAX_FILE_DATA_LEN = 15 * 1024 * 1024 * 1.4; // ~15MB бинарных данных в base64
    if (message.fileData && message.fileData.length > MAX_FILE_DATA_LEN) {
      socket.emit('message:error', { message: 'Файл слишком большой (максимум 15 МБ).' });
      return;
    }

    chat.messages.push(message);
    if (chat.messages.length > 500) chat.messages.shift();
    persist();

    io.to(chat.id).emit('message:new', message);
    pushBotUpdates(chat, message);
    notifyMentions(chat, message, account);
  });

  socket.on('typing', ({ chatId, isTyping }) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account) return;
    socket.to(chatId).emit('typing', { name: account.name, isTyping });
  });

  socket.on('message:read', ({ chatId, messageId }) => {
    const chat = chats.get(chatId);
    if (!chat) return;
    const msg = chat.messages.find((m) => m.id === messageId);
    if (msg) {
      msg.read = true;
      persist();
      io.to(chatId).emit('message:read', { chatId, messageId });
    }
  });

  // Отдельно от message:read (который двигает галочки ✓✓ у чужих
  // сообщений) — chat:read двигает персональный курсор "прочитано до"
  // этого пользователя, от которого считается бейдж непрочитанных.
  // Клиент шлёт это при открытии чата / получении нового сообщения в
  // открытом чате, а не на каждое сообщение по отдельности.
  socket.on('chat:read', ({ chatId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.members.has(accountId)) return;
    const last = chat.messages[chat.messages.length - 1];
    if (!last) return;
    setLastRead(accountId, chat.id, last.id);
    persist();
    sendChatUpsertTo(accountId, chat);
  });

  // Архивация — персональная: не трогает других участников чата, поэтому
  // рассылаем chat:upsert только тому, кто её включил/выключил.
  socket.on('chat:archive', ({ chatId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.members.has(accountId)) return;
    if (!archivedChats.has(accountId)) archivedChats.set(accountId, new Set());
    archivedChats.get(accountId).add(chatId);
    persist();
    sendChatUpsertTo(accountId, chat);
  });

  socket.on('chat:unarchive', ({ chatId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat) return;
    archivedChats.get(accountId)?.delete(chatId);
    persist();
    sendChatUpsertTo(accountId, chat);
  });

  socket.on('chat:create', (payload) => {
    const accountId = socketToAccount.get(socket.id);
    if (!accountId) return;
    const creator = accounts.get(accountId);
    if (creator && creator.restrictions && creator.restrictions.canCreateGroups === false) {
      socket.emit('chat:create-error', { message: 'Администратор запретил тебе создавать группы.' });
      return;
    }
    const name = typeof payload === 'string' ? payload : (payload && payload.name);
    const memberIds = (payload && typeof payload === 'object' && Array.isArray(payload.memberIds)) ? payload.memberIds : [];
    const id = `chat-${Date.now()}`;
    const members = new Set([accountId]);
    for (const mid of memberIds) if (accounts.has(mid)) members.add(mid);
    const chat = {
      id,
      name: (name || 'Новый чат').toString().slice(0, 40),
      isGroup: true,
      members,
      admins: new Set([accountId]),
      owner: accountId,
      description: '',
      inviteCode: crypto.randomBytes(6).toString('hex'),
      pinnedMessageIds: [],
      messages: [],
      createdAt: Date.now(),
    };
    chats.set(id, chat);
    persist();
    for (const mid of members) {
      const sockets = accountSockets.get(mid);
      if (!sockets) continue;
      for (const sid of sockets) {
        io.sockets.sockets.get(sid)?.join(id);
        io.to(sid).emit(mid === accountId ? 'chat:created' : 'chat:upsert', mid === accountId ? { id, name: chat.name } : chatListEntry(chat, mid));
      }
    }
  });

  // ----------------------------------------------------------------
  // Управление группой: участники, роли (админ), выход из группы.
  // ----------------------------------------------------------------
  socket.on('group:add-members', ({ chatId, accountIds } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.isGroup || !isChatAdmin(chat, accountId)) return;
    const added = [];
    for (const targetId of Array.isArray(accountIds) ? accountIds : []) {
      const targetAccount = accounts.get(targetId);
      if (!targetAccount || chat.members.has(targetId)) continue;
      chat.members.add(targetId);
      added.push(targetAccount);
      const sockets = accountSockets.get(targetId);
      if (sockets) {
        for (const sid of sockets) {
          io.sockets.sockets.get(sid)?.join(chat.id);
          io.to(sid).emit('chat:upsert', chatListEntry(chat, targetId));
          io.to(sid).emit('chat:history', { chatId: chat.id, messages: chat.messages });
        }
      }
    }
    if (added.length) {
      persist();
      const me = accounts.get(accountId);
      systemMessage(chat, `${me.name} добавил(а): ${added.map((a) => a.name).join(', ')}`);
      broadcastChatUpsert(chat);
    }
  });

  socket.on('group:remove-member', ({ chatId, accountId: targetId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.isGroup || !isChatAdmin(chat, accountId)) return;
    if (targetId === chat.owner || !chat.members.has(targetId)) return;
    chat.members.delete(targetId);
    chat.admins.delete(targetId);
    persist();
    const targetSockets = accountSockets.get(targetId);
    if (targetSockets) {
      for (const sid of targetSockets) {
        io.sockets.sockets.get(sid)?.leave(chat.id);
        io.to(sid).emit('group:removed', { chatId: chat.id });
      }
    }
    // Оставшиеся участники должны провести ротацию sender key (Sender
    // Keys E2E) — ушедший больше не должен иметь ключ для будущих
    // сообщений группы. К этому моменту сокеты удалённого уже вышли из
    // room (см. выше), поэтому он сам это событие не получит.
    io.to(chat.id).emit('group:rekey-needed', { chatId: chat.id, removedAccountId: targetId });
    const target = accounts.get(targetId);
    systemMessage(chat, `${target ? target.name : 'Участник'} удалён(а) из группы`);
    broadcastChatUpsert(chat);
  });

  socket.on('group:leave', ({ chatId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.isGroup || !chat.members.has(accountId)) return;
    if (accountId === chat.owner) return; // владелец должен сначала передать группу/удалить её
    chat.members.delete(accountId);
    chat.admins.delete(accountId);
    persist();
    const sockets = accountSockets.get(accountId);
    if (sockets) for (const sid of sockets) io.sockets.sockets.get(sid)?.leave(chat.id);
    // Оставшиеся участники должны провести ротацию sender key — см.
    // комментарий в group:remove-member выше, логика идентична.
    io.to(chat.id).emit('group:rekey-needed', { chatId: chat.id, removedAccountId: accountId });
    const me = accounts.get(accountId);
    systemMessage(chat, `${me.name} покинул(а) группу`);
    broadcastChatUpsert(chat);
  });

  socket.on('group:set-admin', ({ chatId, accountId: targetId, isAdmin } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.isGroup || !isChatOwner(chat, accountId)) return;
    if (targetId === chat.owner || !chat.members.has(targetId)) return;
    if (isAdmin) chat.admins.add(targetId); else chat.admins.delete(targetId);
    persist();
    broadcastChatUpsert(chat);
    const target = accounts.get(targetId);
    systemMessage(chat, `${target ? target.name : 'Участник'} ${isAdmin ? 'назначен(а) админом' : 'больше не админ'}`);
    socket.emit('group:members-list', groupMembersList(chat));
  });

  function groupMembersList(chat) {
    return {
      chatId: chat.id,
      owner: chat.owner,
      members: Array.from(chat.members).map((id) => {
        const a = accounts.get(id);
        return a ? { ...publicAccount(a), online: isOnline(id), isAdmin: isChatAdmin(chat, id), isOwner: id === chat.owner } : null;
      }).filter(Boolean),
    };
  }

  socket.on('group:members', ({ chatId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.isGroup || !chat.members.has(accountId)) return;
    socket.emit('group:members-list', groupMembersList(chat));
  });

  // ----------------------------------------------------------------
  // GROUP E2E (Sender Keys): сервер не расшифровывает групповые
  // сообщения — только ретранслирует и хранит непрозрачный ciphertext.
  // ----------------------------------------------------------------
  socket.on('group-msg:send', (payload) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account) return;

    const chat = chats.get(payload && payload.chatId);
    if (!chat || !chat.isGroup || !chat.members.has(accountId)) return;

    // Тот же лимит частоты, что и для обычных сообщений — переиспользуем
    // существующую функцию, не изобретаем отдельный счётчик.
    if (isMessageRateLimited(accountId)) {
      socket.emit('message:error', { message: 'Слишком много сообщений подряд. Подожди немного.' });
      return;
    }

    if (
      typeof payload.chainId !== 'string' || payload.chainId.length > 100 ||
      typeof payload.iv !== 'string' ||
      typeof payload.ciphertext !== 'string' ||
      !Number.isInteger(payload.iteration) || payload.iteration < 0
    ) return;

    const message = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      chatId: chat.id,
      senderId: account.id,
      senderName: account.name,
      senderVerified: !!account.verified,
      type: 'group-e2e',
      encrypted: true,
      text: '', // сервер не видит и не хранит текст — только непрозрачный ciphertext ниже
      ciphertext: payload.ciphertext,
      iv: payload.iv,
      // header — публичные метаданные Sender Keys (какая цепочка/какой
      // номер сообщения в ней), НЕ содержит ключевого материала. Клиент
      // использует их, чтобы понять, каким chain key расшифровывать —
      // сервер их смысла не понимает и не обязан понимать, как и в
      // личных чатах с header Double Ratchet.
      header: { chainId: payload.chainId, iteration: payload.iteration },
      reactions: {},
      edited: false,
      deleted: false,
      time: Date.now(),
      read: false,
      // @упоминания в зашифрованных группах не работают — сервер не
      // видит текст, чтобы их извлечь. Это та же честная граница, что
      // уже описана для личных чатов в комментариях app.js.
      mentions: [],
    };

    chat.messages.push(message);
    if (chat.messages.length > 500) chat.messages.shift();
    persist();

    io.to(chat.id).emit('group-msg:new', message);
  });

  // ----------------------------------------------------------------
  // Реакции, редактирование, удаление, закреп сообщений.
  // ----------------------------------------------------------------
  socket.on('reaction:toggle', ({ chatId, messageId, emoji } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.members.has(accountId) || !emoji) return;
    const msg = chat.messages.find((m) => m.id === messageId);
    if (!msg || msg.deleted) return;
    if (!msg.reactions) msg.reactions = {};
    const list = msg.reactions[emoji] || [];
    const idx = list.indexOf(accountId);
    if (idx >= 0) list.splice(idx, 1); else list.push(accountId);
    if (list.length) msg.reactions[emoji] = list; else delete msg.reactions[emoji];
    persist();
    io.to(chat.id).emit('message:reaction', { chatId: chat.id, messageId, reactions: msg.reactions });
  });

  socket.on('message:edit', (payload = {}) => {
    const { chatId, messageId } = payload;
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat) return;
    const msg = chat.messages.find((m) => m.id === messageId);
    if (!msg || msg.deleted || msg.senderId !== accountId || msg.type === 'system') return;
    if (msg.encrypted) {
      if (typeof payload.ciphertext !== 'string' || typeof payload.iv !== 'string' || !payload.header) return;
      msg.ciphertext = payload.ciphertext;
      msg.iv = payload.iv;
      msg.header = payload.header;
    } else {
      if (typeof payload.text !== 'string') return;
      msg.text = payload.text.slice(0, 4000);
    }
    msg.edited = true;
    msg.editedAt = Date.now();
    persist();
    io.to(chat.id).emit('message:edited', msg);
    if (chat.messages[chat.messages.length - 1] === msg) broadcastChatUpsert(chat);
  });

  socket.on('message:delete', ({ chatId, messageId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat) return;
    const msg = chat.messages.find((m) => m.id === messageId);
    if (!msg || msg.deleted || msg.type === 'system') return;
    if (msg.senderId !== accountId && !isChatAdmin(chat, accountId)) return;
    msg.deleted = true;
    msg.text = '';
    msg.ciphertext = null;
    msg.iv = null;
    msg.header = null;
    msg.stickerEmoji = null;
    msg.stickerUrl = null;
    msg.gifUrl = null;
    msg.voiceData = null;
    msg.fileData = null;
    msg.fileName = null;
    msg.reactions = {};
    msg.replyTo = null;
    if (chat.pinnedMessageIds) chat.pinnedMessageIds = chat.pinnedMessageIds.filter((id) => id !== messageId);
    persist();
    io.to(chat.id).emit('message:deleted', { chatId: chat.id, messageId });
    broadcastChatUpsert(chat);
  });

  // Массовое удаление (мультивыбор на клиенте) — та же проверка прав,
  // что и у одиночного message:delete, применённая к каждому id.
  // Сообщения, которые пользователю не разрешено удалять (не свои и
  // не админ группы), молча пропускаются — не отменяют весь запрос.
  socket.on('message:delete-many', ({ chatId, messageIds } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !Array.isArray(messageIds) || !messageIds.length) return;
    const deletedIds = [];
    for (const messageId of messageIds.slice(0, 200)) {
      const msg = chat.messages.find((m) => m.id === messageId);
      if (!msg || msg.deleted || msg.type === 'system') continue;
      if (msg.senderId !== accountId && !isChatAdmin(chat, accountId)) continue;
      msg.deleted = true;
      msg.text = '';
      msg.ciphertext = null;
      msg.iv = null;
      msg.header = null;
      msg.stickerEmoji = null;
      msg.stickerUrl = null;
      msg.gifUrl = null;
      msg.voiceData = null;
      msg.fileData = null;
      msg.fileName = null;
      msg.reactions = {};
      msg.replyTo = null;
      if (chat.pinnedMessageIds) chat.pinnedMessageIds = chat.pinnedMessageIds.filter((id) => id !== messageId);
      deletedIds.push(messageId);
    }
    if (!deletedIds.length) return;
    persist();
    io.to(chat.id).emit('message:deleted-many', { chatId: chat.id, messageIds: deletedIds });
    broadcastChatUpsert(chat);
  });

  // ------------------------------------------------------------------
  // Свои стикеры: пользователь загружает картинку (data URL, как
  // voice/file), сервер декодирует и пишет файл на диск в
  // STICKERS_DIR/<accountId>/<id>.<ext> — сам JSON-стор хранит только
  // метаданные (см. store.js), не base64.
  // ------------------------------------------------------------------
  const STICKER_MIME_EXT = { 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif' };
  const MAX_STICKER_BYTES = 2 * 1024 * 1024; // ~2MB

  socket.on('sticker:upload', ({ dataUrl } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    if (!accountId || typeof dataUrl !== 'string') return;
    const match = /^data:([^;]+);base64,(.+)$/.exec(dataUrl);
    if (!match) { socket.emit('sticker:error', { message: 'Некорректный файл.' }); return; }
    const [, mime, base64] = match;
    const ext = STICKER_MIME_EXT[mime];
    if (!ext) { socket.emit('sticker:error', { message: 'Поддерживаются только PNG, WebP и GIF.' }); return; }
    let buffer;
    try {
      buffer = Buffer.from(base64, 'base64');
    } catch {
      socket.emit('sticker:error', { message: 'Некорректный файл.' });
      return;
    }
    if (buffer.length > MAX_STICKER_BYTES) {
      socket.emit('sticker:error', { message: 'Стикер слишком большой (максимум 2 МБ).' });
      return;
    }
    const id = crypto.randomBytes(8).toString('hex');
    const userDir = path.join(STICKERS_DIR, accountId);
    try {
      fs.mkdirSync(userDir, { recursive: true });
      fs.writeFileSync(path.join(userDir, `${id}.${ext}`), buffer);
    } catch (err) {
      console.error('[sticker] Не удалось сохранить файл:', err.message);
      socket.emit('sticker:error', { message: 'Не удалось сохранить стикер.' });
      return;
    }
    if (!customStickers.has(accountId)) customStickers.set(accountId, []);
    const list = customStickers.get(accountId);
    list.push({ id, ext, mime, createdAt: Date.now() });
    // Ограничиваем коллекцию, чтобы она не росла бесконечно (старые
    // просто перестают быть в JSON — файлы на диске за собой не подчищаем
    // в этой версии, см. README/раздел "дальше можно добавить").
    if (list.length > 200) list.shift();
    persist();
    socket.emit('sticker:list', { stickers: customStickersPublicList(accountId) });
  });

  socket.on('sticker:delete', ({ stickerId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const list = accountId && customStickers.get(accountId);
    if (!list) return;
    const idx = list.findIndex((s) => s.id === stickerId);
    if (idx === -1) return;
    const [removed] = list.splice(idx, 1);
    try {
      fs.unlinkSync(path.join(STICKERS_DIR, accountId, `${removed.id}.${removed.ext}`));
    } catch (err) {
      // Файла может уже не быть — не критично, метаданные всё равно убрали.
    }
    persist();
    socket.emit('sticker:list', { stickers: customStickersPublicList(accountId) });
  });

  // ------------------------------------------------------------------
  // Мини-приложения: пользователь пишет/вставляет HTML, сервер сохраняет
  // его отдельным файлом (APPS_DIR/<id>.html) и раздаёт статикой по
  // /apps/<id>.html. Сообщение в чате хранит только appId — см.
  // message:send выше, где appName/appOwnerName денормализуются в
  // сообщение в момент отправки.
  // ------------------------------------------------------------------
  const MAX_APP_HTML_BYTES = 300 * 1024; // ~300KB исходного HTML — этого достаточно для калькулятора/игры/виджета, не для целого SPA
  const MAX_APPS_PER_ACCOUNT = 100;

  socket.on('app:list', () => {
    const accountId = socketToAccount.get(socket.id);
    if (!accountId) return;
    socket.emit('app:list', { apps: myAppsPublicList(accountId) });
  });

  socket.on('app:create', ({ name, html } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account) return;
    if (typeof html !== 'string' || !html.trim()) {
      socket.emit('app:error', { message: 'Вставь HTML приложения — поле пустое.' });
      return;
    }
    // Byte-length, не length строки — важно из-за кириллицы/эмодзи в коде.
    if (Buffer.byteLength(html, 'utf8') > MAX_APP_HTML_BYTES) {
      socket.emit('app:error', { message: 'Слишком большой HTML (максимум 300 КБ).' });
      return;
    }

    const id = crypto.randomBytes(8).toString('hex');
    try {
      fs.mkdirSync(APPS_DIR, { recursive: true });
      fs.writeFileSync(path.join(APPS_DIR, `${id}.html`), html, 'utf8');
    } catch (err) {
      console.error('[app] Не удалось сохранить приложение:', err.message);
      socket.emit('app:error', { message: 'Не удалось сохранить приложение.' });
      return;
    }

    const appMeta = {
      id,
      ownerId: accountId,
      ownerName: account.name,
      name: (name || '').toString().trim().slice(0, 60) || 'Без названия',
      createdAt: Date.now(),
      // Дублируем сам HTML в метаданных (не только файл на диске) — см.
      // комментарий у app.get('/apps/:id.html', ...) выше про
      // эфемерные диски на бесплатных хостингах.
      html,
    };
    miniApps.set(id, appMeta);

    // Ограничиваем число приложений на аккаунт — самое старое (по дате
    // создания) удаляем вместе с файлом, чтобы APPS_DIR не рос бесконечно.
    // Уже отправленные сообщения с удалённым appId просто перестанут
    // запускаться (как и комментарий про stickers: подчистка сообщений
    // задним числом не делается).
    const own = Array.from(miniApps.values()).filter((a) => a.ownerId === accountId).sort((a, b) => a.createdAt - b.createdAt);
    while (own.length > MAX_APPS_PER_ACCOUNT) {
      const oldest = own.shift();
      miniApps.delete(oldest.id);
      try { fs.unlinkSync(path.join(APPS_DIR, `${oldest.id}.html`)); } catch (err) { /* файла может уже не быть */ }
    }

    persist();
    socket.emit('app:created', { app: { id: appMeta.id, name: appMeta.name } });
  });

  socket.on('app:delete', ({ appId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const appMeta = accountId && miniApps.get(appId);
    if (!appMeta || appMeta.ownerId !== accountId) return;
    miniApps.delete(appId);
    try { fs.unlinkSync(path.join(APPS_DIR, `${appId}.html`)); } catch (err) { /* файла может уже не быть */ }
    persist();
    socket.emit('app:list', { apps: myAppsPublicList(accountId) });
  });

  // Закрепление: можно закрепить несколько сообщений (как в Telegram) —
  // новые добавляются в конец списка, лимит MAX_PINNED на чат (см. начало
  // файла), чтобы список не разрастался бесконечно.
  socket.on('chat:pin', ({ chatId, messageId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.members.has(accountId) || !isChatAdmin(chat, accountId)) return;
    const msg = chat.messages.find((m) => m.id === messageId);
    if (!msg || msg.deleted) return;
    if (!chat.pinnedMessageIds) chat.pinnedMessageIds = [];
    if (!chat.pinnedMessageIds.includes(messageId)) {
      chat.pinnedMessageIds.push(messageId);
      if (chat.pinnedMessageIds.length > MAX_PINNED) chat.pinnedMessageIds.shift();
    }
    persist();
    io.to(chat.id).emit('chat:pin-changed', { chatId: chat.id, pinnedMessages: pinnedInfoList(chat) });
  });

  socket.on('chat:unpin', ({ chatId, messageId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.members.has(accountId) || !isChatAdmin(chat, accountId)) return;
    if (messageId) {
      chat.pinnedMessageIds = (chat.pinnedMessageIds || []).filter((id) => id !== messageId);
    } else {
      chat.pinnedMessageIds = []; // без messageId — открепить всё разом
    }
    persist();
    io.to(chat.id).emit('chat:pin-changed', { chatId: chat.id, pinnedMessages: pinnedInfoList(chat) });
  });

  // ----------------------------------------------------------------
  // Описание и аватар группы (эмодзи-аватар, без загрузки картинки —
  // это уже отдельная задача с файлами, см. group:set-avatar только для
  // эмодзи-варианта). Инвайт-ссылки: код группы, вступление без ручного
  // добавления по контактам.
  // ----------------------------------------------------------------
  socket.on('group:set-description', ({ chatId, description } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.isGroup || !isChatAdmin(chat, accountId)) return;
    chat.description = (description || '').toString().slice(0, 300);
    persist();
    broadcastChatUpsert(chat);
  });

  socket.on('group:set-avatar', ({ chatId, avatarEmoji } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.isGroup || !isChatAdmin(chat, accountId)) return;
    const emoji = (avatarEmoji || '').toString().trim().slice(0, 8);
    chat.avatarEmoji = emoji || null;
    persist();
    broadcastChatUpsert(chat);
  });

  socket.on('group:regenerate-invite', ({ chatId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.isGroup || !isChatOwner(chat, accountId)) return;
    chat.inviteCode = crypto.randomBytes(6).toString('hex');
    persist();
    const sockets = accountSockets.get(accountId);
    if (sockets) for (const sid of sockets) io.to(sid).emit('chat:upsert', chatListEntry(chat, accountId));
  });

  socket.on('chat:join-by-invite', ({ code } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    if (!accountId || !code) {
      socket.emit('chat:join-error', { message: 'Нужно войти в аккаунт.' });
      return;
    }
    const chat = Array.from(chats.values()).find((c) => c.isGroup && c.inviteCode === code);
    if (!chat) {
      socket.emit('chat:join-error', { message: 'Ссылка недействительна или устарела.' });
      return;
    }
    if (!chat.members.has(accountId)) {
      chat.members.add(accountId);
      socket.join(chat.id);
      persist();
      const account = accounts.get(accountId);
      systemMessage(chat, `${account.name} присоединил(ась) по ссылке-приглашению`);
    }
    socket.emit('chat:joined', chatListEntry(chat, accountId));
    broadcastChatUpsert(chat);
  });

  socket.on('disconnect', () => {
    const accountId = socketToAccount.get(socket.id);
    socketToAccount.delete(socket.id);
    socketToToken.delete(socket.id);
    if (!accountId) return;

    const sockets = accountSockets.get(accountId);
    if (sockets) {
      sockets.delete(socket.id);
      if (sockets.size === 0) {
        const account = accounts.get(accountId);
        if (account) {
          account.lastSeen = Date.now();
          persist();
          io.to(DEFAULT_CHAT_ID).emit('user:offline', publicAccount(account));
          for (const chat of chats.values()) {
            if (!chat.isGroup && chat.members.has(accountId)) io.to(chat.id).emit('user:offline', publicAccount(account));
          }
          broadcastAdminAccounts();
        }
        // Последнее устройство аккаунта отключилось — убираем его из
        // всех активных звонков, иначе он "зависнет" в участниках.
        callHandlers.handleAccountFullyOffline(accountId);
      }
    }
  });
});

// ------------------------------------------------------------------
// Namespace админ-консоли. Отдельный от обычных сокетов чата — здесь
// нет ни аккаунтов, ни чатов, только пароль и список для управления
// аккаунтами/группами.
// ------------------------------------------------------------------
const adminNs = io.of('/admin');
const authorizedAdmins = new Map(); // socket.id -> имя админ-аккаунта (см. ADMIN_ACCOUNTS), прошедших admin:login

// Периодическая проверка временных банов: снимает бан сам по себе, когда
// истёк срок (см. checkBanExpiry) — без этого бан снялся бы только при
// следующей попытке пострадавшего войти. Раз в минуту достаточно: не
// критично, если разбан произойдёт с опозданием в несколько десятков
// секунд после дедлайна.
setInterval(() => {
  let changed = false;
  for (const account of accounts.values()) {
    if (checkBanExpiry(account)) changed = true;
  }
  if (changed) {
    persist();
    broadcastAdminAccounts();
    if (authorizedAdmins.size) adminNs.emit('admin:stats', adminStats());
  }
  // Заодно подчищаем брошенные 2FA-челленджи (человек ввёл пароль, увидел
  // запрос кода и просто закрыл вкладку) — иначе они бы копились вечно.
  const now = Date.now();
  for (const [token, challenge] of pending2FALogin) {
    if (challenge.expiresAt < now) pending2FALogin.delete(token);
  }
}, 60 * 1000);

// ------------------------------------------------------------------
// Журнал действий администратора. Теперь поддерживает именованные
// админ-аккаунты (ADMIN_ACCOUNTS) — если они настроены, каждая запись
// журнала хранит имя того, кто выполнил действие, а не только IP.
// Храним последние ADMIN_LOG_MAX записей в памяти; на диск не пишем,
// чтобы не раздувать store.json — после перезапуска сервера журнал
// начинается заново.
// ------------------------------------------------------------------
const ADMIN_LOG_MAX = 500;
const adminActionLogs = []; // [{ id, ts, ip, action, targetLabel, detail }]

const RESTRICTION_LABELS = {
  canCreateGroups: 'создание групп',
};

const ADMIN_ACTION_LABELS = {
  'set-verified': (d) => `${d.value ? 'Выдал' : 'Снял'} галочку подтверждения ${d.targetLabel}`,
  'set-banned': (d) => {
    if (!d.value) return `Разбанил ${d.targetLabel}`;
    if (d.until) return `Забанил ${d.targetLabel} временно, до ${new Date(d.until).toLocaleString('ru-RU')}`;
    return `Забанил ${d.targetLabel} навсегда`;
  },
  'set-restriction': (d) => `${d.value ? 'Запретил' : 'Разрешил'} ${RESTRICTION_LABELS[d.key] || d.key} для ${d.targetLabel}`,
  'kick': (d) => `Разлогинил ${d.targetLabel} на всех устройствах`,
  'reset-password': (d) => `Сбросил пароль для ${d.targetLabel}`,
  'unlock-login': (d) => `Снял блокировку входа для ${d.targetLabel}`,
  'delete-group': (d) => `Удалил группу «${d.targetLabel}»`,
  'delete-message': (d) => `Удалил сообщение в «${d.targetLabel}»`,
  'edit-message': (d) => `Изменил сообщение в «${d.targetLabel}»`,
  'pin-message': (d) => `Закрепил сообщение в «${d.targetLabel}»`,
  'unpin-message': (d) => `Открепил сообщение в «${d.targetLabel}»`,
  'create-admin': (d) => `Добавил админа «${d.targetLabel}»`,
  'delete-admin': (d) => `Удалил админа «${d.targetLabel}»`,
  'login': () => 'Вошёл в админ-консоль',
};

function adminIp(socket) {
  return (socket.handshake && socket.handshake.address) || 'неизвестно';
}

function logAdminAction(socket, action, detail = {}) {
  const entry = {
    id: `log_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    ts: Date.now(),
    ip: adminIp(socket),
    adminName: authorizedAdmins.get(socket.id) || 'неизвестно',
    action,
    detail,
  };
  adminActionLogs.push(entry);
  if (adminActionLogs.length > ADMIN_LOG_MAX) adminActionLogs.shift();
  if (authorizedAdmins.size) adminNs.emit('admin:logs', adminRecentLogs());
}

function adminRecentLogs() {
  return adminActionLogs.slice(-150).reverse().map((entry) => ({
    ...entry,
    label: (ADMIN_ACTION_LABELS[entry.action] || ((d) => entry.action))(entry.detail),
  }));
}

// Онлайн-статус в списке аккаунтов меняется независимо от действий
// самого админа (люди заходят/выходят) — рассылаем всем подключённым
// админ-сокетам свежий список, только если хоть один админ сейчас
// смотрит панель (иначе никто не увидит, а считать список лишний раз незачем).
function broadcastAdminAccounts() {
  if (authorizedAdmins.size) adminNs.emit('admin:accounts', adminAccountList());
}

adminNs.on('connection', (socket) => {
  socket.on('admin:login', (payload) => {
    const password = (payload && payload.password ? String(payload.password) : '');
    const secondsLeft = adminLockoutSecondsLeft(socket.id);
    if (secondsLeft > 0) {
      socket.emit('admin:error', { message: `Слишком много неверных попыток. Попробуй через ${secondsLeft} сек.` });
      return;
    }
    const matchedAdmin = findAdminAccountByPassword(password);
    if (!matchedAdmin) {
      adminRegisterFailedAttempt(socket.id);
      socket.emit('admin:error', { message: 'Неверный пароль.' });
      return;
    }
    adminAttempts.delete(socket.id);
    authorizedAdmins.set(socket.id, matchedAdmin.name);
    socket.emit('admin:ok', { adminName: matchedAdmin.name });
    socket.emit('admin:accounts', adminAccountList());
    socket.emit('admin:stats', adminStats());
    socket.emit('admin:groups', adminGroupList());
    socket.emit('admin:locked-logins', adminLockedLogins());
    socket.emit('admin:admins', adminAdminsList());
    logAdminAction(socket, 'login');
    socket.emit('admin:logs', adminRecentLogs());
  });

  socket.on('admin:refresh', () => {
    if (!authorizedAdmins.has(socket.id)) return;
    socket.emit('admin:accounts', adminAccountList());
    socket.emit('admin:stats', adminStats());
    socket.emit('admin:groups', adminGroupList());
    socket.emit('admin:locked-logins', adminLockedLogins());
    socket.emit('admin:admins', adminAdminsList());
    socket.emit('admin:logs', adminRecentLogs());
  });

  // Управление админами прямо из консоли: любой вошедший админ может
  // добавить нового (имя + пароль) — он тут же получает ровно те же
  // права, что и все остальные, отдельной системы ролей/разрешений нет.
  // "Встроенных" (заданных через ADMIN_ACCOUNTS/ADMIN_PASSWORD) удалить
  // отсюда нельзя — только созданных в самой консоли.
  socket.on('admin:list-admins', () => {
    if (!authorizedAdmins.has(socket.id)) return;
    socket.emit('admin:admins', adminAdminsList());
  });

  socket.on('admin:create-admin', ({ name, password } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const trimmedName = (name || '').toString().trim().slice(0, 40);
    const pass = (password || '').toString();
    if (!trimmedName) {
      socket.emit('admin:error', { message: 'Укажи имя нового админа.' });
      return;
    }
    if (pass.length < PASSWORD_MIN || pass.length > PASSWORD_MAX) {
      socket.emit('admin:error', { message: `Пароль должен быть от ${PASSWORD_MIN} до ${PASSWORD_MAX} символов.` });
      return;
    }
    if (isAdminNameTaken(trimmedName)) {
      socket.emit('admin:error', { message: 'Админ с таким именем уже есть.' });
      return;
    }
    const id = `admin_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    dynamicAdmins.set(id, {
      id,
      name: trimmedName,
      passwordHash: hashPassword(pass),
      createdAt: Date.now(),
      createdBy: authorizedAdmins.get(socket.id) || 'неизвестно',
    });
    persist();
    adminNs.emit('admin:admins', adminAdminsList());
    logAdminAction(socket, 'create-admin', { targetLabel: trimmedName });
    socket.emit('admin:action-ok', { message: `Админ «${trimmedName}» добавлен.` });
  });

  socket.on('admin:delete-admin', ({ id } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const admin = dynamicAdmins.get(id);
    if (!admin) return;
    dynamicAdmins.delete(id);
    persist();
    // Если удалённый админ сейчас залогинен где-то ещё — выкидываем его
    // из консоли, а не оставляем висеть с уже недействительным доступом.
    for (const [sid, adminName] of authorizedAdmins.entries()) {
      if (adminName === admin.name) {
        authorizedAdmins.delete(sid);
        adminNs.to(sid).emit('admin:kicked-out');
      }
    }
    adminNs.emit('admin:admins', adminAdminsList());
    logAdminAction(socket, 'delete-admin', { targetLabel: admin.name });
  });

  socket.on('admin:set-verified', ({ accountId, verified } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const account = accounts.get(accountId);
    if (!account) return;
    account.verified = !!verified;
    persist();
    logAdminAction(socket, 'set-verified', { value: account.verified, targetLabel: `@${account.username}` });

    // Обновляем самого админа и всех остальных подключённых админов.
    adminNs.emit('admin:accounts', adminAccountList());

    // Обновляем обычных клиентов: если пользователь сейчас онлайн —
    // его собственные вкладки получают обновлённый аккаунт (бейдж в
    // настройках), а остальные участники общего чата видят обновлённое
    // имя/бейдж (список чатов, шапка).
    const sockets = accountSockets.get(accountId);
    if (sockets) {
      for (const sid of sockets) {
        io.to(sid).emit('account:updated', publicAccount(account));
      }
    }
    io.to(DEFAULT_CHAT_ID).emit('user:renamed', publicAccount(account));
  });

  // Бан аккаунта: закрывает вход (пароль/сессия) и сразу выкидывает все
  // активные сокеты этого аккаунта, если он был онлайн. Разбан — просто
  // сбрасывает флаг, заново входить можно обычным способом.
  //
  // durationMs (опционально) — временный бан: если передан положительным
  // числом, аккаунт разбанится сам по себе через это время (см.
  // checkBanExpiry и периодическую проверку выше). Без durationMs —
  // бессрочный бан, как раньше. При banned:false снятие бана — как
  // ручное, так и по таймеру — всегда бессрочное (bannedUntil сбрасывается).
  socket.on('admin:set-banned', ({ accountId, banned, durationMs } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const account = accounts.get(accountId);
    if (!account) return;
    account.banned = !!banned;
    const ms = Number(durationMs);
    account.bannedUntil = (account.banned && Number.isFinite(ms) && ms > 0) ? Date.now() + ms : null;
    persist();
    logAdminAction(socket, 'set-banned', {
      value: account.banned,
      until: account.bannedUntil,
      targetLabel: `@${account.username}`,
    });
    if (account.banned) {
      revokeAllSessions(accountId);
      forceLogoutAccount(accountId, 'Аккаунт заблокирован администратором.');
    }
    adminNs.emit('admin:accounts', adminAccountList());
    adminNs.emit('admin:stats', adminStats());
  });

  // Точечное ограничение возможности аккаунта — без полного бана.
  // Сейчас поддерживается только canCreateGroups (запрет создавать новые
  // группы), но структура (account.restrictions) сделана расширяемой:
  // добавить новую возможность — значит завести новый ключ здесь и
  // проверку в соответствующем обработчике (см. chat:create).
  const ADMIN_RESTRICTION_KEYS = new Set(['canCreateGroups']);
  socket.on('admin:set-restriction', ({ accountId, key, value } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const account = accounts.get(accountId);
    if (!account || !ADMIN_RESTRICTION_KEYS.has(key)) return;
    if (!account.restrictions) account.restrictions = {};
    account.restrictions[key] = !!value;
    persist();
    logAdminAction(socket, 'set-restriction', {
      key,
      value: !!value,
      targetLabel: `@${account.username}`,
    });
    adminNs.emit('admin:accounts', adminAccountList());
  });

  // Принудительный разлогин без бана — разрывает текущие сессии/сокеты,
  // но пароль и возможность снова войти остаются рабочими.
  socket.on('admin:kick', ({ accountId } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const account = accounts.get(accountId);
    if (!account) return;
    revokeAllSessions(accountId);
    forceLogoutAccount(accountId, 'Сессия завершена администратором. Войди заново.');
    logAdminAction(socket, 'kick', { targetLabel: `@${account.username}` });
  });

  // Сброс пароля: раз восстановления пароля в приложении нет вообще (см.
  // README), это единственный способ вернуть доступ, если пользователь его
  // забыл. Новый пароль придётся сообщить человеку отдельно (не через это
  // приложение) — здесь он нигде не логируется и не хранится в открытом виде.
  socket.on('admin:reset-password', ({ accountId, newPassword } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const account = accounts.get(accountId);
    const password = (newPassword || '').toString();
    if (!account) return;
    if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
      socket.emit('admin:error', { message: `Пароль должен быть от ${PASSWORD_MIN} до ${PASSWORD_MAX} символов.` });
      return;
    }
    account.passwordHash = hashPassword(password);
    // Сброс пароля админом — это и есть штатный путь восстановления
    // доступа, если человек потерял телефон с 2FA (см. README): заодно
    // снимаем и её, иначе он всё равно не сможет войти новым паролем.
    account.twoFactorEnabled = false;
    account.twoFactorSecret = null;
    account.twoFactorRecoveryCodes = [];
    persist();
    revokeAllSessions(accountId);
    forceLogoutAccount(accountId, 'Пароль сброшен администратором — войди заново с новым паролем.');
    logAdminAction(socket, 'reset-password', { targetLabel: `@${account.username}` });
    socket.emit('admin:action-ok', { message: `Пароль для @${account.username} обновлён.` });
  });

  // Снятие временной блокировки входа (после нескольких неверных попыток
  // пароля) — на случай, если админ уверен, что это не подбор пароля
  // (например, человек просто забыл раскладку), и не хочет ждать таймаут.
  socket.on('admin:unlock-login', ({ username } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    if (!username) return;
    loginAttempts.delete(String(username));
    logAdminAction(socket, 'unlock-login', { targetLabel: `@${username}` });
    socket.emit('admin:locked-logins', adminLockedLogins());
  });

  // Удаление группового чата целиком (модерация) — общий чат (DEFAULT_CHAT_ID)
  // не удаляется, только очищается кнопкой не отсюда, это отдельная защита.
  socket.on('admin:delete-group', ({ chatId } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const chat = chats.get(chatId);
    if (!chat || !chat.isGroup || chatId === DEFAULT_CHAT_ID) return;
    for (const memberId of chat.members) {
      const sockets = accountSockets.get(memberId);
      if (!sockets) continue;
      for (const sid of sockets) {
        io.sockets.sockets.get(sid)?.leave(chat.id);
        io.to(sid).emit('group:removed', { chatId: chat.id });
      }
    }
    chats.delete(chatId);
    persist();
    logAdminAction(socket, 'delete-group', { targetLabel: chat.name });
    adminNs.emit('admin:groups', adminGroupList());
    adminNs.emit('admin:stats', adminStats());
  });

  // ----------------------------------------------------------------
  // Модерация отдельных сообщений внутри чата: посмотреть последние
  // сообщения, удалить одно конкретное (не удаляя всю группу) и
  // закрепить/открепить сообщение от лица админа. Работает для любого
  // чата (включая общий и личные), не только для тех, где сам админ
  // состоит участником — у админки нет привязки к аккаунту.
  // ----------------------------------------------------------------
  const ADMIN_MESSAGES_PAGE = 100;
  socket.on('admin:chat-messages', ({ chatId } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const chat = chats.get(chatId);
    if (!chat) return;
    const messages = chat.messages
      .slice(-ADMIN_MESSAGES_PAGE)
      .map((m) => ({
        id: m.id,
        senderName: m.senderName,
        preview: m.type === 'system' ? m.text : summarize(m),
        type: m.type || 'text',
        deleted: !!m.deleted,
        pinned: !!(chat.pinnedMessageIds && chat.pinnedMessageIds.includes(m.id)),
        editable: !m.deleted && m.type === 'text' && !m.encrypted,
        time: m.time,
      }))
      .reverse(); // новые сверху, привычнее листать
    socket.emit('admin:chat-messages', { chatId, chatName: chat.name || 'Личный чат', messages });
  });

  socket.on('admin:delete-message', ({ chatId, messageId } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const chat = chats.get(chatId);
    if (!chat) return;
    const msg = chat.messages.find((m) => m.id === messageId);
    if (!msg || msg.deleted || msg.type === 'system') return;
    msg.deleted = true;
    msg.text = '';
    msg.ciphertext = null;
    msg.iv = null;
    msg.header = null;
    msg.stickerEmoji = null;
    msg.stickerUrl = null;
    msg.gifUrl = null;
    msg.voiceData = null;
    msg.fileData = null;
    msg.fileName = null;
    msg.reactions = {};
    msg.replyTo = null;
    if (chat.pinnedMessageIds) chat.pinnedMessageIds = chat.pinnedMessageIds.filter((id) => id !== messageId);
    persist();
    io.to(chat.id).emit('message:deleted', { chatId: chat.id, messageId });
    broadcastChatUpsert(chat);
    logAdminAction(socket, 'delete-message', { targetLabel: chat.name || 'личный чат' });
    adminNs.emit('admin:stats', adminStats());
  });

  // Редактирование текста сообщения из консоли. Возможно только для
  // обычных текстовых сообщений — зашифрованные (личные E2E-чаты)
  // сервер физически не может прочитать или переписать, у него просто
  // нет ключа; для них кнопка редактирования в консоли не показывается
  // (см. admin.js), а на всякий случай проверяем и здесь тоже.
  socket.on('admin:edit-message', ({ chatId, messageId, text } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const chat = chats.get(chatId);
    if (!chat) return;
    const msg = chat.messages.find((m) => m.id === messageId);
    if (!msg || msg.deleted || msg.type === 'system' || msg.encrypted) return;
    if (msg.type !== 'text') return;
    const newText = (text || '').toString().slice(0, 4000);
    if (!newText.trim()) return;
    msg.text = newText;
    msg.edited = true;
    msg.editedAt = Date.now();
    persist();
    io.to(chat.id).emit('message:edited', msg);
    if (chat.messages[chat.messages.length - 1] === msg) broadcastChatUpsert(chat);
    logAdminAction(socket, 'edit-message', { targetLabel: chat.name || 'личный чат' });
  });

  socket.on('admin:pin-message', ({ chatId, messageId } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const chat = chats.get(chatId);
    if (!chat) return;
    const msg = chat.messages.find((m) => m.id === messageId);
    if (!msg || msg.deleted) return;
    if (!chat.pinnedMessageIds) chat.pinnedMessageIds = [];
    if (!chat.pinnedMessageIds.includes(messageId)) {
      chat.pinnedMessageIds.push(messageId);
      if (chat.pinnedMessageIds.length > MAX_PINNED) chat.pinnedMessageIds.shift();
    }
    persist();
    io.to(chat.id).emit('chat:pin-changed', { chatId: chat.id, pinnedMessages: pinnedInfoList(chat) });
    logAdminAction(socket, 'pin-message', { targetLabel: chat.name || 'личный чат' });
  });

  socket.on('admin:unpin-message', ({ chatId, messageId } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const chat = chats.get(chatId);
    if (!chat || !messageId) return;
    chat.pinnedMessageIds = (chat.pinnedMessageIds || []).filter((id) => id !== messageId);
    persist();
    io.to(chat.id).emit('chat:pin-changed', { chatId: chat.id, pinnedMessages: pinnedInfoList(chat) });
    logAdminAction(socket, 'unpin-message', { targetLabel: chat.name || 'личный чат' });
  });

  socket.on('disconnect', () => {
    authorizedAdmins.delete(socket.id);
    adminAttempts.delete(socket.id);
  });
});

const PORT = process.env.PORT || 3000;
// Ждём загрузки данных (см. dataReady выше), прежде чем начать
// принимать входящие соединения — иначе кто-то мог бы подключиться в
// то самое окно, когда аккаунты ещё не подтянуты из хранилища.
dataReady.then(() => {
  server.listen(PORT, () => {
    console.log(`Nova Messenger запущен: http://localhost:${PORT}`);
  });
});