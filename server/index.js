const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(path.join(__dirname, '..', 'public')));

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

const USERNAME_RE = /^[A-Za-z][A-Za-z0-9_]{4,31}$/; // 5-32 символа, начинается с буквы
const NAME_MAX = 24;

function normalizeUsername(u) {
  return (u || '').toString().trim().replace(/^@/, '').toLowerCase();
}

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

function issueSession(accountId) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, accountId);
  return token;
}

// contacts: accountId -> Set<accountId> — список контактов пользователя.
// Хранится так же в памяти сервера, без БД.
const contacts = new Map();

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
  messages: [],
});

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

// Простая защита от подбора пароля: после нескольких неверных попыток
// подряд для конкретного юзернейма — временная блокировка попыток входа
// в этот аккаунт. Не замена нормальному rate-limiting по IP, но закрывает
// самый очевидный сценарий перебора.
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
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
if (!process.env.ADMIN_PASSWORD) {
  console.warn('[admin] ADMIN_PASSWORD не задан в окружении — используется пароль по умолчанию "admin123". Задай свой перед реальным использованием.');
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
  }));
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
  return { id: account.id, name: account.name, username: account.username, novaId: account.novaId, color: account.color, verified: !!account.verified };
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
    chat = { id, name: null, isGroup: false, members: new Set([aId, bId]), messages: [] };
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
    unread: 0,
  };
  if (!chat.isGroup) {
    const peerId = Array.from(chat.members).find((id) => id !== accountId);
    const peer = peerId && accounts.get(peerId);
    entry.peerId = peerId || null;
    entry.name = peer ? peer.name : 'Пользователь';
    entry.peerUsername = peer ? peer.username : '';
    entry.peerVerified = peer ? !!peer.verified : false;
    entry.peerOnline = peerId ? isOnline(peerId) : false;
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

function summarize(msg) {
  if (msg.type === 'text') return msg.text;
  if (msg.type === 'sticker') return '\u2b50 Стикер';
  if (msg.type === 'gif') return '\ud83c\udfac GIF';
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
    me: publicAccount(account),
    isNewAccount,
    chats: publicChatList(accountId),
    session: token,
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
  }
}

io.on('connection', (socket) => {
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

    const novaId = generateNovaId();
    const account = {
      id: novaId,
      name: cleanName,
      username: usernameCheck.value,
      novaId,
      color: avatarColor(cleanName),
      passwordHash: hashPassword(password),
      verified: false,
    };
    accounts.set(account.id, account);
    usedUsernames.set(usernameCheck.normalized, account.id);

    loginAccount(socket, account, true, issueSession(account.id));
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
    if (!account) {
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
    const usernameCheck = validateUsername(payload && payload.username);
    const password = (payload && payload.password ? String(payload.password) : '');

    if (usernameCheck.error) {
      socket.emit('auth:error', { message: usernameCheck.error });
      return;
    }
    if (!password) {
      socket.emit('auth:error', { message: 'Введи пароль.' });
      return;
    }

    const lockKey = usernameCheck.normalized;
    const secondsLeft = getLockoutSecondsLeft(lockKey);
    if (secondsLeft > 0) {
      socket.emit('auth:error', { message: `Слишком много неверных попыток. Попробуй через ${secondsLeft} сек.` });
      return;
    }

    const accountId = usedUsernames.get(usernameCheck.normalized);
    const account = accountId && accounts.get(accountId);

    if (!account || !verifyPassword(password, account.passwordHash)) {
      registerFailedAttempt(lockKey);
      socket.emit('auth:error', { message: 'Неверный юзернейм или пароль.' });
      return;
    }

    loginAttempts.delete(lockKey);
    loginAccount(socket, account, false, issueSession(account.id));
  });

  socket.on('account:rename', (newName) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account) return;
    const clean = (newName || '').toString().trim().slice(0, NAME_MAX);
    if (!clean) return;
    account.name = clean;
    account.color = avatarColor(clean);
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

    socket.emit('account:updated', publicAccount(account));
    socket.to(DEFAULT_CHAT_ID).emit('user:renamed', publicAccount(account));
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
    socket.emit('contacts:list', contactsPublicList(accountId));
  });

  socket.on('contacts:remove', ({ accountId: targetId } = {}) => {
    const accountId = socketToAccount.get(socket.id);
    if (!accountId) return;
    const set = contacts.get(accountId);
    if (set) set.delete(targetId);
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
    });
  });

  socket.on('message:send', (payload) => {
    const accountId = socketToAccount.get(socket.id);
    const account = accountId && accounts.get(accountId);
    if (!account) return;
    const chat = chats.get(payload.chatId) || chats.get(DEFAULT_CHAT_ID);

    const message = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      chatId: chat.id,
      senderId: account.id,
      senderName: account.name,
      senderVerified: !!account.verified,
      type: payload.type || 'text', // text | sticker | gif
      text: payload.text || '',
      stickerEmoji: payload.stickerEmoji || null,
      gifUrl: payload.gifUrl || null,
      time: Date.now(),
      read: false,
    };

    chat.messages.push(message);
    if (chat.messages.length > 500) chat.messages.shift();

    io.to(chat.id).emit('message:new', message);
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
      io.to(chatId).emit('message:read', { chatId, messageId });
    }
  });

  socket.on('chat:create', (name) => {
    const accountId = socketToAccount.get(socket.id);
    if (!accountId) return;
    const id = `chat-${Date.now()}`;
    const chat = { id, name: (name || 'Новый чат').slice(0, 40), isGroup: true, members: new Set([accountId]), messages: [] };
    chats.set(id, chat);
    socket.join(id);
    socket.emit('chat:created', { id, name: chat.name });
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
          io.to(DEFAULT_CHAT_ID).emit('user:offline', publicAccount(account));
          for (const chat of chats.values()) {
            if (!chat.isGroup && chat.members.has(accountId)) io.to(chat.id).emit('user:offline', publicAccount(account));
          }
        }
      }
    }
  });
});

// ------------------------------------------------------------------
// Namespace админ-консоли. Отдельный от обычных сокетов чата — здесь
// нет ни аккаунтов, ни чатов, только пароль и список для выдачи галочек.
// ------------------------------------------------------------------
const adminNs = io.of('/admin');
const authorizedAdmins = new Set(); // socket.id сокетов, прошедших admin:login

adminNs.on('connection', (socket) => {
  socket.on('admin:login', (payload) => {
    const password = (payload && payload.password ? String(payload.password) : '');
    const secondsLeft = adminLockoutSecondsLeft(socket.id);
    if (secondsLeft > 0) {
      socket.emit('admin:error', { message: `Слишком много неверных попыток. Попробуй через ${secondsLeft} сек.` });
      return;
    }
    if (password !== ADMIN_PASSWORD) {
      adminRegisterFailedAttempt(socket.id);
      socket.emit('admin:error', { message: 'Неверный пароль.' });
      return;
    }
    adminAttempts.delete(socket.id);
    authorizedAdmins.add(socket.id);
    socket.emit('admin:ok');
    socket.emit('admin:accounts', adminAccountList());
  });

  socket.on('admin:refresh', () => {
    if (!authorizedAdmins.has(socket.id)) return;
    socket.emit('admin:accounts', adminAccountList());
  });

  socket.on('admin:set-verified', ({ accountId, verified } = {}) => {
    if (!authorizedAdmins.has(socket.id)) return;
    const account = accounts.get(accountId);
    if (!account) return;
    account.verified = !!verified;

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

  socket.on('disconnect', () => {
    authorizedAdmins.delete(socket.id);
    adminAttempts.delete(socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Nova Messenger запущен: http://localhost:${PORT}`);
});