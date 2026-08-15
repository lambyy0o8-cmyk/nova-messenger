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

// accounts: deviceId -> { deviceId, name, username, novaId, color }
// Аккаунт живёт, пока жив процесс сервера (без БД, как и раньше),
// но теперь он привязан к устройству (deviceId из localStorage браузера),
// а не к сокету — так один и тот же браузер всегда возвращается в свой аккаунт.
const accounts = new Map();
const usedNovaIds = new Set();
const usedUsernames = new Map(); // normalized (lowercase) username -> deviceId

const USERNAME_RE = /^[A-Za-z][A-Za-z0-9_]{4,31}$/; // как в Telegram: 5-32 символа, начинается с буквы

function normalizeUsername(u) {
  return (u || '').toString().trim().replace(/^@/, '').toLowerCase();
}

const socketToDevice = new Map(); // socket.id -> deviceId (текущее соединение)
const deviceSockets = new Map();  // deviceId -> Set<socket.id> (для статуса "в сети")

const chats = new Map(); // chatId -> { id, name, isGroup, members:Set<deviceId>, messages:[] }

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
// Пароль аккаунта.
// Теперь deviceId (localStorage) сам по себе НЕ даёт доступ к аккаунту —
// он определяет, к какому аккаунту вообще может логиниться этот браузер,
// но сам вход требует пароль, который знает только владелец. Пароль
// никогда не хранится и не логируется в открытом виде — только
// salt+scrypt-хеш.
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
// подряд для конкретного deviceId — временная блокировка. Это не замена
// нормальному rate-limiting по IP, но закрывает самый очевидный сценарий
// (бесконечный перебор коротких PIN-кодов через один и тот же сокет).
const loginAttempts = new Map(); // deviceId -> { count, lockedUntil }
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MS = 30 * 1000;

function registerFailedAttempt(deviceId) {
  const attempt = loginAttempts.get(deviceId) || { count: 0, lockedUntil: 0 };
  attempt.count += 1;
  if (attempt.count >= MAX_LOGIN_ATTEMPTS) {
    attempt.lockedUntil = Date.now() + LOCKOUT_MS;
    attempt.count = 0;
  }
  loginAttempts.set(deviceId, attempt);
}

function getLockoutSecondsLeft(deviceId) {
  const attempt = loginAttempts.get(deviceId);
  if (!attempt || !attempt.lockedUntil) return 0;
  const msLeft = attempt.lockedUntil - Date.now();
  return msLeft > 0 ? Math.ceil(msLeft / 1000) : 0;
}

// Внутренний "Nova ID" — не настоящий телефонный номер и никак не связан
// с реальными телефонными сетями/SMS. Это просто уникальный ярлык аккаунта
// внутри приложения, по формату похожий на номер.
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
  return { id: account.deviceId, name: account.name, username: account.username || null, novaId: account.novaId, color: account.color };
}

function publicChatList(deviceId) {
  const list = [];
  for (const chat of chats.values()) {
    if (!chat.isGroup && !chat.members.has(deviceId)) continue;
    const last = chat.messages[chat.messages.length - 1];
    list.push({
      id: chat.id,
      name: chat.name,
      isGroup: chat.isGroup,
      lastMessage: last ? summarize(last) : '',
      lastTime: last ? last.time : null,
      unread: 0,
    });
  }
  return list;
}

function summarize(msg) {
  if (msg.type === 'text') return msg.text;
  if (msg.type === 'sticker') return '\u2b50 Стикер';
  if (msg.type === 'gif') return '\ud83c\udfac GIF';
  return '';
}

io.on('connection', (socket) => {
  // ----------------------------------------------------------------
  // Вход / регистрация — один аккаунт на устройство.
  // deviceId генерируется и хранится в localStorage браузера клиента.
  // Если для этого deviceId уже есть аккаунт — просто логиним в него
  // (никакой второй аккаунт на том же устройстве создать нельзя).
  // Если аккаунта ещё нет — создаём новый и выдаём внутренний Nova ID.
  // ----------------------------------------------------------------
  socket.on('auth', (payload) => {
    const deviceId = (payload && payload.deviceId ? String(payload.deviceId) : '').slice(0, 100);
    const password = (payload && payload.password ? String(payload.password) : '');

    if (!deviceId) {
      socket.emit('auth:error', { message: 'Не удалось определить устройство. Обнови страницу.' });
      return;
    }

    if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
      socket.emit('auth:error', { message: `Пароль должен быть от ${PASSWORD_MIN} до ${PASSWORD_MAX} символов.` });
      return;
    }

    let account = accounts.get(deviceId);
    let isNewAccount = false;

    if (!account) {
      // Новый аккаунт на этом устройстве — пароль задаётся сейчас
      // и понадобится для входа в будущем (в том числе если кто-то
      // получит доступ к deviceId в localStorage — без пароля это
      // больше не даёт войти в аккаунт).
      const cleanName = ((payload && payload.name) || 'Гость').toString().trim().slice(0, 24) || 'Гость';
      account = {
        deviceId,
        name: cleanName,
        username: null,
        novaId: generateNovaId(),
        color: avatarColor(cleanName),
        passwordHash: hashPassword(password),
      };
      accounts.set(deviceId, account);
      isNewAccount = true;
    } else {
      const secondsLeft = getLockoutSecondsLeft(deviceId);
      if (secondsLeft > 0) {
        socket.emit('auth:error', { message: `Слишком много неверных попыток. Попробуй через ${secondsLeft} сек.` });
        return;
      }
      if (!verifyPassword(password, account.passwordHash)) {
        registerFailedAttempt(deviceId);
        socket.emit('auth:error', { message: 'Неверный пароль.' });
        return;
      }
      loginAttempts.delete(deviceId);
    }

    socketToDevice.set(socket.id, deviceId);
    if (!deviceSockets.has(deviceId)) deviceSockets.set(deviceId, new Set());
    const wasOffline = deviceSockets.get(deviceId).size === 0;
    deviceSockets.get(deviceId).add(socket.id);

    chats.get(DEFAULT_CHAT_ID).members.add(deviceId);
    socket.join(DEFAULT_CHAT_ID);

    socket.emit('auth:ok', {
      me: publicAccount(account),
      isNewAccount,
      chats: publicChatList(deviceId),
    });
    socket.emit('chat:history', {
      chatId: DEFAULT_CHAT_ID,
      messages: chats.get(DEFAULT_CHAT_ID).messages,
    });

    if (wasOffline) socket.to(DEFAULT_CHAT_ID).emit('user:online', publicAccount(account));
  });

  socket.on('account:rename', (newName) => {
    const deviceId = socketToDevice.get(socket.id);
    const account = deviceId && accounts.get(deviceId);
    if (!account) return;
    const clean = (newName || '').toString().trim().slice(0, 24);
    if (!clean) return;
    account.name = clean;
    account.color = avatarColor(clean);
    socket.emit('account:updated', publicAccount(account));
    socket.to(DEFAULT_CHAT_ID).emit('user:renamed', publicAccount(account));
  });

  // Юзернейм — как в Telegram: уникальный на весь сервер, необязательный,
  // 5-32 символа (буквы/цифры/подчёркивание, начинается с буквы).
  // Если введённый юзернейм уже занят другим аккаунтом — отклоняем.
  socket.on('account:set-username', (rawUsername) => {
    const deviceId = socketToDevice.get(socket.id);
    const account = deviceId && accounts.get(deviceId);
    if (!account) return;

    const trimmed = (rawUsername || '').toString().trim().replace(/^@/, '');

    // Пустая строка — снять юзернейм с аккаунта.
    if (!trimmed) {
      if (account.username) usedUsernames.delete(account.username);
      account.username = null;
      socket.emit('account:updated', publicAccount(account));
      return;
    }

    if (!USERNAME_RE.test(trimmed)) {
      socket.emit('account:username-error', {
        message: 'Юзернейм должен быть 5-32 символа: латинские буквы, цифры и _, начинаться с буквы.',
      });
      return;
    }

    const normalized = normalizeUsername(trimmed);
    const owner = usedUsernames.get(normalized);
    if (owner && owner !== deviceId) {
      socket.emit('account:username-error', { message: `Юзернейм @${trimmed} уже занят.` });
      return;
    }

    if (account.username) usedUsernames.delete(normalizeUsername(account.username));
    usedUsernames.set(normalized, deviceId);
    account.username = trimmed;

    socket.emit('account:updated', publicAccount(account));
    socket.to(DEFAULT_CHAT_ID).emit('user:renamed', publicAccount(account));
  });

  socket.on('chat:join', (chatId) => {
    const chat = chats.get(chatId);
    if (!chat) return;
    socket.join(chatId);
    socket.emit('chat:history', { chatId, messages: chat.messages });
  });

  socket.on('message:send', (payload) => {
    const deviceId = socketToDevice.get(socket.id);
    const account = deviceId && accounts.get(deviceId);
    if (!account) return;
    const chat = chats.get(payload.chatId) || chats.get(DEFAULT_CHAT_ID);

    const message = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      chatId: chat.id,
      senderId: account.deviceId,
      senderName: account.name,
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
    const deviceId = socketToDevice.get(socket.id);
    const account = deviceId && accounts.get(deviceId);
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
    const deviceId = socketToDevice.get(socket.id);
    if (!deviceId) return;
    const id = `chat-${Date.now()}`;
    const chat = { id, name: (name || 'Новый чат').slice(0, 40), isGroup: true, members: new Set([deviceId]), messages: [] };
    chats.set(id, chat);
    socket.join(id);
    socket.emit('chat:created', { id, name: chat.name });
  });

  socket.on('disconnect', () => {
    const deviceId = socketToDevice.get(socket.id);
    socketToDevice.delete(socket.id);
    if (!deviceId) return;

    const sockets = deviceSockets.get(deviceId);
    if (sockets) {
      sockets.delete(socket.id);
      if (sockets.size === 0) {
        const account = accounts.get(deviceId);
        if (account) io.to(DEFAULT_CHAT_ID).emit('user:offline', publicAccount(account));
      }
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Nova Messenger запущен: http://localhost:${PORT}`);
});