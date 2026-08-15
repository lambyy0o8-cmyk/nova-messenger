const socket = io();

// ------------------------------------------------------------------
// Состояние
// ------------------------------------------------------------------
let me = null;
let chats = [];
let activeChatId = null;
let typingTimeout = null;

const el = (id) => document.getElementById(id);

// Бейдж "подтверждён" — простой надёжный кружок с галочкой (без сложных
// путей, чтобы не было проблем с координатами SVG).
function verifiedBadge(isVerified) {
  if (!isVerified) return '';
  return `<svg class="verified-badge" viewBox="0 0 20 20" aria-label="Подтверждённый аккаунт" title="Подтверждённый аккаунт">
    <circle cx="10" cy="10" r="10"/>
    <path d="M6 10.2l2.5 2.5L14.5 7" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
}

// ------------------------------------------------------------------
// Вход / регистрация.
// Аккаунт больше не привязан к браузеру — логин это юзернейм, вход
// требует юзернейм + пароль и работает с любого устройства.
// ------------------------------------------------------------------
el('tab-login').addEventListener('click', () => switchTab('login'));
el('tab-register').addEventListener('click', () => switchTab('register'));

function switchTab(tab) {
  const isLogin = tab === 'login';
  el('tab-login').classList.toggle('active', isLogin);
  el('tab-register').classList.toggle('active', !isLogin);
  el('login-form').classList.toggle('hidden', !isLogin);
  el('register-form').classList.toggle('hidden', isLogin);
  hideLoginError();
}

function showLoginError(message) {
  const box = el('login-error');
  box.textContent = message;
  box.classList.remove('hidden');
}
function hideLoginError() {
  el('login-error').classList.add('hidden');
}
function setAuthBusy(busy) {
  el('login-username').disabled = busy;
  el('login-password').disabled = busy;
  el('login-submit').disabled = busy;
  el('register-name').disabled = busy;
  el('register-username').disabled = busy;
  el('register-password').disabled = busy;
  el('register-submit').disabled = busy;
}

el('login-submit').addEventListener('click', doLogin);
el('login-username').addEventListener('keydown', (e) => { if (e.key === 'Enter') el('login-password').focus(); });
el('login-password').addEventListener('keydown', (e) => { if (e.key === 'Enter') doLogin(); });

function doLogin() {
  const username = el('login-username').value.trim();
  const password = el('login-password').value;
  hideLoginError();
  if (!username) { el('login-username').focus(); return; }
  if (!password) { el('login-password').focus(); return; }
  setAuthBusy(true);
  el('login-submit').textContent = 'Входим…';
  socket.emit('auth:login', { username, password });
}

el('register-submit').addEventListener('click', doRegister);
el('register-name').addEventListener('keydown', (e) => { if (e.key === 'Enter') el('register-username').focus(); });
el('register-username').addEventListener('keydown', (e) => { if (e.key === 'Enter') el('register-password').focus(); });
el('register-password').addEventListener('keydown', (e) => { if (e.key === 'Enter') doRegister(); });

function doRegister() {
  const name = el('register-name').value.trim();
  const username = el('register-username').value.trim();
  const password = el('register-password').value;
  hideLoginError();
  if (!name) { el('register-name').focus(); return; }
  if (!username) { el('register-username').focus(); return; }
  if (password.length < 4) {
    showLoginError('Пароль должен быть не короче 4 символов.');
    el('register-password').focus();
    return;
  }
  setAuthBusy(true);
  el('register-submit').textContent = 'Регистрируем…';
  socket.emit('auth:register', { name, username, password });
}

// Подставляем последний использованный юзернейм на вкладке входа —
// пароль при этом нигде не хранится и вводится заново каждый раз.
window.addEventListener('DOMContentLoaded', () => {
  const savedUsername = localStorage.getItem('nova-username');
  if (!savedUsername) return;
  el('login-username').value = savedUsername;
  el('login-password').focus();
});

socket.on('auth:ok', ({ me: user, chats: chatList }) => {
  me = user;
  chats = chatList;
  if (user.username) localStorage.setItem('nova-username', user.username);
  el('login-password').value = '';
  el('register-password').value = '';
  el('login-screen').classList.add('hidden');
  el('app').classList.remove('hidden');
  renderChatList();
  renderAccountInfo();
});

socket.on('auth:error', ({ message }) => {
  setAuthBusy(false);
  el('login-submit').textContent = 'Войти';
  el('register-submit').textContent = 'Зарегистрироваться';
  showLoginError(message || 'Не удалось войти. Попробуй ещё раз.');
});

socket.on('account:updated', (user) => {
  me = { ...me, ...user };
  if (user.username) localStorage.setItem('nova-username', user.username);
  renderAccountInfo();
  hideUsernameError();
});

socket.on('account:username-error', ({ message }) => {
  showUsernameError(message);
  // Возвращаем поле к последнему подтверждённому значению аккаунта.
  el('account-username').value = me && me.username ? me.username : '';
});

socket.on('chat:created', ({ id, name }) => {
  chats.unshift({ id, name, isGroup: true, lastMessage: '', lastTime: null, unread: 0 });
  renderChatList();
  openChat(id);
});

// ------------------------------------------------------------------
// Список чатов
// ------------------------------------------------------------------
function renderChatList(filter = '') {
  const list = el('chat-list');
  list.innerHTML = '';
  const q = filter.trim().toLowerCase();
  chats
    .filter((c) => c.name.toLowerCase().includes(q))
    .forEach((c) => {
      const item = document.createElement('div');
      item.className = 'chat-item' + (c.id === activeChatId ? ' active' : '');
      item.innerHTML = `
        <div class="avatar" style="background:${avatarBg(c.name)}">${initials(c.name)}</div>
        <div class="chat-meta">
          <div class="chat-meta-top">
            <span class="chat-name">${escapeHtml(c.name)}</span>
            <span class="chat-time">${c.lastTime ? formatTime(c.lastTime) : ''}</span>
          </div>
          <div class="chat-preview">${escapeHtml(c.lastMessage || 'Нет сообщений')}</div>
        </div>
      `;
      item.addEventListener('click', () => openChat(c.id));
      list.appendChild(item);
    });
}

el('chat-search').addEventListener('input', (e) => renderChatList(e.target.value));

el('new-chat').addEventListener('click', () => {
  const name = prompt('Название нового чата:');
  if (name) socket.emit('chat:create', name);
});

function initials(name) {
  return name.trim().slice(0, 2).toUpperCase();
}
function avatarBg(name) {
  const colors = ['#e17076', '#7bc862', '#65aadd', '#a695e7', '#ee7aae', '#6ec9cb', '#faa774', '#4f95d1'];
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash);
  return colors[Math.abs(hash) % colors.length];
}

// ------------------------------------------------------------------
// Открытие чата
// ------------------------------------------------------------------
function openChat(chatId) {
  activeChatId = chatId;
  const chat = chats.find((c) => c.id === chatId);
  el('empty-state').classList.add('hidden');
  el('chat-view').classList.remove('hidden');
  el('app').classList.add('chat-open');

  el('chat-title').textContent = chat.name;
  el('chat-avatar').textContent = initials(chat.name);
  el('chat-avatar').style.background = avatarBg(chat.name);
  el('chat-status').textContent = chat.isGroup ? 'группа' : 'в сети';
  el('messages').innerHTML = '';

  socket.emit('chat:join', chatId);
  renderChatList(el('chat-search').value);
  closeAllPickers();
}

el('back-btn').addEventListener('click', () => {
  el('app').classList.remove('chat-open');
});

socket.on('chat:history', ({ chatId, messages }) => {
  if (chatId !== activeChatId) return;
  el('messages').innerHTML = '';
  messages.forEach(renderMessage);
  scrollToBottom();
});

// ------------------------------------------------------------------
// Сообщения
// ------------------------------------------------------------------
function renderMessage(msg) {
  const out = me && msg.senderId === me.id;
  const row = document.createElement('div');
  row.className = 'msg-row ' + (out ? 'out' : 'in');
  row.dataset.id = msg.id;

  let inner = '';
  if (!out) inner += `<span class="sender-name">${escapeHtml(msg.senderName)}${verifiedBadge(msg.senderVerified)}</span>`;

  let bubbleClass = 'bubble';
  let body = '';
  if (msg.type === 'sticker') {
    bubbleClass += ' sticker-bubble';
    body = msg.stickerEmoji;
  } else if (msg.type === 'gif') {
    bubbleClass += ' gif-bubble';
    body = `<img src="${escapeHtml(msg.gifUrl)}" alt="gif">`;
  } else {
    body = linkify(escapeHtml(msg.text));
  }

  const ticks = out
    ? `<span class="read-tick">${msg.read ? '✓✓' : '✓'}</span>`
    : '';

  row.innerHTML = `<div class="${bubbleClass}">${inner}${body}<span class="bubble-meta">${formatTime(msg.time)} ${ticks}</span></div>`;
  el('messages').appendChild(row);

  if (!out) socket.emit('message:read', { chatId: msg.chatId, messageId: msg.id });
}

socket.on('message:new', (msg) => {
  const chat = chats.find((c) => c.id === msg.chatId);
  if (chat) {
    chat.lastMessage = msg.type === 'text' ? msg.text : msg.type === 'sticker' ? '⭐ Стикер' : '🎬 GIF';
    chat.lastTime = msg.time;
    chats = [chat, ...chats.filter((c) => c.id !== chat.id)];
  }
  if (msg.chatId === activeChatId) {
    renderMessage(msg);
    scrollToBottom();
  } else {
    playSound();
  }
  renderChatList(el('chat-search').value);
});

socket.on('message:read', ({ chatId, messageId }) => {
  if (chatId !== activeChatId) return;
  const row = document.querySelector(`.msg-row[data-id="${messageId}"] .read-tick`);
  if (row) row.textContent = '✓✓';
});

function scrollToBottom() {
  const box = el('messages');
  box.scrollTop = box.scrollHeight;
}

// ------------------------------------------------------------------
// Отправка
// ------------------------------------------------------------------
el('composer').addEventListener('submit', (e) => {
  e.preventDefault();
  const input = el('message-input');
  const text = input.value.trim();
  if (!text || !activeChatId) return;
  socket.emit('message:send', { chatId: activeChatId, type: 'text', text });
  input.value = '';
  socket.emit('typing', { chatId: activeChatId, isTyping: false });
});

el('message-input').addEventListener('input', () => {
  if (!activeChatId) return;
  if (localStorage.getItem('nova-typing') === 'off') return;
  socket.emit('typing', { chatId: activeChatId, isTyping: true });
  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(() => socket.emit('typing', { chatId: activeChatId, isTyping: false }), 1500);
});

socket.on('typing', ({ name, isTyping }) => {
  const indicator = el('typing-indicator');
  if (isTyping) {
    indicator.textContent = `${name} печатает…`;
    indicator.classList.remove('hidden');
  } else {
    indicator.classList.add('hidden');
  }
});

function sendSticker(emoji) {
  if (!activeChatId) return;
  socket.emit('message:send', { chatId: activeChatId, type: 'sticker', stickerEmoji: emoji });
  closeAllPickers();
}
function sendGif(url) {
  if (!activeChatId) return;
  socket.emit('message:send', { chatId: activeChatId, type: 'gif', gifUrl: url });
  closeAllPickers();
}

// ------------------------------------------------------------------
// Утилиты
// ------------------------------------------------------------------
function escapeHtml(str = '') {
  return str.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function linkify(str) {
  return str.replace(/(https?:\/\/[^\s]+)/g, '<a href="$1" target="_blank" rel="noopener">$1</a>');
}
function formatTime(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
}
function playSound() {
  if (localStorage.getItem('nova-sound') === 'off') return;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const o = ctx.createOscillator();
    const g = ctx.createGain();
    o.connect(g); g.connect(ctx.destination);
    o.frequency.value = 880;
    g.gain.value = 0.05;
    o.start();
    setTimeout(() => { o.stop(); ctx.close(); }, 120);
  } catch (e) { /* тихо игнорируем */ }
}

// ==================================================================
// НАСТРОЙКИ
// ==================================================================
const ACCENTS = [
  { name: 'blue', c1: '#2AABEE', c2: '#229ED9' },
  { name: 'green', c1: '#4FC26F', c2: '#2FA352' },
  { name: 'purple', c1: '#9C6EF5', c2: '#7B4FE0' },
  { name: 'pink', c1: '#F16FA9', c2: '#DA4E8C' },
  { name: 'orange', c1: '#FAA774', c2: '#E9853F' },
  { name: 'red', c1: '#F16E6E', c2: '#DB4747' },
];

const WALLPAPERS = [
  { name: 'none', css: 'none', preview: '#e8ecef' },
  { name: 'dots', css: 'radial-gradient(rgba(0,0,0,.06) 1.4px, transparent 1.4px)', preview: 'radial-gradient(#c9ced2 1.4px, transparent 1.4px) 0 0/12px 12px, #eef1f3' },
  { name: 'diag', css: 'repeating-linear-gradient(45deg, rgba(0,0,0,.04) 0 2px, transparent 2px 14px)', preview: 'repeating-linear-gradient(45deg,#c9ced2 0 2px,transparent 2px 14px), #eef1f3' },
];

function initSettings() {
  el('open-settings').addEventListener('click', () => el('settings-overlay').classList.remove('hidden'));
  document.querySelectorAll('[data-close]').forEach((btn) => {
    btn.addEventListener('click', () => el(btn.dataset.close).classList.add('hidden'));
  });
  el('settings-overlay').addEventListener('click', (e) => {
    if (e.target.id === 'settings-overlay') el('settings-overlay').classList.add('hidden');
  });

  // Тема
  document.querySelectorAll('.theme-opt').forEach((btn) => {
    btn.addEventListener('click', () => setTheme(btn.dataset.theme));
  });

  // Акценты
  const accentBox = el('accent-options');
  ACCENTS.forEach((a) => {
    const dot = document.createElement('div');
    dot.className = 'accent-dot';
    dot.style.background = `linear-gradient(135deg, ${a.c1}, ${a.c2})`;
    dot.dataset.accent = a.name;
    dot.addEventListener('click', () => setAccent(a));
    accentBox.appendChild(dot);
  });

  // Обои
  const wallBox = el('wallpaper-options');
  WALLPAPERS.forEach((w) => {
    const opt = document.createElement('div');
    opt.className = 'wallpaper-opt';
    opt.style.background = w.preview;
    opt.dataset.wallpaper = w.name;
    opt.addEventListener('click', () => setWallpaper(w));
    wallBox.appendChild(opt);
  });

  el('font-size').addEventListener('input', (e) => {
    document.documentElement.style.setProperty('--font-size', e.target.value + 'px');
    localStorage.setItem('nova-fontsize', e.target.value);
  });

  el('rounded-toggle').addEventListener('change', (e) => {
    document.getElementById('app').classList.toggle('square-bubbles', !e.target.checked);
    localStorage.setItem('nova-rounded', e.target.checked ? '1' : '0');
  });

  el('sound-toggle').addEventListener('change', (e) => {
    localStorage.setItem('nova-sound', e.target.checked ? 'on' : 'off');
  });

  el('typing-toggle').addEventListener('change', (e) => {
    localStorage.setItem('nova-typing', e.target.checked ? 'on' : 'off');
  });

  el('account-name').addEventListener('change', (e) => {
    const newName = e.target.value.trim();
    if (!me) return;
    if (!newName || newName === me.name) { e.target.value = me.name; return; }
    socket.emit('account:rename', newName);
  });
  el('account-name').addEventListener('keydown', (e) => { if (e.key === 'Enter') e.target.blur(); });

  el('account-username').addEventListener('change', (e) => {
    if (!me) return;
    const raw = e.target.value.trim().replace(/^@/, '');
    const current = me.username || '';
    if (!raw) { e.target.value = current; return; }
    if (raw === current) return;
    socket.emit('account:set-username', raw);
  });
  el('account-username').addEventListener('input', hideUsernameError);
  el('account-username').addEventListener('keydown', (e) => { if (e.key === 'Enter') e.target.blur(); });

  el('logout-btn').addEventListener('click', logout);

  loadSettings();
}

// ------------------------------------------------------------------
// Выход из аккаунта
// ------------------------------------------------------------------
// Аккаунт больше не привязан к этому браузеру — это просто отключение
// от сокета и возврат на экран входа. Чтобы вернуться, нужно снова
// ввести юзернейм и пароль (тот же аккаунт, никакой новый не создаётся).
function logout() {
  const sure = confirm('Выйти из аккаунта?');
  if (!sure) return;

  socket.disconnect();
  window.location.reload();
}

function renderAccountInfo() {
  if (!me) return;
  el('account-avatar').textContent = initials(me.name);
  el('account-avatar').style.background = avatarBg(me.name);
  el('account-name').value = me.name;
  el('account-username').value = me.username || '';
  el('account-novaid').textContent = me.novaId || '';

  const badgeSlot = el('account-verified-badge');
  if (badgeSlot) badgeSlot.innerHTML = verifiedBadge(me.verified);
}

function showUsernameError(message) {
  const box = el('account-username-error');
  box.textContent = message || 'Не удалось сохранить юзернейм.';
  box.classList.remove('hidden');
}
function hideUsernameError() {
  el('account-username-error').classList.add('hidden');
}

function setTheme(theme) {
  localStorage.setItem('nova-theme', theme);
  applyTheme(theme);
  document.querySelectorAll('.theme-opt').forEach((b) => b.classList.toggle('selected', b.dataset.theme === theme));
}
function applyTheme(theme) {
  const resolved = theme === 'auto'
    ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    : theme;
  document.documentElement.dataset.theme = resolved;
}

function setAccent(a) {
  document.documentElement.style.setProperty('--accent', a.c1);
  document.documentElement.style.setProperty('--accent-2', a.c2);
  localStorage.setItem('nova-accent', a.name);
  document.querySelectorAll('.accent-dot').forEach((d) => d.classList.toggle('selected', d.dataset.accent === a.name));
}

function setWallpaper(w) {
  document.documentElement.style.setProperty('--wallpaper', w.css);
  localStorage.setItem('nova-wallpaper', w.name);
  document.querySelectorAll('.wallpaper-opt').forEach((o) => o.classList.toggle('selected', o.dataset.wallpaper === w.name));
}

function loadSettings() {
  const theme = localStorage.getItem('nova-theme') || 'light';
  setTheme(theme);

  const accentName = localStorage.getItem('nova-accent') || 'blue';
  setAccent(ACCENTS.find((a) => a.name === accentName) || ACCENTS[0]);

  const wallName = localStorage.getItem('nova-wallpaper') || 'none';
  setWallpaper(WALLPAPERS.find((w) => w.name === wallName) || WALLPAPERS[0]);

  const fontSize = localStorage.getItem('nova-fontsize') || '15';
  el('font-size').value = fontSize;
  document.documentElement.style.setProperty('--font-size', fontSize + 'px');

  const rounded = localStorage.getItem('nova-rounded');
  el('rounded-toggle').checked = rounded !== '0';
  document.getElementById('app').classList.toggle('square-bubbles', rounded === '0');

  const sound = localStorage.getItem('nova-sound');
  el('sound-toggle').checked = sound !== 'off';

  const typingOn = localStorage.getItem('nova-typing');
  el('typing-toggle').checked = typingOn !== 'off';
}

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if ((localStorage.getItem('nova-theme') || 'light') === 'auto') applyTheme('auto');
});

// ==================================================================
// ЭМОДЗИ
// ==================================================================
const EMOJI_CATEGORIES = {
  '😀': ['😀','😁','😂','🤣','😊','😍','😘','😜','🤔','😎','😴','🥳','😭','😡','🥺','😇','🙃','🤗','😏','🙄','😱','🤩','😅','🫡','😴','🤤','🤯','🥶','🥵','😷'],
  '👍': ['👍','👎','👏','🙌','🤝','🙏','💪','✌️','🤞','👌','🤙','👋','✊','🫶','🤟','👊'],
  '❤️': ['❤️','🧡','💛','💚','💙','💜','🖤','🤍','💔','💕','💞','💗','💖','💘','😻'],
  '🐶': ['🐶','🐱','🦊','🐻','🐼','🐨','🐯','🦁','🐮','🐷','🐸','🐵','🐔','🐧','🐦','🦄'],
  '🍕': ['🍕','🍔','🍟','🌭','🍿','🍩','🍪','🎂','🍫','🍭','🍎','🍉','🍇','☕','🍺','🍷'],
  '⚽': ['⚽','🏀','🏈','⚾','🎾','🏐','🎱','🏓','🎮','🎲','🎯','🎸','🎤','🚀','⭐','🔥'],
};

function initEmojiPicker() {
  const tabsBox = el('emoji-tabs');
  const grid = el('emoji-grid');
  const cats = Object.keys(EMOJI_CATEGORIES);

  function renderCat(cat) {
    grid.innerHTML = '';
    EMOJI_CATEGORIES[cat].forEach((emo) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = emo;
      b.addEventListener('click', () => {
        const input = el('message-input');
        input.value += emo;
        input.focus();
      });
      grid.appendChild(b);
    });
  }

  cats.forEach((cat, i) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = cat;
    b.className = i === 0 ? 'active' : '';
    b.addEventListener('click', () => {
      tabsBox.querySelectorAll('button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      renderCat(cat);
    });
    tabsBox.appendChild(b);
  });
  renderCat(cats[0]);

  el('emoji-btn').addEventListener('click', () => togglePicker('emoji-picker'));
}

// ==================================================================
// СТИКЕРЫ (эмодзи-стикеры, без внешних файлов)
// ==================================================================
const STICKER_PACKS = {
  '🎉': ['🎉','🥳','🎊','🍾','🎁','🏆','✨','🌟'],
  '😻': ['😻','🐱','🐾','🧶','🐈','🐈‍⬛','🙀','😽'],
  '👋': ['👋','🤝','🙏','💌','📩','📢','🔔','💬'],
  '🔥': ['🔥','💯','⚡','🚀','💎','🏅','🎯','👑'],
};

function initStickerPicker() {
  const tabsBox = el('sticker-tabs');
  const grid = el('sticker-grid');
  const packs = Object.keys(STICKER_PACKS);

  function renderPack(pack) {
    grid.innerHTML = '';
    STICKER_PACKS[pack].forEach((emo) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = emo;
      b.addEventListener('click', () => sendSticker(emo));
      grid.appendChild(b);
    });
  }

  packs.forEach((pack, i) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = pack;
    b.className = i === 0 ? 'active' : '';
    b.addEventListener('click', () => {
      tabsBox.querySelectorAll('button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      renderPack(pack);
    });
    tabsBox.appendChild(b);
  });
  renderPack(packs[0]);

  el('sticker-btn').addEventListener('click', () => togglePicker('sticker-picker'));
}

// ==================================================================
// GIF (через Tenor public API)
// ==================================================================
// Демо-ключ Tenor только для теста — для продакшена получи свой на tenor.com/gifapi
const TENOR_KEY = 'LIVDSRZULELA';

let gifDebounce = null;
function initGifPicker() {
  el('gif-btn').addEventListener('click', () => togglePicker('gif-picker'));
  el('gif-search').addEventListener('input', (e) => {
    clearTimeout(gifDebounce);
    const q = e.target.value.trim();
    gifDebounce = setTimeout(() => searchGifs(q), 350);
  });
}

async function searchGifs(query) {
  const grid = el('gif-grid');
  grid.innerHTML = '<div class="gif-hint">Загрузка…</div>';
  try {
    const endpoint = query
      ? `https://tenor.googleapis.com/v2/search?q=${encodeURIComponent(query)}&key=${TENOR_KEY}&limit=12&media_filter=tinygif`
      : `https://tenor.googleapis.com/v2/featured?key=${TENOR_KEY}&limit=12&media_filter=tinygif`;
    const res = await fetch(endpoint);
    const data = await res.json();
    grid.innerHTML = '';
    (data.results || []).forEach((g) => {
      const url = g.media_formats?.tinygif?.url;
      if (!url) return;
      const img = document.createElement('img');
      img.src = url;
      img.loading = 'lazy';
      img.addEventListener('click', () => sendGif(url));
      grid.appendChild(img);
    });
    if (!grid.children.length) grid.innerHTML = '<div class="gif-hint">Ничего не найдено</div>';
  } catch (err) {
    grid.innerHTML = '<div class="gif-hint">Не удалось загрузить GIF. Проверь соединение или свой Tenor API-ключ.</div>';
  }
}

// ==================================================================
// Пикеры: открытие/закрытие
// ==================================================================
function togglePicker(id) {
  const picker = el(id);
  const wasHidden = picker.classList.contains('hidden');
  closeAllPickers();
  if (wasHidden) picker.classList.remove('hidden');
}
function closeAllPickers() {
  ['emoji-picker', 'sticker-picker', 'gif-picker'].forEach((id) => el(id).classList.add('hidden'));
}
document.addEventListener('click', (e) => {
  const isPickerBtn = e.target.closest('#emoji-btn, #sticker-btn, #gif-btn');
  const isPicker = e.target.closest('.picker');
  if (!isPickerBtn && !isPicker) closeAllPickers();
});

// ------------------------------------------------------------------
// Инициализация
// ------------------------------------------------------------------
initSettings();
initEmojiPicker();
initStickerPicker();
initGifPicker();