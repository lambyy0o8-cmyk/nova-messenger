const socket = io();

let myUsername = null;
let myBio = '';
let currentGuildId = null;
let currentChannelId = null;
let channelsData = []; // {id, name, lastText, lastAuthor, lastTimestamp}
let unreadCounts = {}; // channelId -> count
let lastRenderedAuthor = null;
let lastRenderedRow = null;
let typingTimeout = null;

const loginScreen = document.getElementById('login-screen');
const appScreen = document.getElementById('app-screen');
const usernameInput = document.getElementById('username-input');
const loginBtn = document.getElementById('login-btn');

const myAvatarEl = document.getElementById('my-avatar');
const settingsPanel = document.getElementById('settings-panel');
const settingsBackBtn = document.getElementById('settings-back-btn');
const profileAvatarEl = document.getElementById('profile-avatar');
const profileNameInput = document.getElementById('profile-name-input');
const profileBioInput = document.getElementById('profile-bio-input');
const profileSaveBtn = document.getElementById('profile-save-btn');
const profileSaveHint = document.getElementById('profile-save-hint');
const themeToggle = document.getElementById('theme-toggle');
const soundToggle = document.getElementById('sound-toggle');
const logoutBtn = document.getElementById('logout-btn');
const chatListEl = document.getElementById('chat-list');
const searchInput = document.getElementById('search-input');
const newChannelInput = document.getElementById('new-channel-input');
const addChannelBtn = document.getElementById('add-channel-btn');

const backBtn = document.getElementById('back-btn');
const chatEmpty = document.getElementById('chat-empty');
const chatActive = document.getElementById('chat-active');
const chatHeaderAvatar = document.getElementById('chat-header-avatar');
const chatHeaderName = document.getElementById('chat-header-name');
const chatHeaderSub = document.getElementById('chat-header-sub');
const messagesBox = document.getElementById('messages');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');

// ===== Аватары: детерминированный градиент по имени =====
function hashString(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) hash = str.charCodeAt(i) + ((hash << 5) - hash);
  return Math.abs(hash);
}
function avatarStyle(seed) {
  const h = hashString(seed);
  const hue1 = h % 360;
  const hue2 = (hue1 + 40) % 360;
  return `background: linear-gradient(135deg, hsl(${hue1},70%,55%), hsl(${hue2},65%,42%));`;
}
function paintAvatar(el, seed, letter) {
  el.setAttribute('style', avatarStyle(seed));
  el.textContent = letter.charAt(0);
}

// ===== Вход =====
function login() {
  const name = usernameInput.value.trim();
  if (!name) return;
  myUsername = name;
  socket.emit('join_app', name);
  loginScreen.classList.add('hidden');
  appScreen.classList.remove('hidden');
  paintAvatar(myAvatarEl, name, name);
}
loginBtn.addEventListener('click', login);
usernameInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') login(); });
usernameInput.focus();

// ===== Гилды =====
socket.on('guild_list', (guilds) => {
  if (guilds.length > 0) {
    currentGuildId = guilds[0].id;
    socket.emit('join_guild', currentGuildId);
  }
});

// ===== Список чатов (каналов) с превью =====
socket.on('channel_list', ({ guildId, channels }) => {
  if (guildId !== currentGuildId) return;
  channelsData = channels;
  renderChatList();
});

socket.on('channel_list_updated', ({ guildId, channels }) => {
  if (guildId !== currentGuildId) return;
  channelsData = channels;
  renderChatList();
});

socket.on('channel_preview_update', ({ guildId, preview }) => {
  if (guildId !== currentGuildId) return;
  const idx = channelsData.findIndex(c => c.id === preview.id);
  if (idx >= 0) channelsData[idx] = preview; else channelsData.push(preview);

  // непрочитанные — если это не открытый сейчас чат и не моё сообщение
  if (preview.id !== currentChannelId && preview.lastAuthor !== myUsername) {
    unreadCounts[preview.id] = (unreadCounts[preview.id] || 0) + 1;
    playNotifySound();
  }
  renderChatList();
});

function renderChatList() {
  const query = searchInput.value.trim().toLowerCase();
  chatListEl.innerHTML = '';

  const sorted = [...channelsData].sort((a, b) => (b.lastTimestamp || 0) - (a.lastTimestamp || 0));

  sorted
    .filter(ch => ch.name.toLowerCase().includes(query))
    .forEach(ch => {
      const item = document.createElement('div');
      item.className = 'chat-list-item' + (ch.id === currentChannelId ? ' active' : '');

      const avatar = document.createElement('div');
      avatar.className = 'chat-avatar';
      paintAvatar(avatar, ch.name, ch.name);
      item.appendChild(avatar);

      const body = document.createElement('div');
      body.className = 'chat-list-body';

      const previewText = ch.lastText
        ? `${ch.lastAuthor === myUsername ? 'Вы: ' : (ch.lastAuthor ? ch.lastAuthor + ': ' : '')}${ch.lastText}`
        : 'Нет сообщений';

      const unread = unreadCounts[ch.id] || 0;

      body.innerHTML = `
        <div class="chat-list-row1">
          <span class="chat-list-name">${escapeHtml(ch.name)}</span>
          <span class="chat-list-time">${ch.lastTimestamp ? formatTime(ch.lastTimestamp) : ''}</span>
        </div>
        <div class="chat-list-row2">
          <span class="chat-list-preview">${escapeHtml(previewText)}</span>
          ${unread > 0 ? `<span class="unread-badge">${unread}</span>` : ''}
        </div>
      `;
      item.appendChild(body);

      item.addEventListener('click', () => selectChannel(ch.id, ch.name));
      chatListEl.appendChild(item);
    });
}

searchInput.addEventListener('input', renderChatList);

// ===== Выбор чата =====
function selectChannel(channelId, channelName) {
  currentChannelId = channelId;
  unreadCounts[channelId] = 0;

  chatEmpty.classList.add('hidden');
  chatActive.classList.remove('hidden');

  paintAvatar(chatHeaderAvatar, channelName, channelName);
  chatHeaderName.textContent = channelName;
  chatHeaderSub.textContent = '';
  chatHeaderSub.classList.remove('typing');

  socket.emit('join_channel', { guildId: currentGuildId, channelId });

  lastRenderedAuthor = null;
  lastRenderedRow = null;

  appScreen.classList.add('chat-open'); // на мобильном сдвигает список чатов, открывая переписку

  renderChatList();
  messageInput.focus();
}

backBtn.addEventListener('click', () => {
  appScreen.classList.remove('chat-open');
});

// ===== История и новые сообщения =====
socket.on('message_history', ({ channelId, messages }) => {
  if (channelId !== currentChannelId) return;
  messagesBox.innerHTML = '';
  lastRenderedAuthor = null;
  lastRenderedRow = null;
  messages.forEach(renderMessage);
  scrollToBottom();
});

socket.on('new_message', ({ channelId, message }) => {
  if (channelId !== currentChannelId) return;
  renderMessage(message);
  scrollToBottom();
});

function formatTime(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function readTicksSvg() {
  return `<span class="ticks"><svg viewBox="0 0 16 12" width="15" height="11"><path d="M1 6l3 3 7-8" stroke="#5EA6F0" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/><path d="M5 6l3 3 7-8" stroke="#5EA6F0" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg></span>`;
}

function renderMessage(msg) {
  const isOwn = msg.author === myUsername;
  const isGroupStart = lastRenderedAuthor !== msg.author;

  const row = document.createElement('div');
  row.className = `msg-row ${isOwn ? 'out' : 'in'}` + (isGroupStart ? ' group-start' : '');

  if (!isOwn) {
    const avatar = document.createElement('div');
    if (isGroupStart) {
      avatar.className = 'row-avatar';
      paintAvatar(avatar, msg.author, msg.author);
    } else {
      avatar.className = 'row-avatar spacer';
    }
    row.appendChild(avatar);
  }

  const bubble = document.createElement('div');
  bubble.className = 'bubble';

  const authorLabel = (!isOwn && isGroupStart)
    ? `<div class="author-label">${escapeHtml(msg.author)}</div>` : '';

  bubble.innerHTML = `
    ${authorLabel}
    <span class="msg-text">${escapeHtml(msg.text)}</span>
    <span class="msg-meta">${formatTime(msg.timestamp)}${isOwn ? readTicksSvg() : ''}</span>
  `;
  row.appendChild(bubble);
  messagesBox.appendChild(row);

  lastRenderedAuthor = msg.author;
  lastRenderedRow = row;
}

function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

function scrollToBottom() {
  messagesBox.scrollTop = messagesBox.scrollHeight;
}

// ===== Отправка сообщения =====
function sendMessage() {
  const text = messageInput.value;
  if (!text.trim() || !currentChannelId) return;
  socket.emit('send_message', { guildId: currentGuildId, channelId: currentChannelId, text });
  socket.emit('typing_stop', { guildId: currentGuildId, channelId: currentChannelId });
  messageInput.value = '';
}
sendBtn.addEventListener('click', sendMessage);
messageInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendMessage(); });

// ===== Индикатор "печатает…" =====
messageInput.addEventListener('input', () => {
  if (!currentChannelId) return;
  socket.emit('typing_start', { guildId: currentGuildId, channelId: currentChannelId });
  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(() => {
    socket.emit('typing_stop', { guildId: currentGuildId, channelId: currentChannelId });
  }, 1500);
});

socket.on('user_typing', ({ username, channelId }) => {
  if (channelId !== currentChannelId || username === myUsername) return;
  chatHeaderSub.textContent = `${username} печатает…`;
  chatHeaderSub.classList.add('typing');
});
socket.on('user_stopped_typing', ({ channelId }) => {
  if (channelId !== currentChannelId) return;
  chatHeaderSub.textContent = '';
  chatHeaderSub.classList.remove('typing');
});

// ===== Создание нового чата =====
addChannelBtn.addEventListener('click', createChannel);
newChannelInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') createChannel(); });
function createChannel() {
  const name = newChannelInput.value.trim();
  if (!name) return;
  socket.emit('create_channel', { guildId: currentGuildId, channelName: name });
  newChannelInput.value = '';
}

// ===== Настройки / Профиль =====
myAvatarEl.addEventListener('click', openSettings);
settingsBackBtn.addEventListener('click', closeSettings);

function openSettings() {
  paintAvatar(profileAvatarEl, myUsername, myUsername);
  profileNameInput.value = myUsername || '';
  profileBioInput.value = myBio || '';
  profileSaveHint.classList.remove('show');
  settingsPanel.classList.remove('hidden');
}
function closeSettings() {
  settingsPanel.classList.add('hidden');
}

profileSaveBtn.addEventListener('click', () => {
  const newName = profileNameInput.value.trim();
  const newBio = profileBioInput.value.trim();
  if (!newName) return;
  socket.emit('update_profile', { username: newName, bio: newBio });
});

socket.on('profile_updated', ({ username, bio }) => {
  myUsername = username;
  myBio = bio;
  paintAvatar(myAvatarEl, myUsername, myUsername);
  paintAvatar(profileAvatarEl, myUsername, myUsername);
  renderChatList();
  profileSaveHint.textContent = 'Сохранено';
  profileSaveHint.classList.add('show');
  setTimeout(() => profileSaveHint.classList.remove('show'), 1800);
});

// ===== Тёмная тема (сохраняется между визитами) =====
const THEME_KEY = 'nova_messenger_theme';
const SOUND_KEY = 'nova_messenger_sound';

function applyTheme(isDark) {
  document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
  themeToggle.checked = isDark;
}
applyTheme(localStorage.getItem(THEME_KEY) === 'dark');

themeToggle.addEventListener('change', () => {
  applyTheme(themeToggle.checked);
  localStorage.setItem(THEME_KEY, themeToggle.checked ? 'dark' : 'light');
});

// ===== Звук уведомлений =====
soundToggle.checked = localStorage.getItem(SOUND_KEY) !== 'off';
soundToggle.addEventListener('change', () => {
  localStorage.setItem(SOUND_KEY, soundToggle.checked ? 'on' : 'off');
});

let audioCtx = null;
function playNotifySound() {
  if (!soundToggle.checked) return;
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(880, audioCtx.currentTime);
    gain.gain.setValueAtTime(0.001, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.12, audioCtx.currentTime + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.25);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + 0.25);
  } catch (e) { /* аудио недоступно — просто без звука */ }
}

// ===== Выход из аккаунта =====
logoutBtn.addEventListener('click', () => {
  localStorage.removeItem(THEME_KEY);
  location.reload();
});