// ------------------------------------------------------------------
// Клиентская часть аудио/видеозвонков. Работает поверх сигналинга
// server/calls.js (события call:*) и глобальных переменных из app.js
// (socket, me, chats, el, activeChatId) — этот файл подключается
// в index.html ПОСЛЕ app.js, в той же обычной (не module) области
// видимости, поэтому эти имена доступны напрямую.
//
// Топология — mesh: на каждого другого участника звонка у нас есть
// свой RTCPeerConnection, свой поток отправляется каждому напрямую.
// Сервер только пересылает offer/answer/ICE (см. calls.js).
// ------------------------------------------------------------------

const ICE_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }];

let localStream = null;
let callChatId = null;      // чат, в котором сейчас идёт звонок (или ждём подтверждения)
let callType = null;        // 'audio' | 'video'
let micEnabled = true;
let camEnabled = true;
let callTimerHandle = null;
let callStartedAt = null;

// accountId -> { pc: RTCPeerConnection, tileEl, videoEl, account }
const peers = new Map();

// chatId -> { type, isGroup, chatName } — активный звонок в чужом чате,
// который мы обнаружили (call:active / call:incoming), но ещё не приняли.
// Нужен для баннера "звонок уже идёт" при открытии чата.
const knownActiveCalls = new Map();
let incomingCall = null; // { chatId, type, isGroup, chatName, from }

// accountId -> публичный профиль, собранный из group:members-list (app.js
// уже запрашивает его при открытии группового чата) — используем только
// чтобы подписать плитки участников звонка их именами, ничего не мутируем.
const knownAccounts = new Map();
socket.on('group:members-list', ({ owner, members }) => {
  if (owner) knownAccounts.set(owner.id, owner);
  for (const m of members || []) knownAccounts.set(m.id, m);
});

function callEl(id) { return document.getElementById(id); }

// ------------------------------------------------------------------
// Получение локального медиапотока
// ------------------------------------------------------------------
async function getLocalStream(type) {
  const constraints = type === 'video' ? { audio: true, video: { width: 640, height: 480 } } : { audio: true, video: false };
  return navigator.mediaDevices.getUserMedia(constraints);
}

function stopLocalStream() {
  if (!localStream) return;
  for (const track of localStream.getTracks()) track.stop();
  localStream = null;
}

// ------------------------------------------------------------------
// UI: плитки участников
// ------------------------------------------------------------------
function tileLabel(account) {
  return account ? account.name : 'Участник';
}

// Заводит (если нужно) запись в peers для этого участника и его плитку
// в сетке. Может вызываться ДО того, как для участника вообще появится
// RTCPeerConnection (например, когда мы только что узнали о нём из
// call:state, а offer от него ещё не пришёл) — в этом случае entry.pc
// временно null, а createPeerConnection() позже допишет pc в ЭТУ ЖЕ
// запись, а не создаст новую. Без этого при первом же offer появлялась
// вторая, дублирующая плитка того же человека.
function ensureTile(accountId, account, stream, isLocal) {
  let entry = peers.get(accountId);
  if (!entry) {
    entry = { pc: null, account, tileEl: null, videoEl: null, muteBadge: null };
    peers.set(accountId, entry);
  } else if (account && !entry.account) {
    entry.account = account;
  }
  const grid = callEl('call-grid');
  let tile = entry.tileEl;
  if (!tile) {
    tile = document.createElement('div');
    tile.className = 'call-tile';
    tile.dataset.accountId = accountId;
    const video = document.createElement('video');
    video.autoplay = true;
    video.playsInline = true;
    if (isLocal) video.muted = true;
    tile.appendChild(video);
    const label = document.createElement('div');
    label.className = 'call-tile-label';
    label.textContent = isLocal ? 'Вы' : tileLabel(account);
    tile.appendChild(label);
    const muteBadge = document.createElement('div');
    muteBadge.className = 'call-tile-mute hidden';
    muteBadge.textContent = '🔇';
    tile.appendChild(muteBadge);
    grid.appendChild(tile);
    entry.tileEl = tile;
    entry.videoEl = video;
    entry.muteBadge = muteBadge;
  }
  if (stream) {
    const videoEl = tile.querySelector('video');
    videoEl.srcObject = stream;
  }
  return tile;
}

function removeTile(accountId) {
  const entry = peers.get(accountId);
  if (entry && entry.tileEl) entry.tileEl.remove();
}

function setTileCameraOff(accountId, off) {
  const entry = peers.get(accountId);
  if (entry && entry.tileEl) entry.tileEl.classList.toggle('call-tile-audio-only', !!off);
}

function setTileMuted(accountId, muted) {
  const entry = peers.get(accountId);
  if (entry && entry.muteBadge) entry.muteBadge.classList.toggle('hidden', !muted);
}

// ------------------------------------------------------------------
// RTCPeerConnection на каждого участника
// ------------------------------------------------------------------
function createPeerConnection(accountId, account) {
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  // Если для этого участника уже была заведена запись (например, через
  // ensureTile из applyCallState, ещё без соединения) — переиспользуем
  // её (и уже существующую плитку), а не создаём вторую.
  let entry = peers.get(accountId);
  if (!entry) {
    entry = { pc, account, tileEl: null, videoEl: null, muteBadge: null };
    peers.set(accountId, entry);
  } else {
    entry.pc = pc;
    if (account) entry.account = account;
  }

  if (localStream) {
    for (const track of localStream.getTracks()) pc.addTrack(track, localStream);
  }

  pc.onicecandidate = (e) => {
    if (e.candidate) {
      socket.emit('call:signal', { chatId: callChatId, to: accountId, data: { candidate: e.candidate } });
    }
  };

  pc.ontrack = (e) => {
    ensureTile(accountId, account, e.streams[0], false);
  };

  pc.onconnectionstatechange = () => {
    if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
      // Не рвём звонок целиком — просто эта плитка отвалилась, что
      // сервер и так скажет нам через call:peer-left, если человек
      // реально вышел.
    }
  };

  return entry;
}

async function makeOfferTo(accountId, account) {
  const entry = createPeerConnection(accountId, account);
  const offer = await entry.pc.createOffer();
  await entry.pc.setLocalDescription(offer);
  socket.emit('call:signal', { chatId: callChatId, to: accountId, data: { sdp: entry.pc.localDescription } });
}

async function handleSignal(fromId, data) {
  let entry = peers.get(fromId);
  if (data.sdp) {
    if (data.sdp.type === 'offer') {
      if (!entry) entry = createPeerConnection(fromId, entry && entry.account);
      await entry.pc.setRemoteDescription(data.sdp);
      const answer = await entry.pc.createAnswer();
      await entry.pc.setLocalDescription(answer);
      socket.emit('call:signal', { chatId: callChatId, to: fromId, data: { sdp: entry.pc.localDescription } });
    } else if (data.sdp.type === 'answer') {
      if (entry) await entry.pc.setRemoteDescription(data.sdp);
    }
  } else if (data.candidate && entry) {
    try { await entry.pc.addIceCandidate(data.candidate); } catch (err) { /* кандидат мог устареть — не критично */ }
  }
}

function closePeer(accountId) {
  const entry = peers.get(accountId);
  if (!entry) return;
  if (entry.pc) entry.pc.close();
  removeTile(accountId);
  peers.delete(accountId);
}

function closeAllPeers() {
  for (const accountId of Array.from(peers.keys())) closePeer(accountId);
}

// ------------------------------------------------------------------
// Таймер звонка
// ------------------------------------------------------------------
function startCallTimer() {
  callStartedAt = Date.now();
  callTimerHandle = setInterval(() => {
    const secs = Math.floor((Date.now() - callStartedAt) / 1000);
    const m = String(Math.floor(secs / 60)).padStart(2, '0');
    const s = String(secs % 60).padStart(2, '0');
    callEl('call-panel-timer').textContent = `${m}:${s}`;
  }, 1000);
}

function stopCallTimer() {
  if (callTimerHandle) clearInterval(callTimerHandle);
  callTimerHandle = null;
  callEl('call-panel-timer').textContent = '00:00';
}

// ------------------------------------------------------------------
// Открытие/закрытие оверлея звонка
// ------------------------------------------------------------------
async function openCallOverlay(chatId, type, title) {
  callChatId = chatId;
  callType = type;
  micEnabled = true;
  camEnabled = type === 'video';

  try {
    localStream = await getLocalStream(type);
  } catch (err) {
    alert('Не удалось получить доступ к камере/микрофону. Проверь разрешения браузера.');
    callChatId = null;
    callType = null;
    return false;
  }

  callEl('call-panel-title').textContent = title || 'Звонок';
  callEl('call-grid').innerHTML = '';
  ensureTile(me.id, me, localStream, true);
  callEl('call-overlay').classList.remove('hidden');
  callEl('call-toggle-mic').classList.remove('call-ctrl-off');
  callEl('call-toggle-cam').classList.toggle('call-ctrl-off', type !== 'video');
  callEl('call-toggle-cam').classList.toggle('hidden', type !== 'video');
  startCallTimer();
  hideJoinBanner();
  hideIncomingBanner();
  return true;
}

function closeCallOverlay() {
  callEl('call-overlay').classList.add('hidden');
  closeAllPeers();
  stopLocalStream();
  stopCallTimer();
  callEl('call-grid').innerHTML = '';
  callChatId = null;
  callType = null;
}

// ------------------------------------------------------------------
// Баннеры
// ------------------------------------------------------------------
function showIncomingBanner(payload) {
  incomingCall = payload;
  callEl('call-incoming-title').textContent = payload.isGroup
    ? (payload.chatName || 'Групповой звонок')
    : (payload.from ? payload.from.name : 'Входящий звонок');
  callEl('call-incoming-sub').textContent = payload.type === 'video' ? 'Видеозвонок' : 'Аудиозвонок';
  callEl('call-incoming-banner').classList.remove('hidden');
}

function hideIncomingBanner() {
  incomingCall = null;
  callEl('call-incoming-banner').classList.add('hidden');
}

function showJoinBanner(chatId, type) {
  if (activeChatId !== chatId || callChatId) return;
  callEl('call-join-text').textContent = type === 'video' ? 'В этом чате идёт видеозвонок' : 'В этом чате идёт аудиозвонок';
  const banner = callEl('call-join-banner');
  if (banner) banner.classList.remove('hidden');
}

function hideJoinBanner() {
  const banner = callEl('call-join-banner');
  if (banner) banner.classList.add('hidden');
}

// ------------------------------------------------------------------
// Запуск/присоединение к звонку
// ------------------------------------------------------------------
async function startCall(chatId, type) {
  const chat = chats.find((c) => c.id === chatId);
  const ok = await openCallOverlay(chatId, type, chat ? chat.name : 'Звонок');
  if (!ok) return;
  socket.emit('call:start', { chatId, type });
}

async function acceptIncomingCall() {
  if (!incomingCall) return;
  const { chatId, type, isGroup, chatName, from } = incomingCall;
  const title = isGroup ? chatName : (from ? from.name : 'Звонок');
  const ok = await openCallOverlay(chatId, type, title);
  if (!ok) return;
  socket.emit('call:join', { chatId });
}

function declineIncomingCall() {
  if (!incomingCall) return;
  socket.emit('call:decline', { chatId: incomingCall.chatId });
  hideIncomingBanner();
}

function hangUp() {
  if (!callChatId) return;
  socket.emit('call:leave', { chatId: callChatId });
  closeCallOverlay();
}

// ------------------------------------------------------------------
// Обработка состояния звонка, пришедшего от сервера (call:state /
// call:active). iAmInitiatorOfOffers должен быть true ТОЛЬКО когда мы
// сами уже существующий участник и рассказываем себе о текущем
// составе (сейчас нигде так не вызывается — оставлено на случай
// будущего использования); при call:state после call:start/call:join
// передаём false, чтобы не создавать offer самим себе навстречу
// offer'у, который вот-вот пришлёт существующий участник — иначе
// получается glare (см. комментарий у socket.on('call:state', ...)).
// ------------------------------------------------------------------
function applyCallState(payload, iAmInitiatorOfOffers) {
  for (const p of payload.participants) {
    if (p.accountId === me.id) continue;
    if (!peers.has(p.accountId)) {
      const account = knownAccounts.get(p.accountId) || null;
      ensureTile(p.accountId, account, null, false);
      if (iAmInitiatorOfOffers) makeOfferTo(p.accountId, account);
    }
    setTileCameraOff(p.accountId, p.cameraOff);
    setTileMuted(p.accountId, p.muted);
  }
}

// ------------------------------------------------------------------
// Socket-события
// ------------------------------------------------------------------
socket.on('call:incoming', (payload) => {
  if (payload.from) knownAccounts.set(payload.from.id, payload.from);
  if (callChatId === payload.chatId) return; // уже в этом звонке
  showIncomingBanner(payload);
});

socket.on('call:declined', () => {
  // Собеседник отклонил 1:1 звонок, который мы только что начали.
  if (callChatId) {
    alert('Звонок отклонён.');
    hangUp();
  }
});

socket.on('call:state', (payload) => {
  // Приходит нам самим сразу после call:start/call:join. ВАЖНО: тут
  // нельзя самим инициировать offer — иначе получится "glare"
  // (обе стороны одновременно шлют offer друг другу, и
  // RTCPeerConnection ломается с ошибкой вида "wrong state: stable").
  // По дизайну сервера (см. server/calls.js) offer к новичку всегда
  // инициируют УЖЕ существующие участники — они получают отдельное
  // событие call:peer-joined и оттуда вызывают makeOfferTo. Здесь же
  // мы просто заводим плитки для тех, кто уже в звонке, и ждём их
  // входящий offer через call:signal.
  applyCallState(payload, false);
});

// Обнаружен уже идущий звонок в открытом чате (клиент запрашивает
// через call:query при открытии чата).
socket.on('call:active', (payload) => {
  knownActiveCalls.set(payload.chatId, payload);
  if (!callChatId) showJoinBanner(payload.chatId, payload.type);
});

socket.on('call:peer-joined', ({ chatId, accountId, account }) => {
  if (chatId !== callChatId) return;
  if (account) knownAccounts.set(accountId, account);
  // Существующий участник сам инициирует offer к новичку.
  ensureTile(accountId, account, null, false);
  makeOfferTo(accountId, account);
});

socket.on('call:peer-left', ({ chatId, accountId }) => {
  if (chatId !== callChatId) return;
  closePeer(accountId);
});

socket.on('call:peer-media', ({ chatId, accountId, kind, enabled }) => {
  if (chatId !== callChatId) return;
  if (kind === 'video') setTileCameraOff(accountId, !enabled);
  else setTileMuted(accountId, !enabled);
});

socket.on('call:signal', ({ from, data }) => {
  handleSignal(from, data);
});

// ------------------------------------------------------------------
// Кнопки в шапке чата
// ------------------------------------------------------------------
callEl('chat-call-audio-btn') && callEl('chat-call-audio-btn').addEventListener('click', () => {
  if (!activeChatId) return;
  if (callChatId === activeChatId) return; // уже в звонке
  startCall(activeChatId, 'audio');
});

callEl('chat-call-video-btn') && callEl('chat-call-video-btn').addEventListener('click', () => {
  if (!activeChatId) return;
  if (callChatId === activeChatId) return;
  startCall(activeChatId, 'video');
});

callEl('call-join-btn') && callEl('call-join-btn').addEventListener('click', () => {
  const active = knownActiveCalls.get(activeChatId);
  if (!active) return;
  openCallOverlay(activeChatId, active.type, active.chatName || (chats.find((c) => c.id === activeChatId) || {}).name)
    .then((ok) => { if (ok) socket.emit('call:join', { chatId: activeChatId }); });
});

callEl('call-incoming-accept') && callEl('call-incoming-accept').addEventListener('click', acceptIncomingCall);
callEl('call-incoming-decline') && callEl('call-incoming-decline').addEventListener('click', declineIncomingCall);
callEl('call-hangup-btn') && callEl('call-hangup-btn').addEventListener('click', hangUp);

callEl('call-toggle-mic') && callEl('call-toggle-mic').addEventListener('click', () => {
  if (!localStream) return;
  micEnabled = !micEnabled;
  for (const track of localStream.getAudioTracks()) track.enabled = micEnabled;
  callEl('call-toggle-mic').classList.toggle('call-ctrl-off', !micEnabled);
  socket.emit('call:media', { chatId: callChatId, kind: 'audio', enabled: micEnabled });
});

callEl('call-toggle-cam') && callEl('call-toggle-cam').addEventListener('click', () => {
  if (!localStream || callType !== 'video') return;
  camEnabled = !camEnabled;
  for (const track of localStream.getVideoTracks()) track.enabled = camEnabled;
  callEl('call-toggle-cam').classList.toggle('call-ctrl-off', !camEnabled);
  setTileCameraOff(me.id, !camEnabled);
  socket.emit('call:media', { chatId: callChatId, kind: 'video', enabled: camEnabled });
});

// ------------------------------------------------------------------
// Интеграция с открытием чата (app.js): при каждом переходе в чат
// узнаём, не идёт ли там уже звонок, и прячем/показываем баннер.
// Патчим openChat, а не лезем внутрь app.js — так apply работает
// поверх существующей логики без риска конфликтов при обновлении.
// ------------------------------------------------------------------
const _originalOpenChat = window.openChat;
if (typeof _originalOpenChat === 'function') {
  window.openChat = function patchedOpenChat(chatId) {
    _originalOpenChat(chatId);
    hideJoinBanner();
    const known = knownActiveCalls.get(chatId);
    if (known && callChatId !== chatId) {
      showJoinBanner(chatId, known.type);
    } else {
      socket.emit('call:query', { chatId });
    }
  };
} else {
  // openChat объявлена как function-декларация внутри app.js — в
  // обычных (не module) скриптах такие объявления верхнего уровня
  // становятся свойствами window, поэтому обёртка выше должна сработать.
  // Если по какой-то причине нет — хотя бы подписываемся на чужой вызов
  // через отдельное событие не можем, так что просто запрашиваем call:query
  // при каждом клике по списку чатов не делаем (не наша зона), это лучшее,
  // что можно сделать без изменения app.js.
}