// ------------------------------------------------------------------
// Клиент звонков (аудио/видео, WebRTC mesh). Самодостаточный модуль:
// подключается отдельным <script src="calls.js"> ПОСЛЕ app.js (нужен
// доступ к window.__novaCallsCtx(), см. CALLS_INTEGRATION.md) и сам
// строит себе UI — почти не трогает существующую разметку index.html.
// ------------------------------------------------------------------
(function () {
  function ctx() {
    return window.__novaCallsCtx ? window.__novaCallsCtx() : {};
  }

  let socket = null;
  let call = null; // { chatId, type, localStream, peers: Map<accountId, RTCPeerConnection>, participants: Map<accountId, {muted, cameraOff, account}> }
  let incoming = null; // { chatId, type, isGroup, chatName, from }
  let activeElsewhere = null; // { chatId, type } — звонок идёт в открытом чате, но я в нём не участвую

  // ---------------- TURN/STUN креды ----------------
  let iceServersPromise = null;
  function getIceServers() {
    if (!iceServersPromise) {
      iceServersPromise = fetch('/api/turn-credentials')
        .then((r) => r.json())
        .then((d) => (Array.isArray(d.iceServers) && d.iceServers.length ? d.iceServers : [{ urls: 'stun:stun.l.google.com:19302' }]))
        .catch(() => [{ urls: 'stun:stun.l.google.com:19302' }]);
    }
    return iceServersPromise;
  }

  // ---------------- UI ----------------
  const ui = {};

  function buildUi() {
    const overlay = document.createElement('div');
    overlay.id = 'call-overlay';
    overlay.className = 'call-overlay hidden';
    overlay.innerHTML = `
      <div class="call-panel">
        <div class="call-panel-header">
          <span id="call-title" class="call-title"></span>
          <span id="call-timer" class="call-timer"></span>
        </div>
        <div id="call-grid" class="call-grid"></div>
        <div class="call-controls">
          <button id="call-toggle-mic" class="call-ctrl-btn" title="Микрофон">🎙️</button>
          <button id="call-toggle-cam" class="call-ctrl-btn" title="Камера">📹</button>
          <button id="call-hangup" class="call-ctrl-btn call-hangup" title="Завершить">📞</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);

    const banner = document.createElement('div');
    banner.id = 'call-incoming-banner';
    banner.className = 'call-incoming-banner hidden';
    banner.innerHTML = `
      <div class="call-incoming-info">
        <div id="call-incoming-title" class="call-incoming-title"></div>
        <div id="call-incoming-sub" class="call-incoming-sub"></div>
      </div>
      <div class="call-incoming-actions">
        <button id="call-incoming-decline" class="call-ctrl-btn call-hangup">✕</button>
        <button id="call-incoming-accept" class="call-ctrl-btn call-accept">✓</button>
      </div>`;
    document.body.appendChild(banner);

    const joinBanner = document.createElement('div');
    joinBanner.id = 'call-join-banner';
    joinBanner.className = 'call-join-banner hidden';
    joinBanner.innerHTML = `<span id="call-join-text"></span><button id="call-join-btn" class="call-join-btn">Присоединиться</button>`;
    document.body.appendChild(joinBanner);

    ui.overlay = overlay;
    ui.grid = overlay.querySelector('#call-grid');
    ui.title = overlay.querySelector('#call-title');
    ui.timer = overlay.querySelector('#call-timer');
    ui.micBtn = overlay.querySelector('#call-toggle-mic');
    ui.camBtn = overlay.querySelector('#call-toggle-cam');
    ui.hangupBtn = overlay.querySelector('#call-hangup');
    ui.banner = banner;
    ui.bannerTitle = banner.querySelector('#call-incoming-title');
    ui.bannerSub = banner.querySelector('#call-incoming-sub');
    ui.declineBtn = banner.querySelector('#call-incoming-decline');
    ui.acceptBtn = banner.querySelector('#call-incoming-accept');
    ui.joinBanner = joinBanner;
    ui.joinText = joinBanner.querySelector('#call-join-text');
    ui.joinBtn = joinBanner.querySelector('#call-join-btn');

    ui.micBtn.addEventListener('click', toggleMic);
    ui.camBtn.addEventListener('click', toggleCam);
    ui.hangupBtn.addEventListener('click', leaveCall);
    ui.declineBtn.addEventListener('click', declineCall);
    ui.acceptBtn.addEventListener('click', () => {
      if (incoming) joinCall(incoming.chatId, incoming.type);
    });
    ui.joinBtn.addEventListener('click', () => {
      if (activeElsewhere) joinCall(activeElsewhere.chatId, activeElsewhere.type);
    });
  }

  function ensureUi() {
    if (!ui.overlay) buildUi();
  }

  let timerInterval = null;
  function showCallUi() {
    ensureUi();
    ui.overlay.classList.remove('hidden');
    ui.title.textContent = call.type === 'video' ? 'Видеозвонок' : 'Звонок';
    const startedAt = Date.now();
    if (timerInterval) clearInterval(timerInterval);
    timerInterval = setInterval(() => {
      const secs = Math.floor((Date.now() - startedAt) / 1000);
      const m = String(Math.floor(secs / 60)).padStart(2, '0');
      const s = String(secs % 60).padStart(2, '0');
      ui.timer.textContent = `${m}:${s}`;
    }, 1000);
  }

  function hideCallUi() {
    if (!ui.overlay) return;
    ui.overlay.classList.add('hidden');
    ui.grid.innerHTML = '';
    if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
  }

  function tileId(accountId) {
    return `call-tile-${accountId}`;
  }

  function ensureTile(accountId, label) {
    ensureUi();
    let tile = document.getElementById(tileId(accountId));
    if (tile) return tile;
    tile = document.createElement('div');
    tile.id = tileId(accountId);
    tile.className = 'call-tile';
    tile.innerHTML = `<video autoplay playsinline${accountId === 'me' ? ' muted' : ''}></video><div class="call-tile-label">${label}</div><div class="call-tile-mute hidden">🔇</div>`;
    ui.grid.appendChild(tile);
    return tile;
  }

  function removeTile(accountId) {
    const tile = document.getElementById(tileId(accountId));
    if (tile) tile.remove();
  }

  function setLocalPreview(stream) {
    const { me } = ctx();
    const tile = ensureTile('me', me ? `${me.name} (вы)` : 'Вы');
    const video = tile.querySelector('video');
    video.srcObject = stream;
    if (call.type === 'audio') tile.classList.add('call-tile-audio-only');
  }

  function attachRemoteStream(accountId, stream) {
    const p = call.participants.get(accountId);
    const label = p && p.account ? p.account.name : accountId;
    const tile = ensureTile(accountId, label);
    tile.querySelector('video').srcObject = stream;
  }

  function updateTileMedia(accountId) {
    const p = call.participants.get(accountId);
    const tile = document.getElementById(tileId(accountId));
    if (!tile || !p) return;
    tile.querySelector('.call-tile-mute').classList.toggle('hidden', !p.muted);
    tile.classList.toggle('call-tile-audio-only', !!p.cameraOff);
  }

  function renderParticipants() {
    for (const accountId of call.participants.keys()) updateTileMedia(accountId);
  }

  function showIncomingBanner(payload) {
    ensureUi();
    incoming = payload;
    ui.bannerTitle.textContent = payload.isGroup
      ? `Групповой звонок в «${payload.chatName}»`
      : `Звонит ${payload.from ? payload.from.name : payload.chatName}`;
    ui.bannerSub.textContent = payload.type === 'video' ? 'Видеозвонок' : 'Аудиозвонок';
    ui.banner.classList.remove('hidden');
  }

  function hideIncomingBanner() {
    incoming = null;
    if (ui.banner) ui.banner.classList.add('hidden');
  }

  function showJoinBanner(payload) {
    ensureUi();
    activeElsewhere = payload;
    ui.joinText.textContent = payload.type === 'video' ? '🔴 Идёт видеозвонок в этом чате' : '🔴 Идёт звонок в этом чате';
    ui.joinBanner.classList.remove('hidden');
  }

  function hideJoinBanner() {
    activeElsewhere = null;
    if (ui.joinBanner) ui.joinBanner.classList.add('hidden');
  }

  // ---------------- медиа/WebRTC ----------------
  async function openMedia(type) {
    const constraints = type === 'video'
      ? { audio: true, video: { width: 640, height: 480 } }
      : { audio: true, video: false };
    return navigator.mediaDevices.getUserMedia(constraints);
  }

  function createPeerConnection(accountId, iceServers) {
    const pc = new RTCPeerConnection({ iceServers });
    if (call.localStream) {
      for (const track of call.localStream.getTracks()) pc.addTrack(track, call.localStream);
    }
    pc.onicecandidate = (e) => {
      if (e.candidate) {
        socket.emit('call:signal', { chatId: call.chatId, to: accountId, data: { type: 'ice-candidate', candidate: e.candidate } });
      }
    };
    pc.ontrack = (e) => attachRemoteStream(accountId, e.streams[0]);
    call.peers.set(accountId, pc);
    return pc;
  }

  function toggleMic() {
    if (!call || !call.localStream) return;
    const track = call.localStream.getAudioTracks()[0];
    if (!track) return;
    track.enabled = !track.enabled;
    ui.micBtn.classList.toggle('call-ctrl-off', !track.enabled);
    socket.emit('call:media', { chatId: call.chatId, kind: 'audio', enabled: track.enabled });
  }

  function toggleCam() {
    if (!call || !call.localStream || call.type !== 'video') return;
    const track = call.localStream.getVideoTracks()[0];
    if (!track) return;
    track.enabled = !track.enabled;
    ui.camBtn.classList.toggle('call-ctrl-off', !track.enabled);
    socket.emit('call:media', { chatId: call.chatId, kind: 'video', enabled: track.enabled });
  }

  // ---------------- жизненный цикл звонка ----------------
  async function startCall(chatId, type) {
    socket = ctx().socket;
    if (!socket || call) return;
    let stream;
    try {
      stream = await openMedia(type);
    } catch (err) {
      alert('Нет доступа к камере/микрофону: ' + err.message);
      return;
    }
    call = { chatId, type, localStream: stream, peers: new Map(), participants: new Map() };
    hideJoinBanner();
    showCallUi();
    setLocalPreview(stream);
    socket.emit('call:start', { chatId, type });
  }

  async function joinCall(chatId, type) {
    socket = ctx().socket;
    if (!socket || call) return;
    let stream;
    try {
      stream = await openMedia(type || 'video');
    } catch (err) {
      alert('Нет доступа к камере/микрофону: ' + err.message);
      return;
    }
    call = { chatId, type: type || 'video', localStream: stream, peers: new Map(), participants: new Map() };
    hideIncomingBanner();
    hideJoinBanner();
    showCallUi();
    setLocalPreview(stream);
    socket.emit('call:join', { chatId });
  }

  function declineCall() {
    if (!incoming || !socket) return;
    socket.emit('call:decline', { chatId: incoming.chatId });
    hideIncomingBanner();
  }

  function leaveCall() {
    if (!call || !socket) return;
    socket.emit('call:leave', { chatId: call.chatId });
    teardownCall();
  }

  function teardownCall() {
    if (!call) return;
    for (const pc of call.peers.values()) pc.close();
    if (call.localStream) for (const t of call.localStream.getTracks()) t.stop();
    call = null;
    hideCallUi();
  }

  // ---------------- сокет-события ----------------
  function wireSocket() {
    socket = ctx().socket;
    if (!socket || socket.__callsWired) return;
    socket.__callsWired = true;

    socket.on('call:incoming', (payload) => {
      if (call && call.chatId === payload.chatId) return;
      showIncomingBanner(payload);
    });

    socket.on('call:active', (state) => {
      if (call && call.chatId === state.chatId) return;
      const { activeChatId } = ctx();
      if (state.chatId !== activeChatId) return;
      showJoinBanner({ chatId: state.chatId, type: state.type });
    });

    socket.on('call:state', (state) => {
      if (!call || call.chatId !== state.chatId) return;
      const mine = ctx().me;
      for (const p of state.participants) {
        if (mine && p.accountId === mine.id) continue;
        const existing = call.participants.get(p.accountId) || {};
        call.participants.set(p.accountId, { ...existing, muted: p.muted, cameraOff: p.cameraOff });
      }
      renderParticipants();
    });

    socket.on('call:peer-joined', async ({ chatId, accountId, account }) => {
      if (!call || call.chatId !== chatId || call.peers.has(accountId)) return;
      const iceServers = await getIceServers();
      const pc = createPeerConnection(accountId, iceServers);
      call.participants.set(accountId, { muted: false, cameraOff: call.type === 'audio', account });
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      socket.emit('call:signal', { chatId, to: accountId, data: { type: 'offer', sdp: offer.sdp } });
    });

    socket.on('call:signal', async ({ chatId, from, data }) => {
      if (!call || call.chatId !== chatId) return;
      const iceServers = await getIceServers();
      let pc = call.peers.get(from);
      if (!pc) pc = createPeerConnection(from, iceServers);
      if (data.type === 'offer') {
        await pc.setRemoteDescription({ type: 'offer', sdp: data.sdp });
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        socket.emit('call:signal', { chatId, to: from, data: { type: 'answer', sdp: answer.sdp } });
      } else if (data.type === 'answer') {
        await pc.setRemoteDescription({ type: 'answer', sdp: data.sdp });
      } else if (data.type === 'ice-candidate' && data.candidate) {
        try { await pc.addIceCandidate(data.candidate); } catch (e) { /* поздние кандидаты — безопасно игнорируем */ }
      }
    });

    socket.on('call:peer-left', ({ chatId, accountId }) => {
      if (!call || call.chatId !== chatId) return;
      const pc = call.peers.get(accountId);
      if (pc) pc.close();
      call.peers.delete(accountId);
      call.participants.delete(accountId);
      removeTile(accountId);
    });

    socket.on('call:peer-media', ({ chatId, accountId, kind, enabled }) => {
      if (!call || call.chatId !== chatId) return;
      const p = call.participants.get(accountId);
      if (!p) return;
      if (kind === 'audio') p.muted = !enabled; else p.cameraOff = !enabled;
      updateTileMedia(accountId);
    });

    socket.on('call:declined', ({ chatId }) => {
      if (call && call.chatId === chatId && call.participants.size === 0) teardownCall();
    });

    socket.on('call:ended', ({ chatId }) => {
      if (incoming && incoming.chatId === chatId) hideIncomingBanner();
      if (activeElsewhere && activeElsewhere.chatId === chatId) hideJoinBanner();
      if (call && call.chatId === chatId) teardownCall();
    });
  }

  // ---------------- кнопки в шапке чата ----------------
  function injectHeaderButtons() {
    const info = document.getElementById('chat-header-info');
    if (!info || document.getElementById('call-audio-btn')) return;
    const audioBtn = document.createElement('button');
    audioBtn.id = 'call-audio-btn';
    audioBtn.className = 'icon-btn';
    audioBtn.title = 'Аудиозвонок';
    audioBtn.textContent = '📞';
    const videoBtn = document.createElement('button');
    videoBtn.id = 'call-video-btn';
    videoBtn.className = 'icon-btn';
    videoBtn.title = 'Видеозвонок';
    videoBtn.textContent = '📹';
    audioBtn.addEventListener('click', () => {
      const { activeChatId } = ctx();
      if (activeChatId) startCall(activeChatId, 'audio');
    });
    videoBtn.addEventListener('click', () => {
      const { activeChatId } = ctx();
      if (activeChatId) startCall(activeChatId, 'video');
    });
    info.insertAdjacentElement('afterend', videoBtn);
    info.insertAdjacentElement('afterend', audioBtn);
  }

  // Раз в секунду проверяем, не сменился ли открытый чат — чтобы
  // спросить сервер, не идёт ли там уже звонок (call:query), не трогая
  // существующую логику открытия чата в app.js.
  let lastCheckedChatId = null;
  function pollActiveChat() {
    const { activeChatId } = ctx();
    if (activeChatId !== lastCheckedChatId) {
      lastCheckedChatId = activeChatId;
      hideJoinBanner();
      if (activeChatId && socket && !(call && call.chatId === activeChatId)) {
        socket.emit('call:query', { chatId: activeChatId });
      }
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    wireSocket();
    injectHeaderButtons();
    setInterval(pollActiveChat, 1000);
  });

  window.NovaCalls = { start: startCall, join: joinCall, leave: leaveCall, decline: declineCall };
})();