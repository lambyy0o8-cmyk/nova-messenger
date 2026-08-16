// Админ-консоль подключается к отдельному namespace /admin — он не связан
// с обычными аккаунтами и чатами, только пароль сервера + список аккаунтов,
// групп и заблокированных попыток входа.
const socket = io('/admin');

const el = (id) => document.getElementById(id);
let accounts = [];
let groups = [];
let lockedLogins = [];
let actionLogs = [];
let activeTab = 'accounts';
let pendingResetAccount = null; // { id, username } — для модалки сброса пароля
let pendingBanAccount = null; // { id, name, username } — для модалки бана (выбор срока)
let messagesChatId = null; // id чата, чьи сообщения сейчас открыты в модалке модерации

function verifiedBadge(isVerified) {
  if (!isVerified) return '';
  return `<svg class="verified-badge" viewBox="0 0 20 20" aria-label="Подтверждён">
    <circle cx="10" cy="10" r="10"/>
    <path d="M6 10.2l2.5 2.5L14.5 7" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
}

function initials(name) {
  return (name || '?').trim().slice(0, 2).toUpperCase();
}
function avatarBg(name) {
  const colors = ['#e17076', '#7bc862', '#65aadd', '#a695e7', '#ee7aae', '#6ec9cb', '#faa774', '#4f95d1'];
  let hash = 0;
  const s = name || '';
  for (let i = 0; i < s.length; i++) hash = s.charCodeAt(i) + ((hash << 5) - hash);
  return colors[Math.abs(hash) % colors.length];
}
function escapeHtml(str = '') {
  return str.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function formatDate(ts) {
  if (!ts) return 'дата неизвестна';
  const d = new Date(ts);
  return d.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric' });
}
function formatDateTime(ts) {
  if (!ts) return 'время неизвестно';
  const d = new Date(ts);
  return `${d.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric' })} ${d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}`;
}

// ------------------------------------------------------------------
// Вход
// ------------------------------------------------------------------
el('admin-login-btn').addEventListener('click', doAdminLogin);
el('admin-password').addEventListener('keydown', (e) => { if (e.key === 'Enter') doAdminLogin(); });

function doAdminLogin() {
  const password = el('admin-password').value;
  if (!password) { el('admin-password').focus(); return; }
  hideLoginError();
  el('admin-login-btn').disabled = true;
  el('admin-login-btn').textContent = 'Входим…';
  socket.emit('admin:login', { password });
}

function showLoginError(message) {
  const box = el('admin-login-error');
  box.textContent = message;
  box.classList.remove('hidden');
  el('admin-login-btn').disabled = false;
  el('admin-login-btn').textContent = 'Войти';
}
function hideLoginError() {
  el('admin-login-error').classList.add('hidden');
}

socket.on('admin:error', ({ message }) => {
  // На экране входа это ошибка пароля; после входа — ошибка какого-то
  // действия (например, слишком короткий новый пароль при сбросе).
  if (el('admin-login').classList.contains('hidden')) {
    const box = el('reset-pw-error');
    if (!el('reset-pw-overlay').classList.contains('hidden')) {
      box.textContent = message || 'Не удалось выполнить действие.';
      box.classList.remove('hidden');
    } else {
      alert(message || 'Не удалось выполнить действие.');
    }
  } else {
    showLoginError(message || 'Не удалось войти.');
  }
});

socket.on('admin:ok', ({ adminName } = {}) => {
  el('admin-password').value = '';
  el('admin-login').classList.add('hidden');
  el('admin-panel').classList.remove('hidden');
  const nameEl = el('admin-current-name');
  if (nameEl) nameEl.textContent = adminName ? `вы: ${adminName}` : '';
});

socket.on('admin:action-ok', ({ message }) => {
  if (message) alert(message);
});

// ------------------------------------------------------------------
// Вкладки
// ------------------------------------------------------------------
document.querySelectorAll('.admin-tab').forEach((btn) => {
  btn.addEventListener('click', () => setActiveTab(btn.dataset.tab));
});
function setActiveTab(tab) {
  activeTab = tab;
  document.querySelectorAll('.admin-tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('.admin-tab-panel').forEach((p) => p.classList.add('hidden'));
  el(`tab-${tab}`).classList.remove('hidden');
}

// ------------------------------------------------------------------
// Статистика
// ------------------------------------------------------------------
socket.on('admin:stats', (stats) => {
  if (!stats) return;
  el('stat-total').textContent = stats.totalAccounts;
  el('stat-online').textContent = stats.onlineAccounts;
  el('stat-banned').textContent = stats.bannedAccounts;
  el('stat-groups').textContent = stats.groupChats;
  el('stat-messages').textContent = stats.totalMessages;
});

// ------------------------------------------------------------------
// Список аккаунтов
// ------------------------------------------------------------------
socket.on('admin:accounts', (list) => {
  accounts = list || [];
  renderAccountsList(el('admin-search').value);
});

el('admin-refresh').addEventListener('click', () => socket.emit('admin:refresh'));
el('admin-search').addEventListener('input', (e) => {
  renderAccountsList(e.target.value);
  renderGroupsList(e.target.value);
});

function renderAccountsList(filter = '') {
  const box = el('admin-list');
  const q = filter.trim().toLowerCase();
  const filtered = accounts.filter((a) =>
    a.name.toLowerCase().includes(q) || (a.username || '').toLowerCase().includes(q)
  );

  el('admin-empty').classList.toggle('hidden', accounts.length > 0);
  box.innerHTML = '';

  filtered.forEach((a) => {
    const row = document.createElement('div');
    row.className = `admin-row${a.banned ? ' is-banned' : ''}`;
    row.innerHTML = `
      <div class="admin-avatar" style="background:${avatarBg(a.name)}">${initials(a.name)}</div>
      <div class="admin-row-meta">
        <div class="admin-row-name">
          <span class="admin-online-dot${a.online ? ' online' : ''}" title="${a.online ? 'В сети' : 'Не в сети'}"></span>
          ${escapeHtml(a.name)} ${verifiedBadge(a.verified)} ${a.banned ? '<span class="admin-badge-banned">забанен</span>' : ''}
        </div>
        <div class="admin-row-sub">
          @${escapeHtml(a.username || '')} · ${escapeHtml(a.novaId || '')} · с ${formatDate(a.createdAt)}
          ${a.banned && a.bannedUntil ? `<span class="admin-row-flag" title="Бан снимется автоматически">до ${formatDateTime(a.bannedUntil)}</span>` : ''}
          ${!a.canCreateGroups ? '<span class="admin-row-flag">без групп</span>' : ''}
        </div>
      </div>
      <div class="admin-row-actions">
        <button type="button" class="admin-row-btn" data-action="reset-pw" title="Сбросить пароль">🔑</button>
        <button type="button" class="admin-row-btn danger" data-action="kick" title="Разлогинить">⏏</button>
        <label class="admin-switch" title="Подтверждён">
          <input type="checkbox" ${a.verified ? 'checked' : ''} data-action="verified">
          <span class="admin-slider"></span>
        </label>
        <label class="admin-switch" title="Запрет создавать группы">
          <input type="checkbox" ${!a.canCreateGroups ? 'checked' : ''} data-action="no-groups">
          <span class="admin-slider"></span>
        </label>
        <label class="admin-switch" title="Забанен">
          <input type="checkbox" ${a.banned ? 'checked' : ''} data-action="banned">
          <span class="admin-slider"></span>
        </label>
      </div>
    `;
    row.querySelector('[data-action="verified"]').addEventListener('change', (e) => {
      socket.emit('admin:set-verified', { accountId: a.id, verified: e.target.checked });
    });
    row.querySelector('[data-action="no-groups"]').addEventListener('change', (e) => {
      socket.emit('admin:set-restriction', { accountId: a.id, key: 'canCreateGroups', value: !e.target.checked });
    });
    row.querySelector('[data-action="banned"]').addEventListener('change', (e) => {
      if (!e.target.checked) {
        // Разбан — сразу, без выбора срока.
        if (!confirm(`Точно разбанить ${a.name} (@${a.username})?`)) { e.target.checked = true; return; }
        socket.emit('admin:set-banned', { accountId: a.id, banned: false });
        return;
      }
      // Бан — сначала спрашиваем срок через модалку, флажок вернём назад,
      // если админ передумает (закроет модалку без выбора).
      e.target.checked = false;
      openBanModal(a);
    });
    row.querySelector('[data-action="kick"]').addEventListener('click', () => {
      if (!confirm(`Разлогинить ${a.name} (@${a.username}) на всех устройствах? Аккаунт не банится, он сможет войти снова.`)) return;
      socket.emit('admin:kick', { accountId: a.id });
    });
    row.querySelector('[data-action="reset-pw"]').addEventListener('click', () => openResetPasswordModal(a));
    box.appendChild(row);
  });
}

// ------------------------------------------------------------------
// Сброс пароля (модалка)
// ------------------------------------------------------------------
function openResetPasswordModal(account) {
  pendingResetAccount = account;
  el('reset-pw-target').textContent = `${account.name} (@${account.username})`;
  el('reset-pw-input').value = '';
  el('reset-pw-error').classList.add('hidden');
  el('reset-pw-overlay').classList.remove('hidden');
  el('reset-pw-input').focus();
}
function closeResetPasswordModal() {
  pendingResetAccount = null;
  el('reset-pw-overlay').classList.add('hidden');
}
el('reset-pw-cancel').addEventListener('click', closeResetPasswordModal);
el('reset-pw-overlay').addEventListener('click', (e) => { if (e.target.id === 'reset-pw-overlay') closeResetPasswordModal(); });
el('reset-pw-confirm').addEventListener('click', () => {
  if (!pendingResetAccount) return;
  const newPassword = el('reset-pw-input').value;
  if (newPassword.length < 4) {
    const box = el('reset-pw-error');
    box.textContent = 'Пароль должен быть не короче 4 символов.';
    box.classList.remove('hidden');
    return;
  }
  socket.emit('admin:reset-password', { accountId: pendingResetAccount.id, newPassword });
  closeResetPasswordModal();
});
el('reset-pw-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') el('reset-pw-confirm').click(); });

// ------------------------------------------------------------------
// Бан (модалка выбора срока)
// ------------------------------------------------------------------
function openBanModal(account) {
  pendingBanAccount = account;
  el('ban-target').textContent = `${account.name} (@${account.username})`;
  el('ban-overlay').classList.remove('hidden');
}
function closeBanModal() {
  pendingBanAccount = null;
  el('ban-overlay').classList.add('hidden');
}
el('ban-cancel').addEventListener('click', closeBanModal);
el('ban-overlay').addEventListener('click', (e) => { if (e.target.id === 'ban-overlay') closeBanModal(); });
el('ban-durations').addEventListener('click', (e) => {
  const btn = e.target.closest('.admin-duration-btn');
  if (!btn || !pendingBanAccount) return;
  const ms = Number(btn.dataset.ms);
  socket.emit('admin:set-banned', { accountId: pendingBanAccount.id, banned: true, durationMs: ms > 0 ? ms : undefined });
  closeBanModal();
});

// ------------------------------------------------------------------
// Группы
// ------------------------------------------------------------------
socket.on('admin:groups', (list) => {
  groups = list || [];
  renderGroupsList(el('admin-search').value);
});

function renderGroupsList(filter = '') {
  const box = el('groups-list');
  const q = filter.trim().toLowerCase();
  const filtered = groups.filter((g) => (g.name || '').toLowerCase().includes(q));

  el('groups-empty').classList.toggle('hidden', groups.length > 0);
  box.innerHTML = '';

  filtered.forEach((g) => {
    const row = document.createElement('div');
    row.className = 'admin-row';
    row.innerHTML = `
      <div class="admin-avatar" style="background:${avatarBg(g.name)}">${initials(g.name)}</div>
      <div class="admin-row-meta">
        <div class="admin-row-name">${escapeHtml(g.name)}${g.isDefault ? ' <span class="admin-hint" style="display:inline">(общий чат)</span>' : ''}</div>
        <div class="admin-row-sub">
          ${g.memberCount} участник(ов) · ${g.messageCount} сообщений
          ${g.ownerName ? `· владелец ${escapeHtml(g.ownerName)}` : ''} · с ${formatDate(g.createdAt)}
        </div>
      </div>
      <div class="admin-row-actions">
        <button type="button" class="admin-row-btn" data-action="messages" title="Сообщения">💬</button>
        ${g.isDefault ? '' : '<button type="button" class="admin-row-btn danger" data-action="delete-group" title="Удалить группу">🗑</button>'}
      </div>
    `;
    row.querySelector('[data-action="messages"]').addEventListener('click', () => openMessagesModal(g.id, g.name));
    const delBtn = row.querySelector('[data-action="delete-group"]');
    if (delBtn) {
      delBtn.addEventListener('click', () => {
        if (!confirm(`Удалить группу «${g.name}» безвозвратно, вместе со всей историей сообщений?`)) return;
        socket.emit('admin:delete-group', { chatId: g.id });
      });
    }
    box.appendChild(row);
  });
}

// ------------------------------------------------------------------
// Сообщения чата (модалка точечной модерации): посмотреть последние
// сообщения, удалить одно конкретное или закрепить/открепить его.
// ------------------------------------------------------------------
function openMessagesModal(chatId, chatName) {
  messagesChatId = chatId;
  el('messages-title').textContent = `Сообщения — ${chatName}`;
  el('messages-list').innerHTML = '';
  el('messages-empty').classList.add('hidden');
  el('messages-overlay').classList.remove('hidden');
  socket.emit('admin:chat-messages', { chatId });
}
function closeMessagesModal() {
  messagesChatId = null;
  el('messages-overlay').classList.add('hidden');
}
el('messages-close').addEventListener('click', closeMessagesModal);
el('messages-overlay').addEventListener('click', (e) => { if (e.target.id === 'messages-overlay') closeMessagesModal(); });

socket.on('admin:chat-messages', ({ chatId, chatName, messages } = {}) => {
  if (chatId !== messagesChatId) return; // модалка уже закрыта/переключена на другой чат
  if (chatName) el('messages-title').textContent = `Сообщения — ${chatName}`;
  renderMessagesList(messages || []);
});

function renderMessagesList(messages) {
  const box = el('messages-list');
  el('messages-empty').classList.toggle('hidden', messages.length > 0);
  box.innerHTML = '';
  messages.forEach((m) => {
    const row = document.createElement('div');
    row.className = `admin-row admin-message-row${m.deleted ? ' is-deleted' : ''}${m.pinned ? ' is-pinned' : ''}`;
    row.innerHTML = `
      <div class="admin-row-meta">
        <div class="admin-row-name">${escapeHtml(m.senderName || 'Система')}${m.pinned ? ' 📌' : ''}</div>
        <div class="admin-row-sub">${formatDateTime(m.time)}</div>
        <div class="admin-message-text">${escapeHtml(m.deleted ? 'Сообщение удалено' : (m.preview || ''))}</div>
      </div>
      <div class="admin-row-actions">
        ${!m.deleted && m.type !== 'system' ? `<button type="button" class="admin-row-btn${m.pinned ? ' active' : ''}" data-action="pin" title="${m.pinned ? 'Открепить' : 'Закрепить'}">📌</button>` : ''}
        ${!m.deleted && m.type !== 'system' ? '<button type="button" class="admin-row-btn danger" data-action="delete" title="Удалить сообщение">🗑</button>' : ''}
      </div>
    `;
    const pinBtn = row.querySelector('[data-action="pin"]');
    if (pinBtn) {
      pinBtn.addEventListener('click', () => {
        socket.emit(m.pinned ? 'admin:unpin-message' : 'admin:pin-message', { chatId: messagesChatId, messageId: m.id });
        m.pinned = !m.pinned;
        renderMessagesList(messages);
      });
    }
    const delBtn = row.querySelector('[data-action="delete"]');
    if (delBtn) {
      delBtn.addEventListener('click', () => {
        if (!confirm('Удалить это сообщение безвозвратно?')) return;
        socket.emit('admin:delete-message', { chatId: messagesChatId, messageId: m.id });
        m.deleted = true;
        renderMessagesList(messages);
      });
    }
    box.appendChild(row);
  });
}

// ------------------------------------------------------------------
// Заблокированные попытки входа
// ------------------------------------------------------------------
socket.on('admin:locked-logins', (list) => {
  lockedLogins = list || [];
  const badge = el('locked-count');
  badge.textContent = lockedLogins.length;
  badge.classList.toggle('hidden', lockedLogins.length === 0);
  renderLockedList();
});

function renderLockedList() {
  const box = el('locked-list');
  el('locked-empty').classList.toggle('hidden', lockedLogins.length > 0);
  box.innerHTML = '';
  lockedLogins.forEach((l) => {
    const row = document.createElement('div');
    row.className = 'admin-row';
    row.innerHTML = `
      <div class="admin-avatar" style="background:#4a2226">⏱</div>
      <div class="admin-row-meta">
        <div class="admin-row-name">@${escapeHtml(l.username)}</div>
        <div class="admin-row-sub">заблокирован ещё ~${l.secondsLeft} сек после серии неверных попыток пароля</div>
      </div>
      <div class="admin-row-actions">
        <button type="button" class="admin-row-btn" data-action="unlock" title="Снять блокировку">🔓</button>
      </div>
    `;
    row.querySelector('[data-action="unlock"]').addEventListener('click', () => {
      socket.emit('admin:unlock-login', { username: l.username });
    });
    box.appendChild(row);
  });
}

// ------------------------------------------------------------------
// Журнал действий
// ------------------------------------------------------------------
socket.on('admin:logs', (list) => {
  actionLogs = list || [];
  renderLogsList();
});

function renderLogsList() {
  const box = el('logs-list');
  el('logs-empty').classList.toggle('hidden', actionLogs.length > 0);
  box.innerHTML = '';
  actionLogs.forEach((entry) => {
    const row = document.createElement('div');
    row.className = 'admin-row';
    row.innerHTML = `
      <div class="admin-avatar" style="background:#2b303a">📝</div>
      <div class="admin-row-meta">
        <div class="admin-row-name">${escapeHtml(entry.label || entry.action)}</div>
        <div class="admin-row-sub">${formatDateTime(entry.ts)} · ${escapeHtml(entry.adminName || 'неизвестно')} · IP ${escapeHtml(entry.ip || 'неизвестно')}</div>
      </div>
    `;
    box.appendChild(row);
  });
}

socket.on('connect_error', () => {
  showLoginError('Не удалось подключиться к серверу.');
});