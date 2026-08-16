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
        <div class="admin-row-sub">@${escapeHtml(a.username || '')} · ${escapeHtml(a.novaId || '')} · с ${formatDate(a.createdAt)}</div>
      </div>
      <div class="admin-row-actions">
        <button type="button" class="admin-row-btn" data-action="reset-pw" title="Сбросить пароль">🔑</button>
        <button type="button" class="admin-row-btn danger" data-action="kick" title="Разлогинить">⏏</button>
        <label class="admin-switch" title="Подтверждён">
          <input type="checkbox" ${a.verified ? 'checked' : ''} data-action="verified">
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
    row.querySelector('[data-action="banned"]').addEventListener('change', (e) => {
      const verb = e.target.checked ? 'забанить' : 'разбанить';
      if (!confirm(`Точно ${verb} ${a.name} (@${a.username})?`)) { e.target.checked = !e.target.checked; return; }
      socket.emit('admin:set-banned', { accountId: a.id, banned: e.target.checked });
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
        ${g.isDefault ? '' : '<button type="button" class="admin-row-btn danger" data-action="delete-group" title="Удалить группу">🗑</button>'}
      </div>
    `;
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