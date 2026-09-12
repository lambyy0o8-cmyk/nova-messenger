// Админ-консоль подключается к отдельному namespace /admin — он не связан
// с обычными аккаунтами и чатами, только пароль сервера + список аккаунтов,
// групп и заблокированных попыток входа.
const socket = io('/admin');

const el = (id) => document.getElementById(id);
let accounts = [];
let groups = [];
let admins = [];
let lockedLogins = [];
let actionLogs = [];
let activeTab = 'accounts';
let pendingResetAccount = null; // { id, username } — для модалки сброса пароля
let pendingBanAccount = null; // { id, name, username } — для модалки бана (выбор срока)
let messagesChatId = null; // id чата, чьи сообщения сейчас открыты в модалке модерации
let pendingEditMessage = null; // { chatId, messageId } — для модалки редактирования сообщения

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
// Тосты — заменяют системные alert() всплывающими карточками в тон
// остальной панели, не блокируют поток (в отличие от alert()).
// ------------------------------------------------------------------
function toast(message, kind = 'info') {
  if (!message) return;
  const box = el('toast-container');
  if (!box) { alert(message); return; }
  const node = document.createElement('div');
  node.className = `toast${kind === 'error' ? ' error' : kind === 'success' ? ' success' : ''}`;
  node.textContent = message;
  box.appendChild(node);
  setTimeout(() => {
    node.classList.add('leaving');
    setTimeout(() => node.remove(), 200);
  }, 4000);
}

// Плавно "прокручивает" число в статистике до нового значения вместо
// мгновенной подмены — короткая, но живая деталь на панели, которая
// в остальном состоит из статичных списков.
function countUp(elId, value) {
  const node = el(elId);
  if (!node) return;
  const to = Number(value) || 0;
  const from = Number(node.dataset.value || 0);
  node.dataset.value = to;
  if (from === to) { node.textContent = to; return; }
  const duration = 350;
  const start = performance.now();
  function step(now) {
    const p = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - p, 3);
    node.textContent = Math.round(from + (to - from) * eased);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
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
      toast(message || 'Не удалось выполнить действие.', 'error');
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
  // Готовим инфраструктуру расширенных функций: полосу массовых операций
  // над аккаунтами и первичную загрузку настроек (нужна, если админ сразу
  // откроет вкладку «Настройки»).
  ensureBulkBar();
  socket.emit('admin:get-settings');
  requestAnimationFrame(moveTabIndicator);
});

socket.on('admin:action-ok', ({ message }) => {
  if (message) toast(message, 'success');
});

// Если этого админа удалили из консоли прямо во время его сессии (кто-то
// другой нажал "удалить" на нём в списке админов) — выкидываем на экран
// входа, а не оставляем висеть с уже недействительным доступом.
socket.on('admin:kicked-out', () => {
  toast('Ваш доступ администратора был отозван.', 'error');
  el('admin-panel').classList.add('hidden');
  el('admin-login').classList.remove('hidden');
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
  moveTabIndicator();
}
// Двигает скользящую полоску под активной вкладкой на её позицию —
// пересчитывается и при ресайзе, раз ширины вкладок не фиксированы.
function moveTabIndicator() {
  const active = document.querySelector('.admin-tab.active');
  const indicator = el('admin-tab-indicator');
  if (!active || !indicator) return;
  indicator.style.left = `${active.offsetLeft}px`;
  indicator.style.width = `${active.offsetWidth}px`;
}
window.addEventListener('resize', moveTabIndicator);

// ------------------------------------------------------------------
// Статистика
// ------------------------------------------------------------------
socket.on('admin:stats', (stats) => {
  if (!stats) return;
  countUp('stat-total', stats.totalAccounts);
  countUp('stat-online', stats.onlineAccounts);
  countUp('stat-banned', stats.bannedAccounts);
  countUp('stat-groups', stats.groupChats);
  countUp('stat-messages', stats.totalMessages);
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
      <label class="admin-row-select" title="Выбрать для массовой операции"><input type="checkbox" ${selectedAccountIds.has(a.id) ? 'checked' : ''}></label>
      <div class="admin-avatar" style="background:${avatarBg(a.name)}">${initials(a.name)}</div>
      <div class="admin-row-meta" data-open-card="${escapeHtml(a.id)}" style="cursor:pointer">
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
        <button type="button" class="admin-row-btn" data-action="details" title="Подробнее">ℹ</button>
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
    // Чекбокс массовой операции.
    row.querySelector('.admin-row-select input').addEventListener('change', (e) => {
      if (e.target.checked) selectedAccountIds.add(a.id);
      else selectedAccountIds.delete(a.id);
      updateBulkBar();
    });
    // Клик по имени/мете открывает подробную карточку аккаунта.
    row.querySelector('[data-open-card]').addEventListener('click', (e) => {
      e.stopPropagation();
      openAccountCard(a.id);
    });
    // Кнопка «Подробнее» — то же самое.
    row.querySelector('[data-action="details"]').addEventListener('click', () => openAccountCard(a.id));
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
// Админы — управление тем, кто ещё имеет доступ к этой консоли. Любой
// уже вошедший админ может добавить нового (имя + пароль) — прав у него
// будет ровно столько же, отдельной системы ролей нет. "Встроенных"
// (заданных на сервере через ADMIN_ACCOUNTS/ADMIN_PASSWORD) отсюда не
// удалить — только созданных прямо здесь.
// ------------------------------------------------------------------
socket.on('admin:admins', (list) => {
  admins = list || [];
  renderAdminsList();
});

function renderAdminsList() {
  const box = el('admins-list');
  el('admins-empty').classList.toggle('hidden', admins.length > 0);
  box.innerHTML = '';
  admins.forEach((a) => {
    const row = document.createElement('div');
    row.className = 'admin-row';
    row.innerHTML = `
      <div class="admin-avatar" style="background:${avatarBg(a.name)}">${initials(a.name)}</div>
      <div class="admin-row-meta">
        <div class="admin-row-name">${escapeHtml(a.name)}${a.source === 'env' ? '<span class="admin-badge-env" title="Задан на сервере через ADMIN_ACCOUNTS/ADMIN_PASSWORD">окружение</span>' : ''}</div>
        <div class="admin-row-sub">${a.source === 'env' ? 'нельзя удалить из консоли' : `добавлен ${formatDateTime(a.createdAt)}${a.createdBy ? ` · кем: ${escapeHtml(a.createdBy)}` : ''}`}</div>
      </div>
      <div class="admin-row-actions">
        ${a.source === 'dynamic' ? '<button type="button" class="admin-row-btn danger" data-action="delete-admin" title="Удалить админа">🗑</button>' : ''}
      </div>
    `;
    const delBtn = row.querySelector('[data-action="delete-admin"]');
    if (delBtn) {
      delBtn.addEventListener('click', () => {
        if (!confirm(`Удалить админа «${a.name}»? Он потеряет доступ к консоли, если сейчас в ней находится.`)) return;
        socket.emit('admin:delete-admin', { id: a.id });
      });
    }
    box.appendChild(row);
  });
}

el('admin-new-confirm').addEventListener('click', submitNewAdmin);
el('admin-new-password').addEventListener('keydown', (e) => { if (e.key === 'Enter') submitNewAdmin(); });
function submitNewAdmin() {
  const name = el('admin-new-name').value.trim();
  const password = el('admin-new-password').value;
  if (!name) { el('admin-new-name').focus(); return; }
  if (password.length < 4) { toast('Пароль должен быть не короче 4 символов.', 'error'); el('admin-new-password').focus(); return; }
  socket.emit('admin:create-admin', { name, password });
  el('admin-new-name').value = '';
  el('admin-new-password').value = '';
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

// ------------------------------------------------------------------
// Редактирование текста сообщения (модалка поверх модалки сообщений).
// Доступно только для обычных текстовых сообщений — у зашифрованных
// личных чатов сервер не видит текст, редактировать там нечего (кнопка
// для них вообще не показывается, см. m.editable в renderMessagesList).
// ------------------------------------------------------------------
function openEditMessageModal(m) {
  pendingEditMessage = { chatId: messagesChatId, messageId: m.id, message: m };
  el('edit-message-target').textContent = `Отправитель: ${m.senderName || 'неизвестно'}`;
  el('edit-message-input').value = m.preview || '';
  el('edit-message-error').classList.add('hidden');
  el('edit-message-overlay').classList.remove('hidden');
  el('edit-message-input').focus();
}
function closeEditMessageModal() {
  pendingEditMessage = null;
  el('edit-message-overlay').classList.add('hidden');
}
el('edit-message-cancel').addEventListener('click', closeEditMessageModal);
el('edit-message-overlay').addEventListener('click', (e) => { if (e.target.id === 'edit-message-overlay') closeEditMessageModal(); });
el('edit-message-confirm').addEventListener('click', () => {
  if (!pendingEditMessage) return;
  const newText = el('edit-message-input').value;
  if (!newText.trim()) {
    const box = el('edit-message-error');
    box.textContent = 'Текст не может быть пустым.';
    box.classList.remove('hidden');
    return;
  }
  socket.emit('admin:edit-message', { chatId: pendingEditMessage.chatId, messageId: pendingEditMessage.messageId, text: newText });
  socket.emit('admin:chat-messages', { chatId: pendingEditMessage.chatId });
  closeEditMessageModal();
  toast('Сообщение изменено.', 'success');
});

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
        ${m.editable ? '<button type="button" class="admin-row-btn" data-action="edit" title="Изменить текст">✏️</button>' : ''}
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
    const editBtn = row.querySelector('[data-action="edit"]');
    if (editBtn) {
      editBtn.addEventListener('click', () => openEditMessageModal(m));
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

// ==================================================================
// РАСШИРЕННЫЕ ФУНКЦИИ (2026-09-12)
// ------------------------------------------------------------------
// Подробная карточка аккаунта, массовые операции, создание/редактирование
// групп, очистка истории, глобальный поиск, метрики, настройки, экспорт
// журнала и управление приложениями. Все данные приходят с сервера
// событиями admin:* (см. server/index.js).
// ==================================================================

let selectedAccountIds = new Set();
let currentAccountDetailsId = null;

// ---- Подробности аккаунта ----
function openAccountCard(accountId) {
  currentAccountDetailsId = accountId;
  el('account-card-title').textContent = 'Аккаунт';
  el('account-card-body').innerHTML = '<p class="admin-hint">Загрузка…</p>';
  el('account-overlay').classList.remove('hidden');
  socket.emit('admin:account-details', { accountId });
}
function closeAccountCard() {
  currentAccountDetailsId = null;
  el('account-overlay').classList.add('hidden');
}
el('account-card-close').addEventListener('click', closeAccountCard);
el('account-overlay').addEventListener('click', (e) => { if (e.target.id === 'account-overlay') closeAccountCard(); });

function fmtBytes(n) {
  if (!n) return '0 Б';
  if (n < 1024) return `${n} Б`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} КБ`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} МБ`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} ГБ`;
}
function fmtDuration(sec) {
  sec = Math.floor(sec || 0);
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (d) return `${d}д ${h}ч`;
  if (h) return `${h}ч ${m}м`;
  if (m) return `${m}м ${s}с`;
  return `${s}с`;
}

socket.on('admin:account-details', (data) => {
  if (!data || data.error) {
    el('account-card-body').innerHTML = `<p class="admin-hint">${escapeHtml(data && data.error || 'Не удалось загрузить.')}</p>`;
    return;
  }
  const a = data.account;
  const s = data.stats;
  el('account-card-title').textContent = `${a.name} (@${a.username})`;
  const body = el('account-card-body');
  body.innerHTML = `
    <div class="admin-acc-stats">
      <div class="admin-acc-stat"><b>${s.messageCount}</b><span>сообщений</span></div>
      <div class="admin-acc-stat"><b>${s.chatCount}</b><span>чатов</span></div>
      <div class="admin-acc-stat"><b>${s.contactCount}</b><span>контактов</span></div>
      <div class="admin-acc-stat"><b>${s.blockedCount}</b><span>заблокировано</span></div>
      <div class="admin-acc-stat"><b>${s.stickerCount}</b><span>стикеров</span></div>
      <div class="admin-acc-stat"><b>${s.activeSockets}</b><span>устройств онлайн</span></div>
    </div>
    <div class="admin-row-sub" style="margin-bottom:10px">
      Nova ID: ${escapeHtml(a.novaId || '')} · создан ${formatDate(a.createdAt)}<br>
      Последний вход: ${a.lastSeen ? formatDateTime(a.lastSeen) : 'неизвестно'}<br>
      IP сейчас: ${s.ips.length ? escapeHtml(s.ips.join(', ')) : '—'}<br>
      2FA: ${a.twoFactorEnabled ? 'включена' : 'выключена'} · email: ${a.email ? escapeHtml(a.email) + (a.emailVerified ? ' ✓' : ' (не подтверждён)') : '—'}
    </div>
    <div class="admin-acc-field">
      <label>Имя</label>
      <input id="acc-edit-name" type="text" maxlength="24" value="${escapeHtml(a.name)}">
    </div>
    <div class="admin-acc-field">
      <label>Юзернейм</label>
      <input id="acc-edit-username" type="text" maxlength="32" value="${escapeHtml(a.username || '')}">
    </div>
    <div class="admin-acc-field">
      <label>Email</label>
      <input id="acc-edit-email" type="text" value="${escapeHtml(a.email || '')}">
    </div>
    <div class="admin-acc-actions">
      <button type="button" class="primary" id="acc-save-name">Сохранить имя</button>
      <button type="button" class="primary" id="acc-save-username">Сохранить @</button>
      <button type="button" class="primary" id="acc-save-email">Сохранить email</button>
      <button type="button" id="acc-open-chat" data-chat="${escapeHtml(a.id)}">Открыть чат</button>
      <button type="button" class="danger" id="acc-clear-stickers">Очистить стикеры</button>
      <button type="button" class="danger" id="acc-delete">Удалить ${a.isBot ? 'бота' : 'аккаунт'}</button>
    </div>
  `;
  el('acc-save-name').addEventListener('click', () => {
    socket.emit('admin:set-name', { accountId: a.id, name: el('acc-edit-name').value.trim() });
  });
  el('acc-save-username').addEventListener('click', () => {
    socket.emit('admin:set-username', { accountId: a.id, username: el('acc-edit-username').value.trim() });
  });
  el('acc-save-email').addEventListener('click', () => {
    socket.emit('admin:set-email', { accountId: a.id, email: el('acc-edit-email').value.trim(), verified: false });
  });
  el('acc-clear-stickers').addEventListener('click', () => {
    if (!confirm(`Очистить все кастомные стикеры ${a.name}?`)) return;
    socket.emit('admin:clear-stickers', { accountId: a.id });
  });
  el('acc-open-chat').addEventListener('click', () => {
    if (!a.id) return;
    // Личный чат с самим собой как ориентир: открываем историю личных
    // чатов аккаунта через общий поиск чата невозможно (админка не
    // состоит в чатах), поэтому просто подсказываем ID.
    toast('ID аккаунта: ' + a.id);
  });
  el('acc-delete').addEventListener('click', () => {
    openConfirm(
      `Удалить ${a.isBot ? 'бота' : 'аккаунт'}?`,
      `${a.name} (@${a.username}) будет удалён безвозвратно: сессии оборвутся, он пропадёт из всех чатов, контактов и групп. Это действие необратимо.`,
      () => {
        socket.emit('admin:delete-account', { accountId: a.id });
        closeAccountCard();
      }
    );
  });
});

// ---- Массовые операции ----
function updateBulkBar() {
  const bar = el('bulk-bar');
  if (!bar) return;
  bar.classList.toggle('hidden', selectedAccountIds.size === 0);
  const count = el('bulk-count');
  if (count) count.textContent = `Выбрано: ${selectedAccountIds.size}`;
}
function ensureBulkBar() {
  if (el('bulk-bar')) return;
  const bar = document.createElement('div');
  bar.id = 'bulk-bar';
  bar.className = 'admin-bulk-bar hidden';
  bar.innerHTML = `
    <span class="admin-bulk-count" id="bulk-count">Выбрано: 0</span>
    <button type="button" data-bulk="kick">Разлогинить</button>
    <button type="button" data-bulk="unban">Разбанить</button>
    <button type="button" data-bulk="unverify">Снять галочку</button>
    <button type="button" class="danger" data-bulk="ban">Забанить</button>
    <button type="button" class="danger" data-bulk="delete">Удалить</button>
  `;
  bar.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-bulk]');
    if (!btn || !selectedAccountIds.size) return;
    const action = btn.dataset.bulk;
    const label = btn.textContent;
    openConfirm(`Массовая операция: ${label}`, `Применить «${label}» к ${selectedAccountIds.size} аккаунт(ам)? Для «Удалить» действие необратимо.`, () => {
      socket.emit('admin:bulk', { action, accountIds: Array.from(selectedAccountIds) });
      selectedAccountIds.clear();
      updateBulkBar();
    });
  });
  el('admin-list').parentNode.insertBefore(bar, el('admin-list'));
}

// ---- Подтверждение ----
let pendingConfirmFn = null;
function openConfirm(title, text, fn) {
  el('confirm-title').textContent = title;
  el('confirm-text').textContent = text;
  pendingConfirmFn = fn;
  el('confirm-overlay').classList.remove('hidden');
}
function closeConfirm() {
  pendingConfirmFn = null;
  el('confirm-overlay').classList.add('hidden');
}
el('confirm-cancel').addEventListener('click', closeConfirm);
el('confirm-overlay').addEventListener('click', (e) => { if (e.target.id === 'confirm-overlay') closeConfirm(); });
el('confirm-ok').addEventListener('click', () => {
  if (pendingConfirmFn) pendingConfirmFn();
  closeConfirm();
});

// ---- Глобальный поиск сообщений ----
el('msg-search-btn').addEventListener('click', doSearchMessages);
el('msg-search-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') doSearchMessages(); });
function doSearchMessages() {
  const q = el('msg-search-input').value.trim();
  if (q.length < 2) { toast('Введи хотя бы 2 символа.', 'error'); return; }
  socket.emit('admin:search-messages', { query: q });
}
socket.on('admin:search-messages', ({ results } = {}) => {
  const list = el('msg-search-list');
  list.innerHTML = '';
  const arr = results || [];
  el('msg-search-empty').classList.toggle('hidden', arr.length > 0);
  arr.forEach((r) => {
    const row = document.createElement('div');
    row.className = 'admin-row admin-search-hit';
    row.innerHTML = `
      <div class="admin-avatar" style="background:#2b303a">💬</div>
      <div class="admin-row-meta">
        <div class="admin-row-name">${escapeHtml(r.chatName || 'Чат')}</div>
        <div class="admin-row-sub">${escapeHtml(r.senderName || '')} · ${formatDateTime(r.time)}</div>
        <div class="admin-message-text">${escapeHtml(r.text || '')}</div>
      </div>
    `;
    row.addEventListener('click', () => openMessagesModal(r.chatId, r.chatName));
    list.appendChild(row);
  });
});

// ---- Приложения ----
socket.on('admin:list-apps', ({ apps } = {}) => {
  const list = el('apps-list');
  list.innerHTML = '';
  const arr = apps || [];
  el('apps-empty').classList.toggle('hidden', arr.length > 0);
  arr.forEach((a) => {
    const row = document.createElement('div');
    row.className = 'admin-row';
    row.innerHTML = `
      <div class="admin-avatar" style="background:#2b303a">🧩</div>
      <div class="admin-row-meta">
        <div class="admin-row-name">${escapeHtml(a.name)}</div>
        <div class="admin-row-sub">автор: ${escapeHtml(a.ownerName || a.ownerId)} · ${fmtBytes(a.htmlBytes)} · ${formatDate(a.createdAt)}</div>
      </div>
      <div class="admin-row-actions">
        <button type="button" class="admin-row-btn danger" data-action="del-app" title="Удалить">🗑</button>
      </div>
    `;
    row.querySelector('[data-action="del-app"]').addEventListener('click', () => {
      if (!confirm(`Удалить приложение «${a.name}»?`)) return;
      socket.emit('admin:delete-app', { appId: a.id });
    });
    list.appendChild(row);
  });
});

// ---- Настройки ----
socket.on('admin:settings', (s) => {
  if (!s) return;
  if (el('setting-registrationOpen')) el('setting-registrationOpen').checked = !!s.registrationOpen;
  if (el('setting-maintenanceMode')) el('setting-maintenanceMode').checked = !!s.maintenanceMode;
  if (el('setting-readOnlyMode')) el('setting-readOnlyMode').checked = !!s.readOnlyMode;
});
['registrationOpen', 'maintenanceMode', 'readOnlyMode'].forEach((key) => {
  const input = el('setting-' + key);
  if (!input) return;
  input.addEventListener('change', () => {
    socket.emit('admin:set-setting', { key, value: input.checked });
  });
});
const restartBtn = el('restart-server-btn');
if (restartBtn) {
  restartBtn.addEventListener('click', () => {
    openConfirm('Перезапустить сервер?', 'Состояние будет сохранено, процесс завершится. Если сервер запущен через менеджер (nodemon/PM2/Render) — он поднимется заново.', () => {
      socket.emit('admin:restart-server');
    });
  });
}

// ---- Метрики ----
socket.on('admin:metrics', (m) => {
  const grid = el('metrics-grid');
  if (!grid || !m) return;
  const items = [
    ['Аптайм', fmtDuration(m.uptimeSec)],
    ['Память (RSS)', fmtBytes(m.memoryRss)],
    ['Heap used', fmtBytes(m.memoryHeapUsed)],
    ['Heap total', fmtBytes(m.memoryHeapTotal)],
    ['Аккаунтов', m.accounts],
    ['Чатов', m.chats],
    ['Сообщений', m.messages],
    ['Сессий', m.sessions],
    ['Сокетов', m.connectedSockets],
    ['Админ-сессий', m.adminSockets],
    ['Node', m.nodeVersion],
    ['Платформа', m.platform],
  ];
  grid.innerHTML = items.map(([label, val]) => `
    <div class="admin-metric-card">
      <div class="admin-metric-value">${escapeHtml(String(val))}</div>
      <div class="admin-metric-label">${escapeHtml(label)}</div>
    </div>`).join('');
});

// ---- Журнал: фильтр и экспорт ----
el('logs-filter-btn').addEventListener('click', () => {
  socket.emit('admin:logs-filter', {
    adminName: el('logs-filter-admin').value.trim(),
    query: el('logs-filter-query').value.trim(),
  });
});
el('logs-export-btn').addEventListener('click', () => socket.emit('admin:export-logs'));
socket.on('admin:export-logs', ({ csv } = {}) => {
  if (!csv) return;
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `nova-admin-logs-${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast('Журнал выгружен в CSV.', 'success');
});

// Когда админ открывает вкладку — подтягиваем её данные.
// Не переприсваиваем setActiveTab (это хрупко из-за hoisting и порядка
// объявлений), а подписываемся на клики вкладок дополнительным слушателем.
document.querySelectorAll('.admin-tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    if (tab === 'apps') socket.emit('admin:list-apps');
    if (tab === 'metrics') socket.emit('admin:metrics');
    if (tab === 'settings') socket.emit('admin:get-settings');
    if (tab === 'accounts') ensureBulkBar();
  });
});

// Метрики раз в 5 секунд, пока открыта вкладка «Система».
setInterval(() => {
  if (activeTab === 'metrics' && !el('admin-panel').classList.contains('hidden')) socket.emit('admin:metrics');
}, 5000);

socket.on('connect_error', () => {
  showLoginError('Не удалось подключиться к серверу.');
});