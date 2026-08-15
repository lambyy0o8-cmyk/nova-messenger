// Админ-консоль подключается к отдельному namespace /admin — он не связан
// с обычными аккаунтами и чатами, только пароль сервера + список аккаунтов.
const socket = io('/admin');

const el = (id) => document.getElementById(id);
let accounts = [];

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
  showLoginError(message || 'Не удалось войти.');
});

socket.on('admin:ok', () => {
  el('admin-password').value = '';
  el('admin-login').classList.add('hidden');
  el('admin-panel').classList.remove('hidden');
});

// ------------------------------------------------------------------
// Список аккаунтов
// ------------------------------------------------------------------
socket.on('admin:accounts', (list) => {
  accounts = list || [];
  renderList(el('admin-search').value);
});

el('admin-refresh').addEventListener('click', () => socket.emit('admin:refresh'));
el('admin-search').addEventListener('input', (e) => renderList(e.target.value));

function renderList(filter = '') {
  const box = el('admin-list');
  const q = filter.trim().toLowerCase();
  const filtered = accounts.filter((a) =>
    a.name.toLowerCase().includes(q) || (a.username || '').toLowerCase().includes(q)
  );

  el('admin-empty').classList.toggle('hidden', accounts.length > 0);
  box.innerHTML = '';

  filtered.forEach((a) => {
    const row = document.createElement('div');
    row.className = 'admin-row';
    row.innerHTML = `
      <div class="admin-avatar" style="background:${avatarBg(a.name)}">${initials(a.name)}</div>
      <div class="admin-row-meta">
        <div class="admin-row-name">${escapeHtml(a.name)} ${verifiedBadge(a.verified)}</div>
        <div class="admin-row-sub">@${escapeHtml(a.username || '')} · ${escapeHtml(a.novaId || '')}</div>
      </div>
      <label class="admin-switch">
        <input type="checkbox" ${a.verified ? 'checked' : ''} data-id="${a.id}">
        <span class="admin-slider"></span>
      </label>
    `;
    row.querySelector('input[type="checkbox"]').addEventListener('change', (e) => {
      socket.emit('admin:set-verified', { accountId: a.id, verified: e.target.checked });
    });
    box.appendChild(row);
  });
}

socket.on('connect_error', () => {
  showLoginError('Не удалось подключиться к серверу.');
});