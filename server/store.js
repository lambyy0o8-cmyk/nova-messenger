const fs = require('fs');
const path = require('path');

// ------------------------------------------------------------------
// Простое файловое хранилище (без БД): весь стейт сервера пишется в
// один JSON-файл на диске и загружается обратно при старте. Этого
// достаточно, чтобы аккаунты, пароли, контакты, чаты и сообщения не
// терялись при перезапуске процесса (обновил код -> npm start снова).
//
// Это НЕ замена настоящей базе данных: при одновременной записи из
// нескольких процессов данные могут конфликтовать, а на хостингах с
// эфемерной файловой системой (некоторые serverless/PaaS без
// persistent volume) файл всё равно исчезнет при новом деплое — там
// нужно постоянное хранилище (диск с volume, SQLite на volume, или
// внешняя БД).
// ------------------------------------------------------------------

const DATA_DIR = path.join(__dirname, '..', 'data');
const DATA_FILE = path.join(DATA_DIR, 'store.json');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Map/Set нельзя напрямую сохранить в JSON — переводим в массивы/объекты
// и обратно.
function serialize(state) {
  return {
    accounts: Array.from(state.accounts.values()),
    usedNovaIds: Array.from(state.usedNovaIds),
    usedUsernames: Array.from(state.usedUsernames.entries()),
    contacts: Array.from(state.contacts.entries()).map(([id, set]) => [id, Array.from(set)]),
    chats: Array.from(state.chats.values()).map((chat) => ({
      ...chat,
      members: Array.from(chat.members),
    })),
  };
}

function deserialize(data, state) {
  state.accounts.clear();
  for (const account of data.accounts || []) state.accounts.set(account.id, account);

  state.usedNovaIds.clear();
  for (const id of data.usedNovaIds || []) state.usedNovaIds.add(id);

  state.usedUsernames.clear();
  for (const [key, accountId] of data.usedUsernames || []) state.usedUsernames.set(key, accountId);

  state.contacts.clear();
  for (const [accountId, list] of data.contacts || []) state.contacts.set(accountId, new Set(list));

  state.chats.clear();
  for (const chat of data.chats || []) {
    state.chats.set(chat.id, { ...chat, members: new Set(chat.members) });
  }
}

// Загрузка при старте сервера. Возвращает true, если данные найдены и
// применены (тогда дефолтный "общий чат", созданный до вызова, будет
// перезаписан сохранённой версией — это ожидаемо).
function loadState(state) {
  ensureDataDir();
  if (!fs.existsSync(DATA_FILE)) return false;
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    if (!raw.trim()) return false;
    deserialize(JSON.parse(raw), state);
    return true;
  } catch (err) {
    console.error('[store] Не удалось прочитать data/store.json, стартуем с чистого состояния:', err.message);
    return false;
  }
}

let saveTimer = null;
let pendingState = null;

// Сохранение с дебаунсом: при частых событиях (сообщения, тайпинг и
// т.п.) пишем файл не чаще раза в секунду, а не при каждом чихе.
function saveState(state) {
  pendingState = state;
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    const toSave = pendingState;
    pendingState = null;
    writeNow(toSave);
  }, 1000);
}

// Немедленная запись без дебаунса — для выхода из процесса, чтобы не
// потерять последние секунды изменений.
function saveStateNow(state) {
  if (saveTimer) {
    clearTimeout(saveTimer);
    saveTimer = null;
    pendingState = null;
  }
  writeNow(state);
}

function writeNow(state) {
  ensureDataDir();
  const tmpFile = `${DATA_FILE}.tmp`;
  try {
    fs.writeFileSync(tmpFile, JSON.stringify(serialize(state)));
    fs.renameSync(tmpFile, DATA_FILE); // атомарная замена, чтобы не оставить битый файл при сбое
  } catch (err) {
    console.error('[store] Не удалось сохранить data/store.json:', err.message);
  }
}

module.exports = { loadState, saveState, saveStateNow };