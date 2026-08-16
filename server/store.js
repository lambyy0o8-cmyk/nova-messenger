const fs = require('fs');
const path = require('path');
const os = require('os');

// ------------------------------------------------------------------
// Хранилище состояния сервера. Два режима:
//
// 1) ЛОКАЛЬНЫЙ ФАЙЛ (по умолчанию) — весь стейт пишется в один JSON-файл
//    вне папки проекта (в домашней директории), чтобы обновление/замена
//    файлов кода его не затирала. Этого достаточно для локального
//    запуска и для хостинга с постоянным диском (VPS, Render на плане
//    Starter+ с подключённым Persistent Disk и т.п.).
//
// 2) УДАЛЁННОЕ ХРАНИЛИЩЕ — Upstash Redis (если заданы переменные
//    окружения UPSTASH_REDIS_REST_URL и UPSTASH_REDIS_REST_TOKEN).
//    Это нужно для хостингов с ЭФЕМЕРНОЙ файловой системой — например,
//    бесплатный план Render. Там ЛЮБОЙ файл на диске (даже вне папки
//    проекта) пропадает при каждом передеплое/перезапуске контейнера,
//    потому что весь диск каждый раз собирается заново из образа —
//    Persistent Disk на бесплатном плане недоступен. В таком случае
//    единственный способ не терять аккаунты — хранить данные не на
//    диске сервиса, а во внешнем хранилище, которое живёт отдельно.
//
//    Как включить (бесплатно):
//    1. Зарегистрируйся на upstash.com, создай базу Redis (free tier).
//    2. В консоли базы скопируй "REST URL" и "REST TOKEN".
//    3. На Render: Environment → Add Environment Variable →
//       UPSTASH_REDIS_REST_URL и UPSTASH_REDIS_REST_TOKEN, вставь
//       скопированные значения, сохрани (это передеплоит сервис).
//    Больше ничего менять не нужно — при наличии этих переменных
//    сервер сам переключается в удалённый режим при старте (см. лог
//    "[store] Режим хранения" при запуске).
//
//    Ограничение: кастомные стикеры (сами файлы картинок, не их
//    метаданные) по-прежнему хранятся на локальном диске в
//    STICKERS_DIR — в удалённом режиме на Render Free они всё ещё не
//    переживут передеплой. Аккаунты, пароли, чаты, сообщения и
//    контакты — переживают.
// ------------------------------------------------------------------

const DATA_DIR = process.env.NOVA_DATA_DIR || path.join(os.homedir(), '.nova-messenger', 'data');
const DATA_FILE = path.join(DATA_DIR, 'store.json');
// Кастомные стикеры пользователей хранятся не в JSON (base64 раздул бы
// стейт), а обычными файлами на диске рядом с ним — сюда пишутся сами
// картинки, а в общий стейт попадают только их метаданные (id,
// расширение, mime, дата) через customStickers.
const STICKERS_DIR = path.join(DATA_DIR, 'stickers');

const UPSTASH_URL = (process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/+$/, '');
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const REMOTE_KEY = process.env.NOVA_REMOTE_KEY || 'nova-messenger:store';
const useRemoteStore = !!(UPSTASH_URL && UPSTASH_TOKEN);

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(STICKERS_DIR)) fs.mkdirSync(STICKERS_DIR, { recursive: true });
}

// Map/Set нельзя напрямую сохранить в JSON — переводим в массивы/объекты
// и обратно.
function serialize(state) {
  return {
    accounts: Array.from(state.accounts.values()),
    usedNovaIds: Array.from(state.usedNovaIds),
    usedUsernames: Array.from(state.usedUsernames.entries()),
    contacts: Array.from(state.contacts.entries()).map(([id, set]) => [id, Array.from(set)]),
    blockedUsers: Array.from(state.blockedUsers.entries()).map(([id, set]) => [id, Array.from(set)]),
    chats: Array.from(state.chats.values()).map((chat) => ({
      ...chat,
      members: Array.from(chat.members),
      admins: Array.from(chat.admins || []),
    })),
    // Архивация — персональная (у разных людей один и тот же чат может
    // быть архивирован или нет), поэтому это Map<accountId, Set<chatId>>,
    // а не поле на самом чате.
    archivedChats: Array.from(state.archivedChats.entries()).map(([id, set]) => [id, Array.from(set)]),
    // Последнее прочитанное сообщение на чат, тоже персонально на
    // пользователя — нужно для бейджа непрочитанных, который не
    // должен считать чаты, лежащие в архиве.
    lastRead: Array.from(state.lastRead.entries()).map(([id, map]) => [id, Array.from(map.entries())]),
    customStickers: Array.from(state.customStickers.entries()),
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

  state.blockedUsers.clear();
  for (const [accountId, list] of data.blockedUsers || []) state.blockedUsers.set(accountId, new Set(list));

  state.chats.clear();
  for (const chat of data.chats || []) {
    state.chats.set(chat.id, { ...chat, members: new Set(chat.members), admins: new Set(chat.admins || []) });
  }

  state.archivedChats.clear();
  for (const [accountId, list] of data.archivedChats || []) state.archivedChats.set(accountId, new Set(list));

  state.lastRead.clear();
  for (const [accountId, entries] of data.lastRead || []) state.lastRead.set(accountId, new Map(entries));

  state.customStickers.clear();
  for (const [accountId, list] of data.customStickers || []) state.customStickers.set(accountId, list);
}

// ------------------------------------------------------------------
// Upstash Redis REST API — простой GET/SET одного ключа с целым JSON
// внутри. Никакой схемы не нужно, это прямая замена файла на диске.
// ------------------------------------------------------------------
async function remoteRead() {
  const res = await fetch(`${UPSTASH_URL}/get/${encodeURIComponent(REMOTE_KEY)}`, {
    headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` },
  });
  if (!res.ok) throw new Error(`Upstash GET вернул ${res.status}`);
  const data = await res.json();
  return data.result; // строка с JSON или null, если ключа ещё нет
}

async function remoteWrite(jsonString) {
  const res = await fetch(`${UPSTASH_URL}/set/${encodeURIComponent(REMOTE_KEY)}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` },
    body: jsonString,
  });
  if (!res.ok) throw new Error(`Upstash SET вернул ${res.status}`);
}

// Загрузка при старте сервера. Возвращает Promise<boolean> — true, если
// данные найдены и применены (тогда дефолтный "общий чат", созданный до
// вызова, будет перезаписан сохранённой версией — это ожидаемо).
async function loadState(state) {
  if (useRemoteStore) {
    console.log('[store] Режим хранения: Upstash Redis (переживает передеплой на эфемерных хостингах вроде Render Free)');
    try {
      const raw = await remoteRead();
      if (!raw) return false;
      deserialize(JSON.parse(raw), state);
      return true;
    } catch (err) {
      console.error('[store] Не удалось прочитать данные из Upstash, стартуем с чистого состояния:', err.message);
      return false;
    }
  }

  ensureDataDir();
  console.log(`[store] Режим хранения: локальный файл ${DATA_FILE} (переменные UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN не заданы)`);
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
// т.п.) пишем не чаще раза в секунду, а не при каждом чихе.
function saveState(state) {
  pendingState = state;
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    const toSave = pendingState;
    pendingState = null;
    writeNow(toSave).catch((err) => console.error('[store] Не удалось сохранить данные:', err.message));
  }, 1000);
}

// Немедленная запись без дебаунса — для выхода из процесса, чтобы не
// потерять последние секунды изменений. Возвращает Promise — вызывающий
// код должен дождаться её перед завершением процесса.
async function saveStateNow(state) {
  if (saveTimer) {
    clearTimeout(saveTimer);
    saveTimer = null;
    pendingState = null;
  }
  await writeNow(state);
}

async function writeNow(state) {
  const json = JSON.stringify(serialize(state));

  if (useRemoteStore) {
    try {
      await remoteWrite(json);
    } catch (err) {
      console.error('[store] Не удалось сохранить данные в Upstash:', err.message);
    }
    return;
  }

  ensureDataDir();
  const tmpFile = `${DATA_FILE}.tmp`;
  try {
    fs.writeFileSync(tmpFile, json);
    fs.renameSync(tmpFile, DATA_FILE); // атомарная замена, чтобы не оставить битый файл при сбое
  } catch (err) {
    console.error('[store] Не удалось сохранить data/store.json:', err.message);
  }
}

module.exports = { loadState, saveState, saveStateNow, DATA_DIR, STICKERS_DIR, useRemoteStore };