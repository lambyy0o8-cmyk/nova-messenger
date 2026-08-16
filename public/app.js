const socket = io();

// ------------------------------------------------------------------
// Состояние
// ------------------------------------------------------------------
let me = null;
let chats = [];
let activeChatId = null;
let activePeer = null; // { id, name, username, verified, online } — если открыт личный чат
let myContacts = [];
let typingTimeout = null;

// --- Stage 1: реакции/edit/delete/reply/forward/pin/войс/группы/last seen ---
const messageCache = new Map(); // messageId -> { msg, plainText }
let replyingTo = null;          // { id, senderName, preview }
let editingMessageId = null;
let forwardSourceId = null;
let mediaRecorder = null;
let recordedChunks = [];
let recordSeconds = 0;
let recordTimerHandle = null;
let groupInfoChatId = null;

// --- Stage 2: мультивыбор сообщений, архив чатов, свои стикеры ---
let selectionMode = false;
const selectedMessageIds = new Set();
let archiveCollapsed = localStorage.getItem('nova-archive-collapsed') === '1';
let myCustomStickers = []; // [{ id, url, createdAt }]
let longPressTimer = null;

const el = (id) => document.getElementById(id);

// ------------------------------------------------------------------
// Cookies — чтобы вход сохранялся после перезагрузки страницы/браузера.
// Пароль в cookie никогда не попадает — только случайный токен сессии,
// который сервер умеет обменять обратно на аккаунт.
// ------------------------------------------------------------------
function setCookie(name, value, days) {
  const expires = new Date(Date.now() + days * 864e5).toUTCString();
  document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expires}; path=/; SameSite=Lax`;
}
function getCookie(name) {
  return document.cookie.split('; ').reduce((acc, part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return acc;
    return part.slice(0, idx) === name ? decodeURIComponent(part.slice(idx + 1)) : acc;
  }, '');
}
function eraseCookie(name) {
  document.cookie = `${name}=; Max-Age=-1; path=/`;
}

// ==================================================================
// E2E-ШИФРОВАНИЕ ЛИЧНЫХ ЧАТОВ: X3DH-подобный бутстрап + Double Ratchet
// ==================================================================
// У каждого аккаунта есть долгоживущая ECDH-пара (identity key) —
// генерируется в браузере, приватная часть никогда не покидает браузер
// (хранится в IndexedDB), публичная уходит на сервер и раздаётся всем.
//
// Поверх этого работает Double Ratchet (упрощённая версия протокола
// Signal):
// - Симметричная цепочка (chain ratchet): на каждое сообщение выводится
//   ОДНОРАЗОВЫЙ ключ через HMAC, а сама цепочка необратимо продвигается
//   вперёд. Значит, даже если злоумышленник добудет ключ текущего
//   сообщения, расшифровать предыдущие сообщения он не сможет —
//   это и есть forward secrecy.
// - DH-ratchet: когда приходит ответ с новым эфемерным ключом собеседника,
//   мы подмешиваем свежий Диффи-Хеллман в корневой ключ и генерируем
//   СВОЙ новый эфемерный ключ для следующего сообщения. Так что даже
//   если приватный ключ на какой-то момент утечёт, будущие сообщения
//   всё равно защищены новым материалом — это post-compromise security.
//
// Честные ограничения этой реализации (в отличие от полного Signal
// Protocol):
// - Нет полноценного X3DH с одноразовыми prekeys — первичный секрет
//   выводится напрямую из статических identity-ключей. Это чуть слабее
//   в плане deniability, но принцип forward secrecy для дальнейшей
//   переписки всё равно работает благодаря ratchet поверх.
// - Пропущенные ключи (для сообщений не по порядку) хранятся с неглубоким
//   запасом (до 50 шт.) — этого достаточно для реалистичных задержек сети,
//   но не для очень долгого оффлайна с потерянными сообщениями.
// - Собственные отправленные сообщения не расшифровываются заново из
//   цепочки (это и не предусмотрено протоколом — цепочка отправки для
//   этого не годится), а показываются из короткого локального кэша.
//   После перезагрузки страницы кэш пуст, поэтому история СВОИХ старых
//   сообщений в этой демо-версии показывается как "отправлено", без
//   текста — реальные мессенджеры решают это отдельным шифрованием
//   "себе на память", здесь для простоты этого нет.
// - Ключ (и вся ratchet-цепочка) привязаны к БРАУЗЕРУ/устройству, не
//   синхронизируются между устройствами одного аккаунта.
// - Шифруется только текст личных (1-на-1) сообщений. Группы, стикеры
//   и GIF — как раньше, без шифрования.
let myKeypair = null; // { privateKey: CryptoKey, publicKeyJwk: object }
const sentPlaintextCache = new Map(); // `${chatId}:${dhPubJson}:${n}` -> текст (только для своих сообщений)

function idbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('nova-e2e-keys', 4);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('keypairs')) db.createObjectStore('keypairs');
      if (!db.objectStoreNames.contains('ratchets')) db.createObjectStore('ratchets');
      // plaintext: messageId -> { text } — расшифрованный текст ВХОДЯЩИХ
      // сообщений. Ratchet-ключи одноразовые (продвигаются необратимо),
      // поэтому без этого кэша повторный рендер (переоткрыл чат, обновил
      // страницу) не смог бы расшифровать уже прочитанное сообщение
      // второй раз — decryptMessage() просто упадёт на message-key-unavailable.
      if (!db.objectStoreNames.contains('plaintext')) db.createObjectStore('plaintext');
      // trust: peerId -> { fingerprint, verified } — закреплённый (TOFU)
      // identity-ключ собеседника, для индикатора смены ключа.
      if (!db.objectStoreNames.contains('trust')) db.createObjectStore('trust');
      // meta: accountId -> { pinEnabled, salt } — настройки локальной
      // PIN-блокировки хранилища (сам PIN нигде не сохраняется).
      if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta');
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function idbGet(store, key) {
  const db = await idbOpen();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}
async function idbSet(store, key, value) {
  const db = await idbOpen();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function bufToBase64(buf) {
  let binary = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToBuf(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// ------------------------------------------------------------------
// Локальное шифрование хранилища (PIN-блокировка).
// ------------------------------------------------------------------
// По умолчанию identity-ключ и ratchet-состояния лежат в IndexedDB
// как обычные структурно клонируемые объекты — это удобно (CryptoKey
// хранится "как есть"), но означает, что любой, кто получит доступ
// к профилю браузера на этом устройстве, может их прочитать.
//
// Если PIN включён, каждая запись в store 'keypairs'/'ratchets'
// вместо этого хранится как один зашифрованный блоб: сначала
// CryptoKey/ArrayBuffer-поля переводятся в сериализуемый вид (JWK /
// base64), затем весь объект шифруется AES-GCM ключом, выведенным
// из PIN через PBKDF2 (соль — на устройство, не секрет). Сам PIN
// нигде не сохраняется — только в момент ввода, в оперативной памяти.
let vaultKey = null; // CryptoKey (AES-GCM) или null, если блокировка выключена/не разблокирована

async function vaultEncode(value) {
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (v instanceof CryptoKey) out[k] = { __t: 'key', jwk: await crypto.subtle.exportKey('jwk', v) };
    else if (v instanceof ArrayBuffer) out[k] = { __t: 'buf', b64: bufToBase64(v) };
    else out[k] = v;
  }
  return out;
}
async function vaultDecode(value) {
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (v && v.__t === 'key') out[k] = await crypto.subtle.importKey('jwk', v.jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    else if (v && v.__t === 'buf') out[k] = base64ToBuf(v.b64);
    else out[k] = v;
  }
  return out;
}
async function vaultWrap(value) {
  if (!vaultKey) return value; // PIN выключен — храним как раньше, без изменений
  const encoded = await vaultEncode(value);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, vaultKey, new TextEncoder().encode(JSON.stringify(encoded)));
  return { __vault: 1, iv: bufToBase64(iv.buffer), data: bufToBase64(ct) };
}
async function vaultUnwrap(stored) {
  if (!stored) return stored;
  if (!stored.__vault) return stored; // запись сделана до включения PIN — она не зашифрована
  if (!vaultKey) throw new Error('vault-locked');
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(base64ToBuf(stored.iv)) }, vaultKey, base64ToBuf(stored.data)
  );
  return vaultDecode(JSON.parse(new TextDecoder().decode(plainBuf)));
}
async function idbGetSecure(store, key) {
  return vaultUnwrap(await idbGet(store, key));
}
async function idbSetSecure(store, key, value) {
  await idbSet(store, key, await vaultWrap(value));
}

async function deriveVaultKey(pin, saltB64) {
  const salt = new Uint8Array(base64ToBuf(saltB64));
  const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
function getVaultMeta(accountId) {
  return idbGet('meta', accountId);
}
// Перешифровывает ratchet-состояния всех личных чатов, известных
// клиенту (список чатов приходит от сервера при входе и содержит все
// DM этого аккаунта), из одного представления вкладки в другое —
// используется и при включении, и при выключении PIN-блокировки.
async function migrateRatchets(unwrapWith, wrapWith) {
  for (const chat of chats) {
    if (chat.isGroup) continue;
    const raw = await idbGet('ratchets', chat.id);
    if (!raw) continue;
    const plain = await unwrapWith(raw);
    if (plain) await idbSet('ratchets', chat.id, await wrapWith(plain));
  }
}
async function enablePinLock(accountId, pin) {
  const oldKey = vaultKey;
  const unwrapWithOld = async (raw) => {
    const saved = vaultKey; vaultKey = oldKey;
    try { return await vaultUnwrap(raw); } finally { vaultKey = saved; }
  };
  const saltBuf = crypto.getRandomValues(new Uint8Array(16));
  const salt = bufToBase64(saltBuf.buffer);
  const newKey = await deriveVaultKey(pin, salt);

  const rawKeypair = await idbGet('keypairs', accountId);
  const keypairPlain = await unwrapWithOld(rawKeypair);

  vaultKey = newKey;
  if (keypairPlain) { myKeypair = keypairPlain; await idbSetSecure('keypairs', accountId, keypairPlain); }
  await migrateRatchets(unwrapWithOld, vaultWrap);
  await idbSet('meta', accountId, { pinEnabled: true, salt });
}
async function disablePinLock(accountId) {
  if (!vaultKey) { await idbSet('meta', accountId, { pinEnabled: false }); return; }
  const rawKeypair = await idbGet('keypairs', accountId);
  const keypairPlain = await vaultUnwrap(rawKeypair);
  await migrateRatchets(vaultUnwrap, async (v) => v);
  vaultKey = null;
  if (keypairPlain) { myKeypair = keypairPlain; await idbSet('keypairs', accountId, keypairPlain); }
  await idbSet('meta', accountId, { pinEnabled: false });
}
// Полный сброс локальных E2E-данных этого аккаунта на этом устройстве —
// используется, если PIN забыт и расшифровать хранилище больше нечем.
// Разговоры не теряются на сервере, но история "себе" и ratchet-цепочки
// обнуляются — при следующем входе identity-ключ сгенерируется заново.
async function resetLocalE2E(accountId) {
  const db = await idbOpen();
  await Promise.all(['keypairs', 'ratchets', 'meta'].map((store) => new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    if (store === 'ratchets') {
      tx.objectStore(store).clear();
    } else {
      tx.objectStore(store).delete(accountId);
    }
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  })));
}

// Экран блокировки: показывается вместо чата, пока не введён верный
// PIN. Возвращает управление (вызывает initE2E), только после успешной
// разблокировки.
function showLockScreen(accountId) {
  return new Promise((resolve) => {
    const screen = el('lock-screen');
    const input = el('lock-pin-input');
    const errBox = el('lock-error');
    screen.classList.remove('hidden');
    input.value = '';
    errBox.classList.add('hidden');
    input.focus();

    async function tryUnlock() {
      const pin = input.value;
      if (!pin) { input.focus(); return; }
      errBox.classList.add('hidden');
      el('lock-unlock-btn').disabled = true;
      try {
        const meta = await getVaultMeta(accountId);
        const key = await deriveVaultKey(pin, meta.salt);
        const savedVaultKey = vaultKey;
        vaultKey = key;
        const rawKeypair = await idbGet('keypairs', accountId);
        await vaultUnwrap(rawKeypair); // бросит исключение, если PIN неверный
        screen.classList.add('hidden');
        cleanup();
        await initE2E(accountId);
        resolve();
      } catch (err) {
        vaultKey = null;
        errBox.textContent = 'Неверный PIN. Попробуй ещё раз.';
        errBox.classList.remove('hidden');
        input.value = '';
        input.focus();
      } finally {
        el('lock-unlock-btn').disabled = false;
      }
    }
    function onKeydown(e) { if (e.key === 'Enter') tryUnlock(); }
    async function onReset() {
      const sure = confirm('Сбросить локальные ключи на этом устройстве? Старую переписку в этом браузере станет невозможно расшифровать (на сервере сообщения не удаляются).');
      if (!sure) return;
      await resetLocalE2E(accountId);
      vaultKey = null;
      screen.classList.add('hidden');
      cleanup();
      await initE2E(accountId);
      resolve();
    }
    function cleanup() {
      el('lock-unlock-btn').removeEventListener('click', tryUnlock);
      input.removeEventListener('keydown', onKeydown);
      el('lock-reset-btn').removeEventListener('click', onReset);
    }
    el('lock-unlock-btn').addEventListener('click', tryUnlock);
    input.addEventListener('keydown', onKeydown);
    el('lock-reset-btn').addEventListener('click', onReset);
  });
}

// Гарантирует, что у нас есть локальная identity-пара ключей для этого
// аккаунта (создаёт новую при первом входе с этого браузера) и отправляет
// публичный ключ на сервер, чтобы собеседники могли его получить.
async function initE2E(accountId) {
  if (!window.crypto || !window.crypto.subtle) {
    console.warn('Web Crypto API недоступен (нужен HTTPS или localhost) — E2E-шифрование отключено.');
    return;
  }
  try {
    const stored = await idbGetSecure('keypairs', accountId);
    if (stored && stored.privateKey && stored.publicKeyJwk) {
      myKeypair = stored;
    } else {
      const pair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
      );
      const publicKeyJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
      myKeypair = { privateKey: pair.privateKey, publicKeyJwk };
      await idbSetSecure('keypairs', accountId, myKeypair);
    }
    socket.emit('keys:register', { publicKeyJwk: myKeypair.publicKeyJwk });
  } catch (err) {
    console.error('Не удалось инициализировать E2E-ключи:', err);
  }
}

// ------------------------------------------------------------------
// Низкоуровневые KDF-примитивы ratchet'а
// ------------------------------------------------------------------
// Корневая цепочка: из старого root key + результата нового DH выводим
// новый root key и новый chain key (HKDF-SHA256, 64 байта на выходе).
async function kdfRootChain(rootKeyBuf, dhOutBuf) {
  const ikm = await crypto.subtle.importKey('raw', dhOutBuf, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: rootKeyBuf, info: new TextEncoder().encode('nova-ratchet-root') },
    ikm, 512
  );
  return { rootKey: bits.slice(0, 32), chainKey: bits.slice(32, 64) };
}
// Симметричная цепочка: HMAC(chainKey, 0x01) -> ключ сообщения,
// HMAC(chainKey, 0x02) -> следующий chain key. Продвижение необратимо —
// зная новый chain key, восстановить предыдущий (а значит и старые
// ключи сообщений) невозможно.
async function kdfChain(chainKeyBuf) {
  const hmacKey = await crypto.subtle.importKey('raw', chainKeyBuf, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const messageKey = await crypto.subtle.sign('HMAC', hmacKey, new Uint8Array([0x01]));
  const nextChainKey = await crypto.subtle.sign('HMAC', hmacKey, new Uint8Array([0x02]));
  return { messageKey, nextChainKey };
}

async function loadRatchetState(chatId) {
  return idbGetSecure('ratchets', chatId);
}
async function saveRatchetState(chatId, state) {
  await idbSetSecure('ratchets', chatId, state);
}

// Первичный общий секрет чата — статический ECDH между identity-ключами
// (упрощённая замена X3DH). Он используется только как стартовая точка:
// как только пойдёт первый обмен DH-ratchet-ключами, дальнейшая
// секретность уже не зависит от этих долгоживущих ключей напрямую.
async function initRatchet(chat) {
  const peerIdentity = await crypto.subtle.importKey(
    'jwk', chat.peerPublicKey, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const initialSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerIdentity }, myKeypair.privateKey, 256
  );
  const salted = await crypto.subtle.importKey('raw', initialSecret, 'HKDF', false, ['deriveBits']);
  const rootKey = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('nova-ratchet-init') },
    salted, 256
  );

  // Собственная эфемерная ratchet-пара — пригодится, если МЫ отправим
  // первое сообщение в этом чате (тогда собеседник вычислит тот же DH,
  // используя СВОЙ identity-ключ — см. ratchetReceive).
  const selfPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const dhSelfPub = await crypto.subtle.exportKey('jwk', selfPair.publicKey);

  const state = {
    rootKey,
    dhSelfPriv: selfPair.privateKey,
    dhSelfPub,
    dhRemotePub: null,
    sendChainKey: null,
    sendN: 0,
    recvChainKey: null,
    recvN: 0,
    needRatchetOnSend: false,
    skipped: {}, // `${remotePubJson}:${n}` -> base64(ключ сообщения)
  };
  await saveRatchetState(chat.id, state);
  return state;
}

async function getRatchetState(chat) {
  const existing = await loadRatchetState(chat.id);
  return existing || initRatchet(chat);
}

// DH-ratchet шаг перед отправкой: либо это самое первое сообщение в чате
// (тогда используем наш эфемерный ключ + identity-ключ собеседника —
// аналог "signed prekey" в X3DH), либо мы уже получали новый ratchet-ключ
// от собеседника с прошлого раза (тогда генерируем СВОЙ новый эфемерный
// ключ, чтобы продвинуть защиту вперёд).
async function ratchetSend(chat, state) {
  let partnerJwk = state.dhRemotePub;
  if (!partnerJwk) {
    partnerJwk = chat.peerPublicKey; // бутстрап от identity-ключа собеседника
  } else if (state.needRatchetOnSend) {
    const newPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    state.dhSelfPriv = newPair.privateKey;
    state.dhSelfPub = await crypto.subtle.exportKey('jwk', newPair.publicKey);
  }
  const partnerKey = await crypto.subtle.importKey('jwk', partnerJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const dhOut = await crypto.subtle.deriveBits({ name: 'ECDH', public: partnerKey }, state.dhSelfPriv, 256);
  const { rootKey, chainKey } = await kdfRootChain(state.rootKey, dhOut);
  state.rootKey = rootKey;
  state.sendChainKey = chainKey;
  state.sendN = 0;
  state.needRatchetOnSend = false;
}

// DH-ratchet шаг при получении сообщения с НОВЫМ ratchet-ключом
// собеседника. Для самого первого входящего сообщения в чате (когда мы
// ещё ничего не отправляли и не получали) используем наш identity-ключ —
// зеркально тому, как отправитель использовал наш identity-ключ как
// точку опоры.
async function ratchetReceive(chat, state, remoteDhPubJwk) {
  const isNew = JSON.stringify(remoteDhPubJwk) !== JSON.stringify(state.dhRemotePub);
  if (!isNew) return;

  const isBootstrap = !state.dhRemotePub && !state.sendChainKey && !state.recvChainKey;
  const privKey = isBootstrap ? myKeypair.privateKey : state.dhSelfPriv;

  const partnerKey = await crypto.subtle.importKey('jwk', remoteDhPubJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const dhOut = await crypto.subtle.deriveBits({ name: 'ECDH', public: partnerKey }, privKey, 256);
  const { rootKey, chainKey } = await kdfRootChain(state.rootKey, dhOut);
  state.rootKey = rootKey;
  state.recvChainKey = chainKey;
  state.recvN = 0;
  state.dhRemotePub = remoteDhPubJwk;
  state.needRatchetOnSend = true; // при следующей ОТПРАВКЕ тоже продвинем цепочку
  state.skipped = {}; // ключи из предыдущей цепочки уже не актуальны
}

async function advanceSendChain(state) {
  const { messageKey, nextChainKey } = await kdfChain(state.sendChainKey);
  const n = state.sendN;
  state.sendChainKey = nextChainKey;
  state.sendN += 1;
  return { messageKey, n };
}

// Продвигает цепочку получения до нужного номера сообщения. Если
// сообщения пришли не по порядку — недостающие ключи по пути
// складируются (с ограничением на размер запаса), чтобы отложенное
// сообщение всё равно можно было расшифровать, когда оно дойдёт.
async function consumeRecvChain(state, targetN) {
  const remoteKey = JSON.stringify(state.dhRemotePub);
  while (state.recvN < targetN) {
    const { messageKey, nextChainKey } = await kdfChain(state.recvChainKey);
    const skipKey = `${remoteKey}:${state.recvN}`;
    const skippedKeys = Object.keys(state.skipped);
    if (skippedKeys.length >= 50) delete state.skipped[skippedKeys[0]];
    state.skipped[skipKey] = bufToBase64(messageKey);
    state.recvChainKey = nextChainKey;
    state.recvN += 1;
  }
  if (state.recvN === targetN) {
    const { messageKey, nextChainKey } = await kdfChain(state.recvChainKey);
    state.recvChainKey = nextChainKey;
    state.recvN += 1;
    return messageKey;
  }
  const skipKey = `${remoteKey}:${targetN}`;
  const saved = state.skipped[skipKey];
  if (saved) {
    delete state.skipped[skipKey];
    return base64ToBuf(saved);
  }
  throw new Error('message-key-unavailable');
}

// Шифрует текст перед отправкой. Возвращает null, если публичный ключ
// собеседника ещё не известен (например, он ни разу не заходил в
// приложение и не успел зарегистрировать identity-ключ).
async function encryptForChat(chat, text) {
  if (!myKeypair || !chat || chat.isGroup || !chat.peerPublicKey) return null;
  const state = await getRatchetState(chat);
  if (!state.sendChainKey || state.needRatchetOnSend) {
    await ratchetSend(chat, state);
  }
  const { messageKey, n } = await advanceSendChain(state);
  await saveRatchetState(chat.id, state);

  const aesKey = await crypto.subtle.importKey('raw', messageKey, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(text));
  const header = { dhPub: state.dhSelfPub, n };

  const cacheKey = `${chat.id}:${JSON.stringify(header.dhPub)}:${n}`;
  sentPlaintextCache.set(cacheKey, text);
  if (sentPlaintextCache.size > 200) sentPlaintextCache.delete(sentPlaintextCache.keys().next().value);

  return { ciphertext: bufToBase64(ciphertext), iv: bufToBase64(iv.buffer), header };
}

// Расшифровывает входящее сообщение собеседника (не своё — свои
// показываются из sentPlaintextCache, см. renderMessage).
async function decryptMessage(chat, msg) {
  if (!myKeypair || !chat || !chat.peerPublicKey) throw new Error('no-key');
  const header = msg.header;
  if (!header || !header.dhPub) throw new Error('bad-header');

  const state = await getRatchetState(chat);
  await ratchetReceive(chat, state, header.dhPub);
  const messageKey = await consumeRecvChain(state, header.n);
  await saveRatchetState(chat.id, state);

  const aesKey = await crypto.subtle.importKey('raw', messageKey, { name: 'AES-GCM' }, false, ['decrypt']);
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(base64ToBuf(msg.iv)) },
    aesKey,
    base64ToBuf(msg.ciphertext)
  );
  return new TextDecoder().decode(plainBuf);
}

// Обёртка над decryptMessage с кэшем: ratchet-ключ одноразовый, поэтому
// повторный вызов decryptMessage для уже расшифрованного сообщения
// (например, при повторном открытии чата или обновлении страницы —
// сервер каждый раз шлёт chat:history заново) обязан провалиться. Тут
// сначала проверяем оперативный messageCache, затем постоянный стор
// 'plaintext' в IndexedDB, и только если нигде нет — реально дешифруем
// и запоминаем результат на будущее.
async function getDecryptedText(chat, msg) {
  const cached = messageCache.get(msg.id);
  if (cached && cached.plainText != null) return cached.plainText;
  try {
    const stored = await idbGetSecure('plaintext', msg.id);
    if (stored && typeof stored.text === 'string') return stored.text;
  } catch (err) {
    // hранилище заблокировано PIN'ом или записи ещё нет — расшифровываем заново ниже
  }
  // Если для этого же сообщения уже идёт расшифровка (два почти
  // одновременных renderMessage подряд) — ждём тот же промис, а не
  // тратим второй (уже несуществующий) ключ ratchet'а параллельно.
  const inFlight = decryptInFlight.get(msg.id);
  if (inFlight) return inFlight;

  const promise = (async () => {
    const text = await decryptMessage(chat, msg);
    try { await idbSetSecure('plaintext', msg.id, { text }); } catch (err) { /* не критично, просто не закэшировалось */ }
    return text;
  })();
  decryptInFlight.set(msg.id, promise);
  try {
    return await promise;
  } finally {
    decryptInFlight.delete(msg.id);
  }
}
const decryptInFlight = new Map(); // messageId -> Promise<string>, пока идёт расшифровка

// ------------------------------------------------------------------
// Verified safety numbers + индикатор смены ключа собеседника.
// ------------------------------------------------------------------
// "Код безопасности" — короткий отпечаток связки публичных identity-
// ключей обеих сторон (аналог Signal/WhatsApp security code). Его можно
// сверить вслух или лично: если цифры совпадают у обоих — между вами
// настоящий сквозной канал и никто не может тихо подменить ключ (MITM).
// Отпечаток считается от отсортированной пары ключей, поэтому у обеих
// сторон получается одна и та же строка независимо от того, кто "я".
async function computeSafetyNumber(myPubJwk, peerPubJwk) {
  const a = JSON.stringify(myPubJwk);
  const b = JSON.stringify(peerPubJwk);
  const [first, second] = a < b ? [a, b] : [b, a];
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(first + '|' + second));
  const bytes = new Uint8Array(digest);
  const groups = [];
  for (let i = 0; i < 6; i++) {
    const n = ((bytes[i * 2] << 8) | bytes[i * 2 + 1]) % 100000;
    groups.push(String(n).padStart(5, '0'));
  }
  return groups.join('   ');
}
async function fingerprintOf(pubJwk) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(pubJwk)));
  return bufToBase64(digest);
}

// TOFU (trust-on-first-use): самый первый ключ, который мы увидели у
// собеседника, закрепляем локально. Если сервер вдруг пришлёт другой
// ключ для того же человека — это не обязательно MITM, чаще собеседник
// просто зашёл с нового устройства/браузера или переустановил
// приложение, но разница принципиальная — тихо доверять новому ключу
// без предупреждения нельзя, иначе индикатор ничего не защищает.
async function checkPeerKey(peerId, peerPubJwk) {
  if (!peerId || !peerPubJwk) return { changed: false };
  const fp = await fingerprintOf(peerPubJwk);
  const trust = await idbGet('trust', peerId);
  if (!trust || !trust.fingerprint) {
    await idbSet('trust', peerId, { fingerprint: fp, verified: false });
    return { changed: false, verified: false };
  }
  if (trust.fingerprint !== fp) return { changed: true };
  return { changed: false, verified: !!trust.verified };
}
async function acceptPeerKey(peerId, peerPubJwk) {
  const fp = await fingerprintOf(peerPubJwk);
  await idbSet('trust', peerId, { fingerprint: fp, verified: false });
}
async function markPeerVerified(peerId, peerPubJwk, verified) {
  const fp = await fingerprintOf(peerPubJwk);
  await idbSet('trust', peerId, { fingerprint: fp, verified });
}
async function getTrust(peerId) {
  return idbGet('trust', peerId);
}

// Пересчитывает статус доверия к ключу собеседника для чата и, если
// это активный сейчас чат, обновляет предупреждающий баннер.
async function refreshKeyTrust(chat) {
  if (!chat || chat.isGroup || !chat.peerId || !chat.peerPublicKey) {
    if (chat) chat.keyChanged = false;
    return;
  }
  const result = await checkPeerKey(chat.peerId, chat.peerPublicKey);
  chat.keyChanged = !!result.changed;
  chat.keyVerified = !!result.verified;
  if (chat.id === activeChatId) updateKeyChangeBanner(chat);
}
function updateKeyChangeBanner(chat) {
  const banner = el('key-change-banner');
  if (!banner) return;
  banner.classList.toggle('hidden', !(chat && !chat.isGroup && chat.keyChanged));
}

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
// Если в cookie есть токен сессии — пробуем восстановить вход
// автоматически, не дожидаясь ввода пароля.
window.addEventListener('DOMContentLoaded', () => {
  checkInviteInUrl();
  const savedUsername = localStorage.getItem('nova-username');
  if (savedUsername) el('login-username').value = savedUsername;

  const token = getCookie('nova-session');
  if (token) {
    el('login-content').classList.add('hidden');
    el('session-loader').classList.remove('hidden');
    socket.emit('auth:session', { token });
  } else if (savedUsername) {
    el('login-password').focus();
  }
});

function endSessionRestore() {
  el('login-content').classList.remove('hidden');
  el('session-loader').classList.add('hidden');
}

socket.on('auth:session-invalid', () => {
  eraseCookie('nova-session');
  endSessionRestore();
});

socket.on('auth:ok', async ({ me: user, chats: chatList, session, customStickers }) => {
  me = user;
  chats = chatList;
  myCustomStickers = customStickers || [];
  if (user.username) localStorage.setItem('nova-username', user.username);
  if (session) {
    const remember = el('remember-me') ? el('remember-me').checked : true;
    if (remember) setCookie('nova-session', session, 30);
  }
  el('login-password').value = '';
  el('register-password').value = '';
  el('login-screen').classList.add('hidden');
  el('app').classList.remove('hidden');
  renderChatList();
  renderAccountInfo();
  socket.emit('contacts:list');
  await Promise.all(chats.map((c) => refreshKeyTrust(c)));

  const meta = await getVaultMeta(user.id);
  if (el('pinlock-toggle')) el('pinlock-toggle').checked = !!(meta && meta.pinEnabled);
  if (meta && meta.pinEnabled) {
    await showLockScreen(user.id);
  } else {
    await initE2E(user.id);
  }
  showInvitePrompt();
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

// Личный чат появился/обновился (например, кто-то открыл переписку со
// мной, или изменился онлайн-статус собеседника) — добавляем/обновляем
// запись в списке чатов без перезагрузки.
socket.on('chat:upsert', async (entry) => {
  const existing = chats.find((c) => c.id === entry.id);
  const chat = existing || entry;
  if (existing) {
    Object.assign(existing, entry);
  } else {
    chats.unshift(entry);
  }
  renderChatList(el('chat-search').value);
  if (entry.id === activeChatId && !entry.isGroup) {
    activePeer = { id: entry.peerId, name: entry.name, username: entry.peerUsername, verified: entry.peerVerified, online: entry.peerOnline, lastSeen: entry.peerLastSeen };
    setChatStatus(entry.peerOnline, entry.peerLastSeen);
    el('chat-safety-btn').classList.toggle('hidden', !entry.peerPublicKey);
  }
  if (entry.id === activeChatId) renderPinnedBar(chat);
  if (entry.id === groupInfoChatId) refreshGroupInfoPanel(chat);
  await refreshKeyTrust(chat);
});

// ------------------------------------------------------------------
// Список чатов (обычные + сворачиваемая секция "Архив")
// ------------------------------------------------------------------
function buildChatItem(c) {
  const item = document.createElement('div');
  item.className = 'chat-item' + (c.id === activeChatId ? ' active' : '');
  item.dataset.id = c.id;
  const draftText = loadDrafts()[c.id];
  const previewHtml = draftText
    ? `<span class="draft-label">Черновик:</span> ${escapeHtml(draftText.slice(0, 60))}`
    : escapeHtml(c.lastMessage || 'Нет сообщений');
  const unreadHtml = c.unread ? `<span class="unread-badge">${c.unread > 99 ? '99+' : c.unread}</span>` : '';
  item.innerHTML = `
    <div class="avatar" style="background:${avatarBg(c.name)}">${initials(c.name)}</div>
    <div class="chat-meta">
      <div class="chat-meta-top">
        <span class="chat-name">${escapeHtml(c.name)}</span>
        <span class="chat-time">${c.lastTime ? formatTime(c.lastTime) : ''}</span>
      </div>
      <div class="chat-preview">${previewHtml}</div>
    </div>
    ${unreadHtml}
    <button type="button" class="chat-item-more" title="Ещё" aria-label="Ещё">⋯</button>
  `;
  item.addEventListener('click', (e) => { if (!e.target.closest('.chat-item-more')) openChat(c.id); });
  item.querySelector('.chat-item-more').addEventListener('click', (e) => {
    e.stopPropagation();
    openChatItemMenu(e.currentTarget, c);
  });
  return item;
}

function openChatItemMenu(anchor, c) {
  closeFloatingMenus();
  const menu = document.createElement('div');
  menu.className = 'msg-menu';
  const addBtn = (label, fn) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = label;
    b.addEventListener('click', () => { fn(); closeFloatingMenus(); });
    menu.appendChild(b);
  };
  if (c.archived) {
    addBtn('📤 Разархивировать', () => socket.emit('chat:unarchive', { chatId: c.id }));
  } else {
    addBtn('🗄 В архив', () => socket.emit('chat:archive', { chatId: c.id }));
  }
  positionMenu(menu, anchor);
}

function renderChatList(filter = '') {
  const list = el('chat-list');
  list.innerHTML = '';
  const q = filter.trim().toLowerCase();
  const matching = chats.filter((c) => c.name.toLowerCase().includes(q));
  const regular = matching.filter((c) => !c.archived);
  const archived = matching.filter((c) => c.archived);

  regular.forEach((c) => list.appendChild(buildChatItem(c)));

  if (archived.length) {
    const archivedUnread = archived.reduce((sum, c) => sum + (c.unread || 0), 0);
    const header = document.createElement('div');
    header.className = 'archive-header' + (archiveCollapsed ? ' collapsed' : '');
    header.innerHTML = `
      <span class="archive-chevron">›</span>
      <span class="archive-title">Архив</span>
      <span class="archive-count">${archived.length}${archivedUnread ? ` · ${archivedUnread} непрочитано` : ''}</span>
    `;
    header.addEventListener('click', () => {
      archiveCollapsed = !archiveCollapsed;
      localStorage.setItem('nova-archive-collapsed', archiveCollapsed ? '1' : '0');
      renderChatList(el('chat-search').value);
    });
    list.appendChild(header);
    if (!archiveCollapsed) {
      const box = document.createElement('div');
      box.className = 'archive-list';
      archived.forEach((c) => box.appendChild(buildChatItem(c)));
      list.appendChild(box);
    }
  }

  updateTitleBadge();
}

// Непрочитанные из архива намеренно не входят в этот бейдж (заголовок
// вкладки браузера) — только "живые" чаты вне архива.
function updateTitleBadge() {
  const total = chats.filter((c) => !c.archived).reduce((sum, c) => sum + (c.unread || 0), 0);
  document.title = total > 0 ? `(${total > 99 ? '99+' : total}) Nova Messenger` : 'Nova Messenger';
}

el('chat-search').addEventListener('input', (e) => renderChatList(e.target.value));

el('new-chat').addEventListener('click', () => openGroupCreate());

// ------------------------------------------------------------------
// Создание группы
// ------------------------------------------------------------------
function openGroupCreate() {
  el('group-create-overlay').dataset.mode = '';
  el('group-create-name').closest('.settings-section').classList.remove('hidden');
  el('group-create-name').value = '';
  const box = el('group-create-people');
  box.innerHTML = '';
  el('group-create-empty').classList.toggle('hidden', myContacts.length > 0);
  myContacts.forEach((person) => {
    const row = document.createElement('div');
    row.className = 'person-row';
    row.innerHTML = `
      <input type="checkbox" class="person-check" value="${person.id}">
      <div class="avatar person-avatar" style="background:${avatarBg(person.name)}">${initials(person.name)}</div>
      <div class="person-meta"><div class="person-name">${escapeHtml(person.name)}${verifiedBadge(person.verified)}</div><div class="person-sub">@${escapeHtml(person.username || '')}</div></div>`;
    row.addEventListener('click', (e) => {
      if (e.target.tagName !== 'INPUT') row.querySelector('.person-check').checked = !row.querySelector('.person-check').checked;
    });
    box.appendChild(row);
  });
  el('group-create-overlay').classList.remove('hidden');
}

el('group-create-submit').addEventListener('click', () => {
  if (el('group-create-overlay').dataset.mode === 'add-to-group') return;
  const name = el('group-create-name').value.trim();
  if (!name) { el('group-create-name').focus(); return; }
  const memberIds = Array.from(document.querySelectorAll('#group-create-people .person-check:checked')).map((i) => i.value);
  socket.emit('chat:create', { name, memberIds });
  closeOverlay('group-create-overlay');
});

// ------------------------------------------------------------------
// Информация о группе: участники, роли, добавление/удаление
// ------------------------------------------------------------------
function openGroupInfo(chatId) {
  groupInfoChatId = chatId;
  const chat = chats.find((c) => c.id === chatId);
  if (!chat) return;
  el('group-info-title').textContent = chat.name;
  el('group-add-btn').classList.toggle('hidden', !chat.isAdmin);
  el('group-leave-btn').classList.toggle('hidden', !!chat.isOwner);
  refreshGroupInfoPanel(chat);
  socket.emit('group:members', { chatId });
  el('group-info-overlay').classList.remove('hidden');
}

// Обновляет аватар/описание/инвайт-блок панели без пересоздания всего
// оверлея — вызывается и при открытии, и при live-обновлении (chat:upsert).
function refreshGroupInfoPanel(chat) {
  if (!chat || chat.id !== groupInfoChatId) return;
  const avatarEl = el('group-info-avatar');
  avatarEl.textContent = chat.avatarEmoji || initials(chat.name);
  avatarEl.style.background = chat.avatarEmoji ? 'var(--hover)' : avatarBg(chat.name);
  el('group-avatar-edit-btn').classList.toggle('hidden', !chat.isAdmin);

  const descInput = el('group-description-input');
  if (document.activeElement !== descInput) descInput.value = chat.description || '';
  descInput.disabled = !chat.isAdmin;
  el('group-description-save').classList.toggle('hidden', !chat.isAdmin);

  const inviteSection = el('group-invite-section');
  inviteSection.classList.toggle('hidden', !chat.inviteCode);
  if (chat.inviteCode) {
    el('group-invite-link').value = `${location.origin}/?invite=${chat.inviteCode}`;
  }
  el('group-invite-regen').classList.toggle('hidden', !chat.isOwner);
}

// Небольшой фиксированный набор эмодзи для аватара группы — без загрузки
// картинок (это отдельная, более крупная задача).
const GROUP_AVATAR_EMOJIS = ['💬','👥','🚀','🎉','📚','🎮','🎵','⚽','🍕','✈️','💡','🔥','🌈','🐱','🌟','📌'];

el('group-avatar-edit-btn').addEventListener('click', () => {
  const picker = el('group-avatar-picker');
  if (!picker.classList.contains('hidden')) { picker.classList.add('hidden'); return; }
  picker.innerHTML = '';
  GROUP_AVATAR_EMOJIS.forEach((emoji) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = emoji;
    btn.addEventListener('click', () => {
      socket.emit('group:set-avatar', { chatId: groupInfoChatId, avatarEmoji: emoji });
      picker.classList.add('hidden');
    });
    picker.appendChild(btn);
  });
  picker.classList.remove('hidden');
});

el('group-description-save').addEventListener('click', () => {
  if (!groupInfoChatId) return;
  socket.emit('group:set-description', { chatId: groupInfoChatId, description: el('group-description-input').value.trim() });
});

el('group-invite-copy').addEventListener('click', async () => {
  const input = el('group-invite-link');
  input.select();
  try {
    await navigator.clipboard.writeText(input.value);
    showLoginErrorLike('Ссылка скопирована.');
  } catch {
    document.execCommand('copy');
  }
});

el('group-invite-regen').addEventListener('click', () => {
  if (!groupInfoChatId) return;
  if (!confirm('Старая ссылка перестанет работать. Обновить?')) return;
  socket.emit('group:regenerate-invite', { chatId: groupInfoChatId });
});

// ------------------------------------------------------------------
// Вступление в группу по ссылке-приглашению (?invite=код в URL) —
// вместо ручного добавления по контактам.
// ------------------------------------------------------------------
let pendingInviteCode = null;

function checkInviteInUrl() {
  const params = new URLSearchParams(location.search);
  const code = params.get('invite');
  if (!code) return;
  pendingInviteCode = code;
  history.replaceState({}, '', location.pathname); // убираем код из адресной строки
  if (me) showInvitePrompt();
}

function showInvitePrompt() {
  if (!pendingInviteCode) return;
  el('join-invite-text').textContent = 'Тебя пригласили в группу по ссылке. Присоединиться?';
  el('join-invite-overlay').classList.remove('hidden');
}

el('join-invite-confirm').addEventListener('click', () => {
  if (!pendingInviteCode) return;
  socket.emit('chat:join-by-invite', { code: pendingInviteCode });
  pendingInviteCode = null;
  closeOverlay('join-invite-overlay');
});

socket.on('chat:joined', (entry) => {
  const existing = chats.find((c) => c.id === entry.id);
  if (existing) Object.assign(existing, entry); else chats.unshift(entry);
  renderChatList(el('chat-search').value);
  openChat(entry.id);
});

socket.on('chat:join-error', ({ message }) => showLoginErrorLike(message || 'Не удалось присоединиться.'));

socket.on('group:members-list', ({ chatId, owner, members }) => {
  if (chatId !== groupInfoChatId) return;
  el('group-info-count').textContent = members.length;
  const box = el('group-info-members');
  box.innerHTML = '';
  const chat = chats.find((c) => c.id === chatId);
  const iAmOwner = chat && chat.isOwner;
  members.forEach((m) => {
    const row = document.createElement('div');
    row.className = 'person-row';
    const roleTag = m.isOwner ? '<span class="person-role-tag">владелец</span>' : m.isAdmin ? '<span class="person-role-tag">админ</span>' : '';
    row.innerHTML = `
      <div class="person-avatar-wrap">
        <div class="avatar person-avatar" style="background:${avatarBg(m.name)}">${initials(m.name)}</div>
        ${m.online ? '<span class="online-dot"></span>' : ''}
      </div>
      <div class="person-meta">
        <div class="person-name">${escapeHtml(m.name)}${verifiedBadge(m.verified)}${roleTag}</div>
        <div class="person-sub">@${escapeHtml(m.username || '')}${!m.online ? ' · ' + formatLastSeen(m.lastSeen) : ''}</div>
      </div>`;
    row.querySelector('.person-meta').addEventListener('click', () => openProfile(m.id));
    if (iAmOwner && !m.isOwner && me && m.id !== me.id) {
      const adminBtn = document.createElement('button');
      adminBtn.type = 'button';
      adminBtn.className = 'person-action';
      adminBtn.textContent = m.isAdmin ? 'Снять админа' : 'Сделать админом';
      adminBtn.addEventListener('click', () => socket.emit('group:set-admin', { chatId, accountId: m.id, isAdmin: !m.isAdmin }));
      row.appendChild(adminBtn);
    }
    if (chat && chat.isAdmin && !m.isOwner && me && m.id !== me.id) {
      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'person-action remove';
      removeBtn.textContent = 'Удалить';
      removeBtn.addEventListener('click', () => { if (confirm(`Удалить ${m.name} из группы?`)) socket.emit('group:remove-member', { chatId, accountId: m.id }); });
      row.appendChild(removeBtn);
    }
    box.appendChild(row);
  });
});

el('group-add-btn').addEventListener('click', () => {
  if (!groupInfoChatId) return;
  const chat = chats.find((c) => c.id === groupInfoChatId);
  el('group-create-overlay').dataset.mode = 'add-to-group';
  const box = el('group-create-people');
  box.innerHTML = '';
  el('group-create-name').closest('.settings-section').classList.add('hidden');
  el('group-create-empty').classList.toggle('hidden', myContacts.length > 0);
  myContacts.forEach((person) => {
    const row = document.createElement('div');
    row.className = 'person-row';
    row.innerHTML = `
      <input type="checkbox" class="person-check" value="${person.id}">
      <div class="avatar person-avatar" style="background:${avatarBg(person.name)}">${initials(person.name)}</div>
      <div class="person-meta"><div class="person-name">${escapeHtml(person.name)}</div></div>`;
    row.addEventListener('click', (e) => {
      if (e.target.tagName !== 'INPUT') row.querySelector('.person-check').checked = !row.querySelector('.person-check').checked;
    });
    box.appendChild(row);
  });
  el('group-create-overlay').classList.remove('hidden');
});

el('group-create-submit').addEventListener('click', () => {
  if (el('group-create-overlay').dataset.mode !== 'add-to-group') return;
  const memberIds = Array.from(document.querySelectorAll('#group-create-people .person-check:checked')).map((i) => i.value);
  if (memberIds.length) socket.emit('group:add-members', { chatId: groupInfoChatId, accountIds: memberIds });
  el('group-create-overlay').dataset.mode = '';
  el('group-create-name').closest('.settings-section').classList.remove('hidden');
  closeOverlay('group-create-overlay');
});

el('group-leave-btn').addEventListener('click', () => {
  if (!groupInfoChatId) return;
  if (!confirm('Покинуть группу?')) return;
  socket.emit('group:leave', { chatId: groupInfoChatId });
  closeOverlay('group-info-overlay');
});

socket.on('group:removed', ({ chatId }) => {
  chats = chats.filter((c) => c.id !== chatId);
  renderChatList(el('chat-search').value);
  if (activeChatId === chatId) {
    activeChatId = null;
    el('chat-view').classList.add('hidden');
    el('empty-state').classList.remove('hidden');
  }
  alert('Тебя удалили из группы.');
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

  el('chat-title').innerHTML = escapeHtml(chat.name) + (chat.isGroup ? '' : verifiedBadge(chat.peerVerified));
  el('chat-avatar').textContent = initials(chat.name);
  el('chat-avatar').style.background = avatarBg(chat.name);

  const headerInfo = el('chat-header-info');
  if (chat.isGroup) {
    activePeer = null;
    el('chat-status').textContent = `${chat.memberCount || chat.memberCount === 0 ? chat.memberCount : ''} участников`.trim();
    el('chat-status').classList.remove('online');
    headerInfo.classList.add('clickable');
    headerInfo.onclick = () => openGroupInfo(chat.id);
    el('chat-safety-btn').classList.add('hidden');
    el('key-change-banner').classList.add('hidden');
  } else {
    activePeer = { id: chat.peerId, name: chat.name, username: chat.peerUsername, verified: chat.peerVerified, online: chat.peerOnline, lastSeen: chat.peerLastSeen };
    setChatStatus(chat.peerOnline, chat.peerLastSeen);
    headerInfo.classList.add('clickable');
    headerInfo.onclick = () => openProfile(chat.peerId);
    el('chat-safety-btn').classList.toggle('hidden', !chat.peerPublicKey);
    refreshKeyTrust(chat);
    updateKeyChangeBanner(chat);
  }

  el('messages').innerHTML = '';
  cancelReply();
  cancelEdit();
  exitSelectionMode();
  pinnedCursor = 0;
  renderPinnedBar(chat);
  restoreDraft(chatId);

  socket.emit('chat:join', chatId);
  socket.emit('chat:read', { chatId });
  if (chat) { chat.unread = 0; }
  renderChatList(el('chat-search').value);
  closeAllPickers();
}

function setChatStatus(online, lastSeen) {
  el('chat-status').textContent = online ? 'в сети' : formatLastSeen(lastSeen);
  el('chat-status').classList.toggle('online', !!online);
}

function formatLastSeen(ts) {
  if (!ts) return 'не в сети';
  const diffMin = Math.floor((Date.now() - ts) / 60000);
  if (diffMin < 1) return 'был(а) в сети только что';
  if (diffMin < 60) return `был(а) в сети ${diffMin} мин назад`;
  const diffH = Math.floor(diffMin / 60);
  if (diffH < 24) return `был(а) в сети ${diffH} ч назад`;
  const d = new Date(ts);
  return `был(а) в сети недавно (${d.toLocaleDateString()})`;
}

// ------------------------------------------------------------------
// Закреплённые сообщения (несколько на чат, как в Telegram) — бар
// показывает текущее, клик по бару (не по крестику) листает к
// следующему закреплённому по кругу.
// ------------------------------------------------------------------
let pinnedCursor = 0;

function renderPinnedBar(chat) {
  const bar = el('pinned-bar');
  const list = (chat && chat.pinnedMessages) || [];
  if (!chat || !list.length) { bar.classList.add('hidden'); return; }
  bar.classList.remove('hidden');
  if (pinnedCursor >= list.length) pinnedCursor = 0;
  const current = list[list.length - 1 - pinnedCursor]; // самое свежее — первым
  const countLabel = list.length > 1 ? ` (${pinnedCursor + 1}/${list.length})` : '';
  el('pinned-text').textContent = `${current.senderName ? current.senderName + ': ' : ''}${current.preview || 'Сообщение'}${countLabel}`;
  bar.onclick = (e) => {
    if (e.target.closest('#pinned-unpin')) return;
    const row = document.querySelector(`.msg-row[data-id="${current.id}"]`);
    if (row) row.scrollIntoView({ behavior: 'smooth', block: 'center' });
    if (list.length > 1) {
      pinnedCursor = (pinnedCursor + 1) % list.length;
      renderPinnedBar(chat);
    }
  };
  const canUnpin = chat.isGroup ? chat.isAdmin : true;
  el('pinned-unpin').classList.toggle('hidden', !canUnpin);
  el('pinned-unpin').title = list.length > 1 ? 'Открепить это сообщение' : 'Открепить';
  el('pinned-unpin').onclick = () => socket.emit('chat:unpin', { chatId: chat.id, messageId: current.id });
}

socket.on('chat:pin-changed', ({ chatId, pinnedMessages }) => {
  const chat = chats.find((c) => c.id === chatId);
  if (chat) chat.pinnedMessages = pinnedMessages || [];
  pinnedCursor = 0;
  if (chatId === activeChatId) renderPinnedBar(chat);
});

el('back-btn').addEventListener('click', () => {
  el('app').classList.remove('chat-open');
});

socket.on('chat:history', async ({ chatId, messages }) => {
  if (chatId !== activeChatId) return;
  el('messages').innerHTML = '';
  for (const msg of messages) {
    await renderMessage(msg);
  }
  scrollToBottom();
});

// ------------------------------------------------------------------
// Сообщения
// ------------------------------------------------------------------
async function renderMessage(msg, existingRow) {
  if (msg.type === 'system') {
    const row = existingRow || document.createElement('div');
    row.className = 'msg-row system';
    row.dataset.id = msg.id;
    row.innerHTML = `<div class="system-text">${escapeHtml(msg.text)}</div>`;
    if (!existingRow) el('messages').appendChild(row);
    return;
  }

  const out = me && msg.senderId === me.id;
  const row = existingRow || document.createElement('div');
  row.className = 'msg-row ' + (out ? 'out' : 'in');
  row.dataset.id = msg.id;

  if (msg.deleted) {
    row.innerHTML = `<div class="msg-col"><div class="bubble deleted-bubble">Сообщение удалено</div></div>`;
    if (!existingRow) el('messages').appendChild(row);
    return;
  }

  let inner = '';
  if (!out) inner += `<span class="sender-name">${escapeHtml(msg.senderName)}${verifiedBadge(msg.senderVerified)}</span>`;

  let bubbleClass = 'bubble';
  let body = '';
  let lockPrefix = '';
  let plainForCache = null;
  if (msg.encrypted) {
    lockPrefix = '<span class="e2e-lock" title="Сквозное шифрование">🔒</span> ';
    let plain = null;
    if (out) {
      // Своё сообщение: цепочка ОТПРАВКИ для расшифровки не годится
      // (это разные ключи), поэтому берём текст из локального кэша,
      // сохранённого в момент отправки.
      const cacheKey = msg.header ? `${msg.chatId}:${JSON.stringify(msg.header.dhPub)}:${msg.header.n}` : null;
      const cached = cacheKey ? sentPlaintextCache.get(cacheKey) : undefined;
      if (cached !== undefined) { plain = cached; }
    } else {
      const chat = chats.find((c) => c.id === msg.chatId);
      try { plain = await getDecryptedText(chat, msg); } catch (err) { plain = null; }
    }

    plainForCache = plain;
    if (msg.type === 'sticker') {
      bubbleClass += ' sticker-bubble';
      body = plain !== null ? escapeHtml(plain) : '<span class="e2e-error">🔒 Стикер</span>';
    } else if (msg.type === 'custom-sticker') {
      bubbleClass += ' sticker-bubble custom-sticker-bubble';
      body = plain !== null ? `<img src="${escapeHtml(plain)}" alt="стикер">` : '<span class="e2e-error">🔒 Стикер</span>';
    } else if (msg.type === 'gif') {
      bubbleClass += ' gif-bubble';
      body = plain !== null ? `<img src="${escapeHtml(plain)}" alt="gif">` : '<span class="e2e-error">🔒 GIF</span>';
    } else if (msg.type === 'voice') {
      bubbleClass += ' voice-bubble';
      body = plain !== null ? `<audio controls src="${escapeHtml(plain)}"></audio>` : '<span class="e2e-error">🔒 Голосовое</span>';
    } else if (plain !== null) {
      body = linkify(escapeHtml(plain));
    } else {
      body = out
        ? '<span class="e2e-error">Отправлено (текст доступен только сразу после отправки)</span>'
        : '<span class="e2e-error">Не удалось расшифровать (другое устройство или ключ ещё не готов)</span>';
    }
  } else if (msg.type === 'sticker') {
    bubbleClass += ' sticker-bubble';
    body = msg.stickerEmoji;
    plainForCache = msg.stickerEmoji;
  } else if (msg.type === 'custom-sticker') {
    bubbleClass += ' sticker-bubble custom-sticker-bubble';
    body = `<img src="${escapeHtml(msg.stickerUrl)}" alt="стикер">`;
    plainForCache = msg.stickerUrl;
  } else if (msg.type === 'gif') {
    bubbleClass += ' gif-bubble';
    body = `<img src="${escapeHtml(msg.gifUrl)}" alt="gif">`;
    plainForCache = msg.gifUrl;
  } else if (msg.type === 'voice') {
    bubbleClass += ' voice-bubble';
    body = `<audio controls src="${escapeHtml(msg.voiceData || '')}"></audio>`;
    plainForCache = msg.voiceData;
  } else if (msg.type === 'file') {
    bubbleClass += ' file-bubble';
    body = renderFileBubble(msg);
    plainForCache = msg.fileName;
  } else {
    body = linkify(escapeHtml(msg.text));
    plainForCache = msg.text;
  }

  const ticks = out
    ? `<span class="read-tick">${msg.read ? '✓✓' : '✓'}</span>`
    : '';
  const editedTag = msg.edited ? '<span class="msg-edited-tag">изменено</span>' : '';

  let replyHtml = '';
  if (msg.replyTo) {
    const rqText = msg.replyTo.preview ? escapeHtml(msg.replyTo.preview) : '🔒 Сообщение';
    replyHtml = `<div class="msg-reply-quote" data-reply-jump="${msg.replyTo.id}"><span class="rq-name">${escapeHtml(msg.replyTo.senderName)}</span><span class="rq-text">${rqText}</span></div>`;
  }
  const forwardedHtml = msg.forwardedFrom ? `<div class="msg-forwarded">↪ Переслано от ${escapeHtml(msg.forwardedFrom.senderName)}</div>` : '';

  const menuBtn = `<button type="button" class="msg-act-more" title="Действия">⋯</button>`;
  const replyBtn = `<button type="button" class="msg-act-reply" title="Ответить">↩</button>`;
  const reactBtn = `<button type="button" class="msg-act-react" title="Реакция">🙂</button>`;
  const selectCheck = `<label class="msg-select-check"><input type="checkbox" ${selectedMessageIds.has(msg.id) ? 'checked' : ''}></label>`;

  row.classList.toggle('selected', selectedMessageIds.has(msg.id));
  row.innerHTML = `
    ${selectCheck}
    <div class="msg-col">
      <div class="msg-hover-actions">${reactBtn}${replyBtn}${menuBtn}</div>
      ${replyHtml}
      <div class="${bubbleClass}">${inner}${forwardedHtml}${lockPrefix}${body}<span class="bubble-meta">${editedTag} ${formatTime(msg.time)} ${ticks}</span></div>
      <div class="reactions-row"></div>
    </div>`;
  if (!existingRow) el('messages').appendChild(row);

  messageCache.set(msg.id, { msg, plainText: plainForCache });
  renderReactions(row, msg);
  wireMessageActions(row, msg);
  wireSelection(row, msg);

  if (!out) socket.emit('message:read', { chatId: msg.chatId, messageId: msg.id });
}

// ------------------------------------------------------------------
// Мультивыбор сообщений: чекбокс в углу пузыря (виден в режиме выбора
// или при наведении/долгом тапе), панель снизу с "Удалить"/"Переслать".
// ------------------------------------------------------------------
function wireSelection(row, msg) {
  const checkbox = row.querySelector('.msg-select-check input');
  checkbox?.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleMessageSelection(msg.id);
  });
  row.addEventListener('click', (e) => {
    if (!selectionMode) return;
    if (e.target.closest('.msg-hover-actions') || e.target.closest('.msg-menu')) return;
    toggleMessageSelection(msg.id);
  });

  // Долгий тап (мобильный) на пузыре включает режим выбора и сразу
  // выбирает это сообщение.
  const bubble = row.querySelector('.bubble');
  bubble?.addEventListener('touchstart', () => {
    clearTimeout(longPressTimer);
    longPressTimer = setTimeout(() => {
      if (!selectionMode) enterSelectionMode();
      toggleMessageSelection(msg.id);
    }, 450);
  }, { passive: true });
  ['touchend', 'touchmove', 'touchcancel'].forEach((ev) => {
    bubble?.addEventListener(ev, () => clearTimeout(longPressTimer), { passive: true });
  });
}

function toggleMessageSelection(messageId) {
  if (selectedMessageIds.has(messageId)) selectedMessageIds.delete(messageId);
  else selectedMessageIds.add(messageId);
  if (selectedMessageIds.size && !selectionMode) enterSelectionMode();
  if (!selectedMessageIds.size && selectionMode) { exitSelectionMode(); return; }
  const row = document.querySelector(`.msg-row[data-id="${messageId}"]`);
  if (row) {
    row.classList.toggle('selected', selectedMessageIds.has(messageId));
    const cb = row.querySelector('.msg-select-check input');
    if (cb) cb.checked = selectedMessageIds.has(messageId);
  }
  updateSelectionBar();
}

function enterSelectionMode() {
  selectionMode = true;
  el('messages').classList.add('selection-mode');
  el('selection-bar').classList.remove('hidden');
  closeFloatingMenus();
}

function exitSelectionMode() {
  selectionMode = false;
  selectedMessageIds.clear();
  el('messages').classList.remove('selection-mode');
  el('selection-bar').classList.add('hidden');
  document.querySelectorAll('.msg-row.selected').forEach((r) => {
    r.classList.remove('selected');
    const cb = r.querySelector('.msg-select-check input');
    if (cb) cb.checked = false;
  });
}

function updateSelectionBar() {
  el('selection-count').textContent = `Выбрано: ${selectedMessageIds.size}`;
}

el('selection-cancel').addEventListener('click', exitSelectionMode);

el('selection-delete').addEventListener('click', () => {
  if (!selectedMessageIds.size || !activeChatId) return;
  if (!confirm(`Удалить выбранные сообщения (${selectedMessageIds.size})?`)) return;
  socket.emit('message:delete-many', { chatId: activeChatId, messageIds: Array.from(selectedMessageIds) });
  exitSelectionMode();
});

el('selection-forward').addEventListener('click', () => {
  if (!selectedMessageIds.size) return;
  const ids = Array.from(selectedMessageIds);
  const msgs = ids.map((id) => messageCache.get(id)?.msg).filter(Boolean)
    .sort((a, b) => a.time - b.time);
  if (!msgs.length) return;
  openForwardPicker(msgs);
});

// ------------------------------------------------------------------
// Реакции
// ------------------------------------------------------------------
function renderReactions(row, msg) {
  const box = row.querySelector('.reactions-row');
  if (!box) return;
  box.innerHTML = '';
  const reactions = msg.reactions || {};
  Object.entries(reactions).forEach(([emoji, ids]) => {
    if (!ids.length) return;
    const pill = document.createElement('button');
    pill.type = 'button';
    pill.className = 'reaction-pill' + (me && ids.includes(me.id) ? ' mine' : '');
    pill.innerHTML = `${emoji} <span>${ids.length}</span>`;
    pill.addEventListener('click', () => socket.emit('reaction:toggle', { chatId: msg.chatId, messageId: msg.id, emoji }));
    box.appendChild(pill);
  });
}

socket.on('message:reaction', ({ chatId, messageId, reactions }) => {
  const cached = messageCache.get(messageId);
  if (cached) cached.msg.reactions = reactions;
  if (chatId !== activeChatId) return;
  const row = document.querySelector(`.msg-row[data-id="${messageId}"]`);
  if (row && cached) renderReactions(row, cached.msg);
});

const QUICK_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🙏'];

// ------------------------------------------------------------------
// Действия над сообщением: реакция, ответ, меню (изменить/удалить/
// переслать/закрепить)
// ------------------------------------------------------------------
function wireMessageActions(row, msg) {
  const out = me && msg.senderId === me.id;
  row.querySelector('.msg-act-react')?.addEventListener('click', (e) => openReactionPicker(e.currentTarget, msg));
  row.querySelector('.msg-act-reply')?.addEventListener('click', () => startReply(msg));
  row.querySelector('.msg-act-more')?.addEventListener('click', (e) => openMsgMenu(e.currentTarget, msg, out));
  row.querySelector('[data-reply-jump]')?.addEventListener('click', (e) => {
    const id = e.currentTarget.dataset.replyJump;
    const target = document.querySelector(`.msg-row[data-id="${id}"]`);
    if (target) target.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });
}

function closeFloatingMenus() {
  document.querySelectorAll('.msg-menu').forEach((n) => n.remove());
}
document.addEventListener('click', (e) => {
  if (!e.target.closest('.msg-menu') && !e.target.closest('.msg-act-more') && !e.target.closest('.msg-act-react')) closeFloatingMenus();
});

function positionMenu(menu, anchor) {
  const r = anchor.getBoundingClientRect();
  document.body.appendChild(menu);
  const top = Math.min(r.bottom + 4, window.innerHeight - menu.offsetHeight - 8);
  const left = Math.min(r.left, window.innerWidth - menu.offsetWidth - 8);
  menu.style.top = `${Math.max(8, top)}px`;
  menu.style.left = `${Math.max(8, left)}px`;
}

function openReactionPicker(anchor, msg) {
  closeFloatingMenus();
  const menu = document.createElement('div');
  menu.className = 'msg-menu';
  const row = document.createElement('div');
  row.className = 'msg-menu-emojis';
  QUICK_EMOJIS.forEach((emoji) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = emoji;
    b.addEventListener('click', () => { socket.emit('reaction:toggle', { chatId: msg.chatId, messageId: msg.id, emoji }); closeFloatingMenus(); });
    row.appendChild(b);
  });
  menu.appendChild(row);
  positionMenu(menu, anchor);
}

function openMsgMenu(anchor, msg, isOwn) {
  closeFloatingMenus();
  const chat = chats.find((c) => c.id === msg.chatId);
  const menu = document.createElement('div');
  menu.className = 'msg-menu';

  const addBtn = (label, fn, danger) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = label;
    if (danger) b.classList.add('danger');
    b.addEventListener('click', () => { fn(); closeFloatingMenus(); });
    menu.appendChild(b);
  };

  addBtn('↩ Ответить', () => startReply(msg));
  addBtn('↪ Переслать', () => openForwardPicker(msg));
  addBtn('☑️ Выбрать', () => { enterSelectionMode(); toggleMessageSelection(msg.id); });
  if (isOwn && !msg.encrypted || (isOwn && msg.encrypted && msg.type !== 'sticker' && msg.type !== 'custom-sticker' && msg.type !== 'gif' && msg.type !== 'voice')) {
    addBtn('✏️ Изменить', () => startEdit(msg));
  }
  const canPin = chat && (chat.isGroup ? chat.isAdmin : true);
  if (canPin) addBtn('📌 Закрепить', () => socket.emit('chat:pin', { chatId: msg.chatId, messageId: msg.id }));
  const canDelete = isOwn || (chat && chat.isGroup && chat.isAdmin);
  if (canDelete) addBtn('🗑 Удалить', () => { if (confirm('Удалить сообщение?')) socket.emit('message:delete', { chatId: msg.chatId, messageId: msg.id }); }, true);

  positionMenu(menu, anchor);
}

socket.on('message:new', async (msg) => {
  const chat = chats.find((c) => c.id === msg.chatId);
  if (chat) {
    if (msg.type === 'system') {
      chat.lastMessage = msg.text;
    } else if (msg.encrypted) {
      chat.lastMessage = '🔒 Сообщение';
    } else {
      chat.lastMessage = summarizePlain(msg);
    }
    chat.lastTime = msg.time;
    if (msg.type !== 'system') chats = [chat, ...chats.filter((c) => c.id !== chat.id)];
  }
  if (msg.chatId === activeChatId) {
    await renderMessage(msg);
    scrollToBottom();
    // Чат открыт — новое сообщение сразу считается прочитанным, курсор
    // на сервере двигаем, чтобы бейдж не появился, если переключиться и
    // вернуться назад (или зайти с другого устройства).
    if (msg.type !== 'system' && me && msg.senderId !== me.id) socket.emit('chat:read', { chatId: msg.chatId });
  } else {
    playSound();
    // Чат не открыт — считаем сообщение непрочитанным локально сразу
    // (не дожидаясь ответного chat:upsert с сервера, чтобы бейдж не
    // мигал с задержкой). Сервер всё равно пришлёт актуальное значение
    // при следующем chat:upsert — здесь просто оптимистичное обновление.
    if (chat && msg.type !== 'system' && (!me || msg.senderId !== me.id)) chat.unread = (chat.unread || 0) + 1;
  }
  renderChatList(el('chat-search').value);
});

socket.on('user:online', (account) => updatePresence(account.id, true, account.lastSeen));
socket.on('user:offline', (account) => updatePresence(account.id, false, account.lastSeen));

function updatePresence(accountId, online, lastSeen) {
  if (activePeer && activePeer.id === accountId) {
    activePeer.online = online;
    if (lastSeen) activePeer.lastSeen = lastSeen;
    setChatStatus(online, activePeer.lastSeen);
  }
  chats.forEach((c) => { if (!c.isGroup && c.peerId === accountId) { c.peerOnline = online; if (lastSeen) c.peerLastSeen = lastSeen; } });
  const contact = myContacts.find((c) => c.id === accountId);
  if (contact) {
    contact.online = online;
    renderContactsList();
  }
  if (el('profile-overlay') && !el('profile-overlay').classList.contains('hidden') && currentProfileId === accountId) {
    el('profile-status').textContent = online ? 'в сети' : formatLastSeen(lastSeen);
    el('profile-status').classList.toggle('online', online);
  }
}

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
// Ответ (reply) и редактирование — общее состояние композера
// ------------------------------------------------------------------
function startReply(msg) {
  const cached = messageCache.get(msg.id);
  const preview = msg.encrypted ? (cached && cached.plainText ? cached.plainText : '') : summarizePlain(msg);
  replyingTo = { id: msg.id, senderName: msg.senderName, preview: (preview || '').slice(0, 120) };
  cancelEdit(true);
  el('reply-preview').classList.remove('hidden');
  el('reply-preview-name').textContent = msg.senderName;
  el('reply-preview-text').textContent = preview || (msg.encrypted ? '🔒 Сообщение' : '');
  el('message-input').focus();
}
function cancelReply() {
  replyingTo = null;
  el('reply-preview').classList.add('hidden');
}
el('reply-preview-cancel').addEventListener('click', cancelReply);

function summarizePlain(msg) {
  if (msg.type === 'sticker') return '⭐ Стикер';
  if (msg.type === 'custom-sticker') return '⭐ Стикер';
  if (msg.type === 'gif') return '🎬 GIF';
  if (msg.type === 'voice') return '🎤 Голосовое сообщение';
  if (msg.type === 'file') return `📎 ${msg.fileName || 'Файл'}`;
  return msg.text || '';
}

function startEdit(msg) {
  const cached = messageCache.get(msg.id);
  const text = msg.encrypted ? (cached ? cached.plainText : '') : msg.text;
  if (typeof text !== 'string') return;
  editingMessageId = msg.id;
  cancelReply();
  const input = el('message-input');
  input.value = text;
  input.focus();
  el('send-btn').classList.add('editing');
  showLoginErrorLike('Редактирование сообщения — нажми ✓, чтобы сохранить.');
}
function cancelEdit(silent) {
  editingMessageId = null;
  el('send-btn').classList.remove('editing');
  if (!silent) el('message-input').value = '';
}

// ------------------------------------------------------------------
// Пересылка
// ------------------------------------------------------------------
// msgOrMsgs — одно сообщение (обычная пересылка из меню) или массив
// сообщений (мультивыбор) — во втором случае все летят в один выбранный
// целевой чат, по порядку времени отправки.
function openForwardPicker(msgOrMsgs) {
  const msgs = Array.isArray(msgOrMsgs) ? msgOrMsgs : [msgOrMsgs];
  forwardSourceId = msgs.length === 1 ? msgs[0].id : null;
  const box = el('forward-chat-list');
  box.innerHTML = '';
  chats.forEach((c) => {
    const row = document.createElement('div');
    row.className = 'person-row';
    row.innerHTML = `
      <div class="avatar person-avatar" style="background:${avatarBg(c.name)}">${initials(c.name)}</div>
      <div class="person-meta"><div class="person-name">${escapeHtml(c.name)}</div></div>
      <button type="button" class="person-action">Переслать</button>`;
    row.querySelector('.person-action').addEventListener('click', async () => {
      for (const msg of msgs) await forwardMessageTo(msg, c);
      closeOverlay('forward-overlay');
    });
    box.appendChild(row);
  });
  el('forward-overlay').classList.remove('hidden');
}

async function forwardMessageTo(msg, targetChat) {
  const forwardedFrom = { senderName: msg.senderName };
  if (msg.type === 'file') {
    // Файлы не шифруются и не идут через summarizePlain (там только имя,
    // не сами данные) — пересылаем как есть.
    socket.emit('message:send', {
      chatId: targetChat.id, type: 'file', forwardedFrom,
      fileData: msg.fileData, fileName: msg.fileName, fileSize: msg.fileSize, fileMime: msg.fileMime,
    });
    return;
  }
  const cached = messageCache.get(msg.id);
  const plain = msg.encrypted ? (cached ? cached.plainText : null) : summarizePlain(msg);
  if (plain === null || plain === undefined) return;
  const FORWARDABLE_TYPES = ['sticker', 'custom-sticker', 'gif', 'voice'];
  const type = FORWARDABLE_TYPES.includes(msg.type) ? msg.type : 'text';

  if (!targetChat.isGroup) {
    const enc = await encryptForChat(targetChat, plain);
    if (!enc) { showLoginErrorLike('Ключ шифрования этого собеседника ещё не готов.'); return; }
    socket.emit('message:send', { chatId: targetChat.id, type, encrypted: true, ciphertext: enc.ciphertext, iv: enc.iv, header: enc.header, forwardedFrom });
  } else if (type === 'sticker') {
    socket.emit('message:send', { chatId: targetChat.id, type, stickerEmoji: plain, forwardedFrom });
  } else if (type === 'custom-sticker') {
    socket.emit('message:send', { chatId: targetChat.id, type, stickerUrl: plain, forwardedFrom });
  } else if (type === 'gif') {
    socket.emit('message:send', { chatId: targetChat.id, type, gifUrl: plain, forwardedFrom });
  } else if (type === 'voice') {
    socket.emit('message:send', { chatId: targetChat.id, type, voiceData: plain, voiceDuration: msg.voiceDuration || 0, forwardedFrom });
  } else {
    socket.emit('message:send', { chatId: targetChat.id, type: 'text', text: plain, forwardedFrom });
  }
}

// ------------------------------------------------------------------
// Изменения/удаления сообщений с сервера
// ------------------------------------------------------------------
socket.on('message:edited', async (msg) => {
  messageCache.delete(msg.id);
  if (msg.chatId !== activeChatId) return;
  const row = document.querySelector(`.msg-row[data-id="${msg.id}"]`);
  if (row) await renderMessage(msg, row); // перерисовываем содержимое той же строки, не меняя позицию
});

socket.on('message:deleted', ({ chatId, messageId }) => {
  messageCache.delete(messageId);
  selectedMessageIds.delete(messageId);
  if (chatId !== activeChatId) return;
  const row = document.querySelector(`.msg-row[data-id="${messageId}"]`);
  if (row) row.innerHTML = `<div class="msg-col"><div class="bubble deleted-bubble">Сообщение удалено</div></div>`;
});

socket.on('message:deleted-many', ({ chatId, messageIds }) => {
  messageIds.forEach((messageId) => {
    messageCache.delete(messageId);
    selectedMessageIds.delete(messageId);
    if (chatId !== activeChatId) return;
    const row = document.querySelector(`.msg-row[data-id="${messageId}"]`);
    if (row) row.innerHTML = `<div class="msg-col"><div class="bubble deleted-bubble">Сообщение удалено</div></div>`;
  });
  if (chatId === activeChatId) updateSelectionBar();
});

// ------------------------------------------------------------------
// Файлы/документы (не только картинки/GIF) — как голосовые, кодируем
// в base64 и шлём через сокет. Лимит 15MB на файл (соответствует
// серверной проверке в message:send).
// ------------------------------------------------------------------
const MAX_FILE_SIZE = 15 * 1024 * 1024;

function formatFileSize(bytes) {
  if (!bytes) return '';
  if (bytes < 1024) return `${bytes} Б`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} КБ`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} МБ`;
}

function fileIconFor(mime) {
  if ((mime || '').startsWith('image/')) return '🖼️';
  if ((mime || '').startsWith('video/')) return '🎞️';
  if ((mime || '').startsWith('audio/')) return '🎵';
  if ((mime || '').includes('pdf')) return '📕';
  if ((mime || '').includes('zip') || (mime || '').includes('rar')) return '🗜️';
  return '📄';
}

function renderFileBubble(msg) {
  const icon = fileIconFor(msg.fileMime);
  const size = formatFileSize(msg.fileSize);
  return `
    <a class="file-attachment" href="${escapeHtml(msg.fileData || '#')}" download="${escapeHtml(msg.fileName || 'файл')}">
      <span class="file-attachment-icon">${icon}</span>
      <span class="file-attachment-meta">
        <span class="file-attachment-name">${escapeHtml(msg.fileName || 'Файл')}</span>
        <span class="file-attachment-size">${size}</span>
      </span>
    </a>`;
}

el('file-btn').addEventListener('click', () => el('file-input').click());

el('file-input').addEventListener('change', async (e) => {
  const files = Array.from(e.target.files || []);
  e.target.value = '';
  if (!activeChatId || !files.length) return;
  for (const file of files) {
    if (file.size > MAX_FILE_SIZE) {
      showLoginErrorLike(`«${file.name}» больше 15 МБ — не отправлено.`);
      continue;
    }
    const dataUrl = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
    // Файлы пока идут без E2E-шифрования (как и GIF/стикеры в группах) —
    // это отдельная задача на будущее, см. README.
    socket.emit('message:send', {
      chatId: activeChatId,
      type: 'file',
      fileData: dataUrl,
      fileName: file.name,
      fileSize: file.size,
      fileMime: file.type || 'application/octet-stream',
    });
  }
});

// ------------------------------------------------------------------
// Отправка
// ------------------------------------------------------------------
el('composer').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = el('message-input');
  const text = input.value.trim();
  if (!text || !activeChatId) return;
  const chat = chats.find((c) => c.id === activeChatId);

  if (editingMessageId) {
    const cached = messageCache.get(editingMessageId);
    const isEncrypted = cached && cached.msg.encrypted;
    if (isEncrypted) {
      const enc = await encryptForChat(chat, text);
      if (!enc) { showLoginErrorLike('Ключ шифрования собеседника ещё не готов.'); return; }
      socket.emit('message:edit', { chatId: activeChatId, messageId: editingMessageId, ciphertext: enc.ciphertext, iv: enc.iv, header: enc.header });
    } else {
      socket.emit('message:edit', { chatId: activeChatId, messageId: editingMessageId, text });
    }
    cancelEdit();
    input.value = '';
    return;
  }

  const replyTo = replyingTo ? { id: replyingTo.id, senderName: replyingTo.senderName } : undefined;

  if (chat && !chat.isGroup) {
    // Личный чат — шифруем на клиенте, сервер получит только шифротекст.
    const enc = await encryptForChat(chat, text);
    if (!enc) {
      showLoginErrorLike('Ключ шифрования собеседника ещё не готов. Попробуй чуть позже (когда он откроет приложение).');
      return;
    }
    socket.emit('message:send', { chatId: activeChatId, type: 'text', encrypted: true, ciphertext: enc.ciphertext, iv: enc.iv, header: enc.header, replyTo });
  } else {
    // Групповой чат — без E2E (см. комментарий в разделе шифрования выше).
    socket.emit('message:send', { chatId: activeChatId, type: 'text', text, replyTo });
  }

  clearDraft(activeChatId);
  input.value = '';
  cancelReply();
  socket.emit('typing', { chatId: activeChatId, isTyping: false });
});

// ------------------------------------------------------------------
// Черновики сообщений — введённый, но не отправленный текст сохраняется
// при переключении чата и восстанавливается при возврате (per-аккаунт,
// в localStorage, чтобы не потерялось и после перезагрузки страницы).
// ------------------------------------------------------------------
function draftsKey() {
  return `nova-drafts:${me ? me.id : 'anon'}`;
}
function loadDrafts() {
  try { return JSON.parse(localStorage.getItem(draftsKey()) || '{}'); } catch { return {}; }
}
function saveDraft(chatId, text) {
  if (!chatId) return;
  const drafts = loadDrafts();
  if (text) drafts[chatId] = text; else delete drafts[chatId];
  localStorage.setItem(draftsKey(), JSON.stringify(drafts));
  updateDraftPreview(chatId, text || '');
}
function clearDraft(chatId) { saveDraft(chatId, ''); }
function restoreDraft(chatId) {
  const drafts = loadDrafts();
  el('message-input').value = drafts[chatId] || '';
}
// Показать "Черновик: ..." вместо превью последнего сообщения в списке
// чатов — как в Telegram — не трогая сам объект chat.lastMessage.
function updateDraftPreview(chatId, text) {
  const row = document.querySelector(`.chat-item[data-id="${chatId}"] .chat-preview`);
  if (!row) return;
  const chat = chats.find((c) => c.id === chatId);
  if (text) {
    row.innerHTML = `<span class="draft-label">Черновик:</span> ${escapeHtml(text.slice(0, 60))}`;
  } else if (chat) {
    row.textContent = chat.lastMessage || '';
  }
}

// Небольшое ненавязчивое уведомление в композере (чтобы не городить
// отдельный alert для ошибки шифрования).
function showLoginErrorLike(message) {
  const indicator = el('typing-indicator');
  indicator.textContent = message;
  indicator.classList.remove('hidden');
  setTimeout(() => indicator.classList.add('hidden'), 3000);
}

el('message-input').addEventListener('input', (e) => {
  if (!activeChatId) return;
  if (!editingMessageId) saveDraft(activeChatId, e.target.value.trim());
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

// Стикеры и GIF в личных чатах шифруются точно так же, как текст —
// это просто короткая строка (эмодзи или URL картинки), которую можно
// прогнать через тот же ratchet, что и обычные сообщения.
async function sendSticker(emoji) {
  if (!activeChatId) return;
  const chat = chats.find((c) => c.id === activeChatId);
  if (chat && !chat.isGroup) {
    const enc = await encryptForChat(chat, emoji);
    if (!enc) { showLoginErrorLike('Ключ шифрования собеседника ещё не готов.'); return; }
    socket.emit('message:send', { chatId: activeChatId, type: 'sticker', encrypted: true, ciphertext: enc.ciphertext, iv: enc.iv, header: enc.header });
  } else {
    socket.emit('message:send', { chatId: activeChatId, type: 'sticker', stickerEmoji: emoji });
  }
  closeAllPickers();
}
async function sendGif(url) {
  if (!activeChatId) return;
  const chat = chats.find((c) => c.id === activeChatId);
  if (chat && !chat.isGroup) {
    const enc = await encryptForChat(chat, url);
    if (!enc) { showLoginErrorLike('Ключ шифрования собеседника ещё не готов.'); return; }
    socket.emit('message:send', { chatId: activeChatId, type: 'gif', encrypted: true, ciphertext: enc.ciphertext, iv: enc.iv, header: enc.header });
  } else {
    socket.emit('message:send', { chatId: activeChatId, type: 'gif', gifUrl: url });
  }
  closeAllPickers();
}
async function sendCustomSticker(url) {
  if (!activeChatId) return;
  const chat = chats.find((c) => c.id === activeChatId);
  if (chat && !chat.isGroup) {
    const enc = await encryptForChat(chat, url);
    if (!enc) { showLoginErrorLike('Ключ шифрования собеседника ещё не готов.'); return; }
    socket.emit('message:send', { chatId: activeChatId, type: 'custom-sticker', encrypted: true, ciphertext: enc.ciphertext, iv: enc.iv, header: enc.header });
  } else {
    socket.emit('message:send', { chatId: activeChatId, type: 'custom-sticker', stickerUrl: url });
  }
  closeAllPickers();
}

// ------------------------------------------------------------------
// Голосовые сообщения (MediaRecorder). В личных чатах шифруются так же,
// как стикеры/GIF — просто короткая строка (data URL) через общий
// ratchet-пайплайн.
// ------------------------------------------------------------------
el('voice-btn').addEventListener('click', startVoiceRecording);
el('voice-cancel-btn').addEventListener('click', () => stopVoiceRecording(false));
el('voice-send-btn').addEventListener('click', () => stopVoiceRecording(true));

async function startVoiceRecording() {
  if (!activeChatId) return;
  if (!navigator.mediaDevices || !window.MediaRecorder) {
    showLoginErrorLike('Запись голоса не поддерживается этим браузером.');
    return;
  }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    recordedChunks = [];
    mediaRecorder = new MediaRecorder(stream);
    mediaRecorder.ondataavailable = (e) => { if (e.data.size) recordedChunks.push(e.data); };
    mediaRecorder.start();
    recordSeconds = 0;
    el('voice-timer').textContent = '0:00';
    el('voice-recording').classList.remove('hidden');
    el('composer').classList.add('hidden');
    recordTimerHandle = setInterval(() => {
      recordSeconds += 1;
      const m = Math.floor(recordSeconds / 60);
      const s = String(recordSeconds % 60).padStart(2, '0');
      el('voice-timer').textContent = `${m}:${s}`;
    }, 1000);
    mediaRecorder._stream = stream;
  } catch (err) {
    showLoginErrorLike('Нет доступа к микрофону.');
  }
}

function stopVoiceRecording(send) {
  if (!mediaRecorder) return;
  clearInterval(recordTimerHandle);
  el('voice-recording').classList.add('hidden');
  el('composer').classList.remove('hidden');
  const duration = recordSeconds;
  const recorder = mediaRecorder;
  mediaRecorder = null;
  recorder.addEventListener('stop', async () => {
    recorder._stream.getTracks().forEach((t) => t.stop());
    if (!send || !recordedChunks.length) return;
    const blob = new Blob(recordedChunks, { type: recorder.mimeType || 'audio/webm' });
    const dataUrl = await new Promise((resolve) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(reader.result);
      reader.readAsDataURL(blob);
    });
    await sendVoice(dataUrl, duration);
  }, { once: true });
  recorder.stop();
}

async function sendVoice(dataUrl, duration) {
  if (!activeChatId) return;
  const chat = chats.find((c) => c.id === activeChatId);
  if (chat && !chat.isGroup) {
    const enc = await encryptForChat(chat, dataUrl);
    if (!enc) { showLoginErrorLike('Ключ шифрования собеседника ещё не готов.'); return; }
    socket.emit('message:send', { chatId: activeChatId, type: 'voice', encrypted: true, ciphertext: enc.ciphertext, iv: enc.iv, header: enc.header, voiceDuration: duration });
  } else {
    socket.emit('message:send', { chatId: activeChatId, type: 'voice', voiceData: dataUrl, voiceDuration: duration });
  }
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
  document.querySelectorAll('.overlay').forEach((overlay) => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) overlay.classList.add('hidden');
    });
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

  // PIN-блокировка локального хранилища.
  el('pinlock-toggle').addEventListener('change', (e) => {
    if (!me) return;
    if (e.target.checked) {
      el('pin-setup-1').value = '';
      el('pin-setup-2').value = '';
      el('pin-setup-error').classList.add('hidden');
      el('pin-setup-overlay').classList.remove('hidden');
      el('pin-setup-1').focus();
    } else {
      const sure = confirm('Выключить PIN-блокировку? Ключи на этом устройстве снова будут храниться без шифрования.');
      if (!sure) { e.target.checked = true; return; }
      disablePinLock(me.id);
    }
  });
  el('pin-setup-cancel').addEventListener('click', () => {
    el('pin-setup-overlay').classList.add('hidden');
    el('pinlock-toggle').checked = false;
  });
  el('pin-setup-confirm').addEventListener('click', async () => {
    const pin1 = el('pin-setup-1').value;
    const pin2 = el('pin-setup-2').value;
    const errBox = el('pin-setup-error');
    if (pin1.length < 4) { errBox.textContent = 'PIN должен быть не короче 4 символов.'; errBox.classList.remove('hidden'); return; }
    if (pin1 !== pin2) { errBox.textContent = 'PIN-коды не совпадают.'; errBox.classList.remove('hidden'); return; }
    errBox.classList.add('hidden');
    await enablePinLock(me.id, pin1);
    el('pin-setup-overlay').classList.add('hidden');
  });

  // Код безопасности (сверка ключей) + баннер смены ключа.
  el('chat-safety-btn').addEventListener('click', openSafetyOverlay);
  el('safety-verified-toggle').addEventListener('change', async (e) => {
    const chat = chats.find((c) => c.id === activeChatId);
    if (!chat || !chat.peerPublicKey) return;
    await markPeerVerified(chat.peerId, chat.peerPublicKey, e.target.checked);
    chat.keyVerified = e.target.checked;
  });
  el('key-change-check').addEventListener('click', openSafetyOverlay);
  el('key-change-accept').addEventListener('click', async () => {
    const chat = chats.find((c) => c.id === activeChatId);
    if (!chat || !chat.peerPublicKey) return;
    await acceptPeerKey(chat.peerId, chat.peerPublicKey);
    chat.keyChanged = false;
    updateKeyChangeBanner(chat);
  });

  loadSettings();
}

// Открывает экран сверки кода безопасности для активного личного чата.
async function openSafetyOverlay() {
  const chat = chats.find((c) => c.id === activeChatId);
  if (!chat || chat.isGroup || !chat.peerPublicKey || !myKeypair) return;
  const code = await computeSafetyNumber(myKeypair.publicKeyJwk, chat.peerPublicKey);
  el('safety-code').textContent = code;
  el('safety-peer-name').textContent = chat.name;
  el('safety-key-changed').classList.toggle('hidden', !chat.keyChanged);
  const trust = await getTrust(chat.peerId);
  el('safety-verified-toggle').checked = !!(trust && trust.verified);
  el('safety-overlay').classList.remove('hidden');
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

  const token = getCookie('nova-session');
  if (token) socket.emit('auth:logout', { token });
  eraseCookie('nova-session');
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

  function renderMine() {
    grid.innerHTML = '';
    grid.classList.add('sticker-grid-mine');

    const uploadTile = document.createElement('button');
    uploadTile.type = 'button';
    uploadTile.className = 'sticker-upload-tile';
    uploadTile.title = 'Загрузить свой стикер';
    uploadTile.textContent = '+';
    uploadTile.addEventListener('click', () => el('sticker-upload-input').click());
    grid.appendChild(uploadTile);

    myCustomStickers.forEach((s) => {
      const tile = document.createElement('div');
      tile.className = 'sticker-mine-tile';
      tile.innerHTML = `
        <button type="button" class="sticker-mine-img"><img src="${escapeHtml(s.url)}" alt="стикер"></button>
        <button type="button" class="sticker-mine-remove" title="Удалить">✕</button>`;
      tile.querySelector('.sticker-mine-img').addEventListener('click', () => sendCustomSticker(s.url));
      tile.querySelector('.sticker-mine-remove').addEventListener('click', (e) => {
        e.stopPropagation();
        if (confirm('Удалить этот стикер?')) socket.emit('sticker:delete', { stickerId: s.id });
      });
      grid.appendChild(tile);
    });

    if (!myCustomStickers.length) {
      const hint = document.createElement('div');
      hint.className = 'sticker-hint';
      hint.textContent = 'Загрузи PNG, WebP или GIF (до 2 МБ) — появится здесь.';
      grid.appendChild(hint);
    }
  }

  const mineTab = document.createElement('button');
  mineTab.type = 'button';
  mineTab.textContent = '📁 Мои';
  mineTab.addEventListener('click', () => {
    tabsBox.querySelectorAll('button').forEach((x) => x.classList.remove('active'));
    mineTab.classList.add('active');
    grid.classList.remove('sticker-grid-mine');
    renderMine();
  });
  tabsBox.appendChild(mineTab);
  window.__renderMineStickers = renderMine; // для обновления после sticker:list, если вкладка открыта

  packs.forEach((pack, i) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = pack;
    b.className = i === 0 ? 'active' : '';
    b.addEventListener('click', () => {
      tabsBox.querySelectorAll('button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      grid.classList.remove('sticker-grid-mine');
      renderPack(pack);
    });
    tabsBox.appendChild(b);
  });
  renderPack(packs[0]);

  el('sticker-btn').addEventListener('click', () => togglePicker('sticker-picker'));

  el('sticker-upload-input').addEventListener('change', async (e) => {
    const file = e.target.files && e.target.files[0];
    e.target.value = '';
    if (!file) return;
    if (!['image/png', 'image/webp', 'image/gif'].includes(file.type)) {
      showLoginErrorLike('Поддерживаются только PNG, WebP и GIF.');
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      showLoginErrorLike('Стикер слишком большой (максимум 2 МБ).');
      return;
    }
    const dataUrl = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
    socket.emit('sticker:upload', { dataUrl });
  });
}

socket.on('sticker:list', ({ stickers }) => {
  myCustomStickers = stickers || [];
  if (window.__renderMineStickers && el('sticker-tabs').querySelector('button.active')?.textContent === '📁 Мои') {
    window.__renderMineStickers();
  }
});

socket.on('sticker:error', ({ message }) => showLoginErrorLike(message || 'Не удалось загрузить стикер.'));

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

// ==================================================================
// КОНТАКТЫ
// ==================================================================
let contactsSearchDebounce = null;
let currentProfileId = null;

function initContacts() {
  el('open-contacts').addEventListener('click', () => {
    el('contacts-overlay').classList.remove('hidden');
    el('contacts-search').value = '';
    el('contacts-search-results').innerHTML = '';
    socket.emit('contacts:list');
  });

  el('contacts-search').addEventListener('input', (e) => {
    clearTimeout(contactsSearchDebounce);
    const q = e.target.value.trim();
    if (!q) { el('contacts-search-results').innerHTML = ''; return; }
    contactsSearchDebounce = setTimeout(() => socket.emit('contacts:search', q), 300);
  });
}

socket.on('contacts:list', (list) => {
  myContacts = list || [];
  renderContactsList();
});

socket.on('contacts:search-results', (results) => {
  const box = el('contacts-search-results');
  box.innerHTML = '';
  if (!results.length) {
    box.innerHTML = '<div class="people-hint">Никого не найдено.</div>';
    return;
  }
  results.forEach((person) => box.appendChild(personRow(person, 'search')));
});

function renderContactsList() {
  const box = el('contacts-list');
  box.innerHTML = '';
  el('contacts-empty').classList.toggle('hidden', myContacts.length > 0);
  myContacts.forEach((person) => box.appendChild(personRow(person, 'contact')));
}

function personRow(person, mode) {
  const row = document.createElement('div');
  row.className = 'person-row';
  row.innerHTML = `
    <div class="person-avatar-wrap">
      <div class="avatar person-avatar" style="background:${avatarBg(person.name)}">${initials(person.name)}</div>
      ${person.online ? '<span class="online-dot"></span>' : ''}
    </div>
    <div class="person-meta">
      <div class="person-name">${escapeHtml(person.name)}${verifiedBadge(person.verified)}</div>
      <div class="person-sub">@${escapeHtml(person.username || '')}</div>
    </div>
    <button type="button" class="person-action">${mode === 'contact' ? 'Написать' : 'Открыть'}</button>
  `;
  const openIt = () => { closeOverlay('contacts-overlay'); socket.emit('contacts:open-chat', { accountId: person.id }); };
  row.querySelector('.person-meta').addEventListener('click', () => openProfile(person.id));
  row.querySelector('.person-avatar-wrap').addEventListener('click', () => openProfile(person.id));
  row.querySelector('.person-action').addEventListener('click', openIt);
  return row;
}

// Ответ на "написать/открыть" — сразу переключаемся на этот чат.
socket.on('contacts:chat-opened', (entry) => {
  if (!chats.find((c) => c.id === entry.id)) chats.unshift(entry);
  openChat(entry.id);
});

function closeOverlay(id) {
  el(id).classList.add('hidden');
}

// ==================================================================
// ПРОФИЛЬ
// ==================================================================
function openProfile(accountId) {
  if (!accountId) return;
  currentProfileId = accountId;
  socket.emit('profile:get', { accountId });
}

socket.on('profile:data', (profile) => {
  currentProfileId = profile.id;
  el('profile-avatar').textContent = initials(profile.name);
  el('profile-avatar').style.background = avatarBg(profile.name);
  el('profile-name').innerHTML = escapeHtml(profile.name) + verifiedBadge(profile.verified);
  el('profile-username').textContent = '@' + (profile.username || '');
  el('profile-status').textContent = profile.online ? 'в сети' : formatLastSeen(profile.lastSeen);
  el('profile-status').classList.toggle('online', !!profile.online);
  el('profile-novaid').textContent = profile.novaId || '';

  const msgBtn = el('profile-message-btn');
  const contactBtn = el('profile-contact-btn');
  if (profile.isSelf) {
    msgBtn.classList.add('hidden');
    contactBtn.classList.add('hidden');
  } else {
    msgBtn.classList.remove('hidden');
    msgBtn.onclick = () => {
      closeOverlay('profile-overlay');
      socket.emit('contacts:open-chat', { accountId: profile.id });
    };
    contactBtn.classList.remove('hidden');
    contactBtn.textContent = profile.isContact ? 'Удалить из контактов' : 'Добавить в контакты';
    contactBtn.classList.toggle('remove', profile.isContact);
    contactBtn.onclick = () => {
      if (profile.isContact) {
        socket.emit('contacts:remove', { accountId: profile.id });
      } else {
        socket.emit('contacts:add', { accountId: profile.id });
      }
      socket.emit('profile:get', { accountId: profile.id });
    };
  }

  el('profile-overlay').classList.remove('hidden');
});

socket.on('profile:error', ({ message }) => {
  alert(message || 'Не удалось открыть профиль.');
});

// ------------------------------------------------------------------
// Инициализация
// ------------------------------------------------------------------
initSettings();
initContacts();
initEmojiPicker();
initStickerPicker();
initGifPicker();