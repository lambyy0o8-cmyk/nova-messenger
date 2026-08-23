// ------------------------------------------------------------------
// AI-бот для Nova Messenger на базе Ollama.
//
// Использует встроенный в Nova Bot API (см. server/index.js, раздел
// "Bot API" — /bot<TOKEN>/getUpdates, /sendMessage, /getMe), который
// работает по принципу Telegram Bot API: long polling за апдейтами и
// HTTP-отправка ответов. Никаких изменений в самом Nova не требуется —
// это отдельный процесс, работающий как внешний клиент.
//
// КАК ПОЛУЧИТЬ ТОКЕН:
//   1. Зайди в свой аккаунт в Nova → Настройки → "Создать бота".
//   2. Укажи имя и юзернейм — сервер покажет токен ОДИН РАЗ, сразу
//      сохрани его (сервер хранит только хеш, второй раз не покажет).
//   3. У бота появится личный чат-консоль с тобой (можно писать
//      боту, добавлять его в группы — как обычного пользователя).
//
// ЗАПУСК:
//   NOVA_URL=https://your-nova-instance.example \
//   NOVA_BOT_TOKEN=nova_bot_xxxxxxxx \
//   node ollama-bot.js
// ------------------------------------------------------------------

const NOVA_URL = (process.env.NOVA_URL || 'http://localhost:3000').replace(/\/+$/, '');
const BOT_TOKEN = process.env.NOVA_BOT_TOKEN || '';
const OLLAMA_URL = process.env.OLLAMA_URL || 'http://127.0.0.1:11434/api/chat';
const MODEL_NAME = process.env.OLLAMA_MODEL || 'qwen2.5:latest';
const SYSTEM_PROMPT = process.env.SYSTEM_PROMPT || 'Ты дружелюбный ассистент. Отвечай только на русском языке, чётко и по делу.';

// Сколько последних сообщений (без учёта системного) хранить на чат,
// чтобы контекст не рос бесконечно — как MAX_HISTORY в bot.py.
const MAX_HISTORY = 30;
const LONG_POLL_TIMEOUT_S = 25; // сервер сам ограничивает максимум 50с

if (!BOT_TOKEN) {
  console.error('Не задан NOVA_BOT_TOKEN. Получи токен через Настройки → "Создать бота" в Nova.');
  process.exit(1);
}

const API = `${NOVA_URL}/bot${BOT_TOKEN}`;

// chatId -> [{ role, content }, ...]  (без системного сообщения — оно
// подставляется отдельно при каждом запросе к Ollama, см. askOllama)
const histories = new Map();

function getHistory(chatId) {
  if (!histories.has(chatId)) histories.set(chatId, []);
  return histories.get(chatId);
}

function trimHistory(history) {
  if (history.length > MAX_HISTORY) history.splice(0, history.length - MAX_HISTORY);
}

async function apiGet(path) {
  const res = await fetch(`${API}${path}`);
  return res.json();
}

async function apiPost(path, body) {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
}

async function askOllama(chatId, userText) {
  const history = getHistory(chatId);
  history.push({ role: 'user', content: userText });
  trimHistory(history);

  const messages = [{ role: 'system', content: SYSTEM_PROMPT }, ...history];

  const res = await fetch(OLLAMA_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: MODEL_NAME, messages, stream: false }),
  });
  if (!res.ok) throw new Error(`Ollama вернул ${res.status}`);
  const data = await res.json();
  const reply = data.message?.content?.trim() || '…';

  history.push({ role: 'assistant', content: reply });
  trimHistory(history);
  return reply;
}

async function handleUpdate(update) {
  const msg = update.message;
  if (!msg || !msg.text) return; // стикеры/фото/зашифрованные (text:null) — игнорируем
  if (msg.from?.is_bot) return; // не отвечаем другим ботам

  console.log(`[in] chat=${msg.chat_id} from=${msg.from?.username || '?'}: ${msg.text}`);

  try {
    const reply = await askOllama(msg.chat_id, msg.text);
    const result = await apiPost('/sendMessage', { chat_id: msg.chat_id, text: reply });
    if (!result.ok) console.error(`[out] Ошибка отправки в чат ${msg.chat_id}:`, result.error);
    else console.log(`[out] chat=${msg.chat_id}: ${reply}`);
  } catch (err) {
    console.error('[ollama] Ошибка запроса к модели:', err.message);
    await apiPost('/sendMessage', {
      chat_id: msg.chat_id,
      text: '⚠️ Не получилось получить ответ от модели. Проверь, что Ollama запущена (ollama serve).',
    }).catch(() => {});
  }
}

async function pollLoop() {
  let offset = 0;
  console.log(`Бот запущен. Nova: ${NOVA_URL}, модель: ${MODEL_NAME}`);

  const me = await apiGet('/getMe');
  if (me.ok) console.log(`Это @${me.result.username} (${me.result.name})`);
  else console.error('Не удалось авторизоваться по токену — проверь NOVA_BOT_TOKEN.');

  while (true) {
    try {
      const res = await apiGet(`/getUpdates?offset=${offset}&timeout=${LONG_POLL_TIMEOUT_S}`);
      if (!res.ok) {
        console.error('getUpdates вернул ошибку:', res.error);
        await new Promise((r) => setTimeout(r, 3000));
        continue;
      }
      for (const update of res.result) {
        offset = Math.max(offset, update.update_id);
        await handleUpdate(update);
      }
    } catch (err) {
      console.error('Сбой long-polling, повтор через 3с:', err.message);
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
}

pollLoop();