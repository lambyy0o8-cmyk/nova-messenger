const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(path.join(__dirname, '..', 'public')));

// ------------------------------------------------------------------
// In-memory state (без базы данных, как и в исходном проекте)
// ------------------------------------------------------------------

const users = new Map(); // socket.id -> { id, name, color, online }
const chats = new Map(); // chatId -> { id, name, isGroup, members:Set, messages:[] }

const DEFAULT_CHAT_ID = 'general';
chats.set(DEFAULT_CHAT_ID, {
  id: DEFAULT_CHAT_ID,
  name: 'Общий чат',
  isGroup: true,
  members: new Set(),
  messages: [],
});

function avatarColor(name) {
  const colors = ['#e17076', '#7bc862', '#65aadd', '#a695e7', '#ee7aae', '#6ec9cb', '#faa774', '#4f95d1'];
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash);
  return colors[Math.abs(hash) % colors.length];
}

function publicChatList(socketId) {
  const list = [];
  for (const chat of chats.values()) {
    if (!chat.isGroup && !chat.members.has(socketId)) continue;
    const last = chat.messages[chat.messages.length - 1];
    list.push({
      id: chat.id,
      name: chat.name,
      isGroup: chat.isGroup,
      lastMessage: last ? summarize(last) : '',
      lastTime: last ? last.time : null,
      unread: 0,
    });
  }
  return list;
}

function summarize(msg) {
  if (msg.type === 'text') return msg.text;
  if (msg.type === 'sticker') return '\u2b50 Стикер';
  if (msg.type === 'gif') return '\ud83c\udfac GIF';
  return '';
}

io.on('connection', (socket) => {
  socket.on('auth', (name) => {
    const cleanName = (name || 'Гость').toString().slice(0, 24);
    const user = { id: socket.id, name: cleanName, color: avatarColor(cleanName), online: true };
    users.set(socket.id, user);

    chats.get(DEFAULT_CHAT_ID).members.add(socket.id);
    socket.join(DEFAULT_CHAT_ID);

    socket.emit('auth:ok', { me: user, chats: publicChatList(socket.id) });
    socket.emit('chat:history', {
      chatId: DEFAULT_CHAT_ID,
      messages: chats.get(DEFAULT_CHAT_ID).messages,
    });

    socket.to(DEFAULT_CHAT_ID).emit('user:online', user);
  });

  socket.on('chat:join', (chatId) => {
    const chat = chats.get(chatId);
    if (!chat) return;
    socket.join(chatId);
    socket.emit('chat:history', { chatId, messages: chat.messages });
  });

  socket.on('message:send', (payload) => {
    const user = users.get(socket.id);
    if (!user) return;
    const chat = chats.get(payload.chatId) || chats.get(DEFAULT_CHAT_ID);

    const message = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      chatId: chat.id,
      senderId: socket.id,
      senderName: user.name,
      type: payload.type || 'text', // text | sticker | gif
      text: payload.text || '',
      stickerEmoji: payload.stickerEmoji || null,
      gifUrl: payload.gifUrl || null,
      time: Date.now(),
      read: false,
    };

    chat.messages.push(message);
    if (chat.messages.length > 500) chat.messages.shift();

    io.to(chat.id).emit('message:new', message);
  });

  socket.on('typing', ({ chatId, isTyping }) => {
    const user = users.get(socket.id);
    if (!user) return;
    socket.to(chatId).emit('typing', { name: user.name, isTyping });
  });

  socket.on('message:read', ({ chatId, messageId }) => {
    const chat = chats.get(chatId);
    if (!chat) return;
    const msg = chat.messages.find((m) => m.id === messageId);
    if (msg) {
      msg.read = true;
      io.to(chatId).emit('message:read', { chatId, messageId });
    }
  });

  socket.on('chat:create', (name) => {
    const id = `chat-${Date.now()}`;
    const chat = { id, name: (name || 'Новый чат').slice(0, 40), isGroup: true, members: new Set([socket.id]), messages: [] };
    chats.set(id, chat);
    socket.join(id);
    socket.emit('chat:created', { id, name: chat.name });
  });

  socket.on('disconnect', () => {
    const user = users.get(socket.id);
    users.delete(socket.id);
    if (user) {
      io.to(DEFAULT_CHAT_ID).emit('user:offline', user);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Nova Messenger запущен: http://localhost:${PORT}`);
});
