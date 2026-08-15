const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(path.join(__dirname, '..', 'public')));

// ===== "База данных" в памяти (для старта; потом заменить на PostgreSQL/Mongo) =====

const guilds = {
  'general-guild': {
    id: 'general-guild',
    name: 'Мой первый сервер',
    channels: {
      'general': { id: 'general', name: 'general', messages: [] },
      'random': { id: 'random', name: 'random', messages: [] }
    }
  }
};

// Онлайн пользователи: socket.id -> { username, currentGuild, currentChannel }
const onlineUsers = {};

function channelPreview(channel) {
  const last = channel.messages[channel.messages.length - 1];
  return {
    id: channel.id,
    name: channel.name,
    lastText: last ? last.text : null,
    lastAuthor: last ? last.author : null,
    lastTimestamp: last ? last.timestamp : null
  };
}

function onlineCountForGuild() {
  // упрощённо: один общий гилд, поэтому просто общее число подключённых
  return Object.keys(onlineUsers).length;
}

// ===== Socket.IO обработка событий =====

io.on('connection', (socket) => {
  socket.on('join_app', (username) => {
    onlineUsers[socket.id] = { username, bio: '', currentGuild: null, currentChannel: null };
    socket.emit('guild_list', Object.values(guilds).map(g => ({ id: g.id, name: g.name })));
    io.emit('online_users', Object.values(onlineUsers).map(u => u.username));
  });

  socket.on('update_profile', ({ username, bio }) => {
    const user = onlineUsers[socket.id];
    if (!user || !username?.trim()) return;
    user.username = username.trim().slice(0, 20);
    user.bio = (bio || '').trim().slice(0, 70);
    socket.emit('profile_updated', { username: user.username, bio: user.bio });
  });

  socket.on('join_guild', (guildId) => {
    const guild = guilds[guildId];
    if (!guild) return;
    onlineUsers[socket.id].currentGuild = guildId;
    socket.emit('channel_list', {
      guildId,
      channels: Object.values(guild.channels).map(channelPreview),
      onlineCount: onlineCountForGuild()
    });
  });

  socket.on('join_channel', ({ guildId, channelId }) => {
    const guild = guilds[guildId];
    if (!guild || !guild.channels[channelId]) return;

    const prev = onlineUsers[socket.id];
    if (prev.currentGuild && prev.currentChannel) {
      socket.leave(`${prev.currentGuild}:${prev.currentChannel}`);
    }

    socket.join(`${guildId}:${channelId}`);
    onlineUsers[socket.id].currentGuild = guildId;
    onlineUsers[socket.id].currentChannel = channelId;

    socket.emit('message_history', { channelId, messages: guild.channels[channelId].messages });
  });

  socket.on('send_message', ({ guildId, channelId, text }) => {
    const user = onlineUsers[socket.id];
    const guild = guilds[guildId];
    if (!user || !guild || !guild.channels[channelId] || !text?.trim()) return;

    const message = {
      id: uuidv4(),
      author: user.username,
      text: text.trim(),
      timestamp: Date.now()
    };

    guild.channels[channelId].messages.push(message);

    io.to(`${guildId}:${channelId}`).emit('new_message', { channelId, message });

    // обновляем превью в списке чатов у всех, кто на этом гилде
    io.emit('channel_preview_update', {
      guildId,
      preview: channelPreview(guild.channels[channelId])
    });
  });

  socket.on('typing_start', ({ guildId, channelId }) => {
    const user = onlineUsers[socket.id];
    if (!user) return;
    socket.to(`${guildId}:${channelId}`).emit('user_typing', { username: user.username, channelId });
  });

  socket.on('typing_stop', ({ guildId, channelId }) => {
    const user = onlineUsers[socket.id];
    if (!user) return;
    socket.to(`${guildId}:${channelId}`).emit('user_stopped_typing', { channelId });
  });

  socket.on('create_channel', ({ guildId, channelName }) => {
    const guild = guilds[guildId];
    if (!guild || !channelName?.trim()) return;
    const id = channelName.trim().toLowerCase().replace(/\s+/g, '-');
    if (guild.channels[id]) return;

    guild.channels[id] = { id, name: id, messages: [] };

    io.emit('channel_list_updated', {
      guildId,
      channels: Object.values(guild.channels).map(channelPreview)
    });
  });

  socket.on('disconnect', () => {
    delete onlineUsers[socket.id];
    io.emit('online_users', Object.values(onlineUsers).map(u => u.username));
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Сервер запущен: http://localhost:${PORT}`);
});