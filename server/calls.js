// ------------------------------------------------------------------
// Групповые/личные звонки (аудио/видео) поверх WebRTC.
//
// Сервер здесь — ТОЛЬКО сигналинг: relay offer/answer/ICE-кандидатов
// через Socket.IO и учёт состояния активных звонков в памяти. Сами
// медиапотоки идут напрямую между браузерами (mesh-топология: у
// каждого участника есть RTCPeerConnection на каждого другого
// участника звонка).
//
// Почему mesh, а не SFU: без своего медиа-сервера (mediasoup/Janus/
// LiveKit) это самый простой вариант, который вообще не требует новой
// инфраструктуры. Комфортно тянет 2-5 участников — каждый клиент
// отправляет свой поток N-1 раз, так что аплинк отправителя растёт
// линейно с числом людей в звонке. Если звонки станут больше и
// регулярнее — стоит вынести медиа на SFU, но сигналинг (события
// call:*) можно оставить почти таким же, поменяется только то, что
// клиент будет открывать одно соединение с медиасервером вместо N-1.
//
// Состояние звонка НЕ персистится (не пишется в store.js) — это чисто
// оперативные данные, как онлайн-статус или "печатает...": если
// сервер перезапустится, все звонки просто обрываются, что нормально.
// ------------------------------------------------------------------

// chatId -> {
//   chatId, type: 'audio' | 'video', startedAt,
//   participants: Map<accountId, { joinedAt, muted, cameraOff }>,
// }
const activeCalls = new Map();

function callStatePayload(call) {
  return {
    chatId: call.chatId,
    type: call.type,
    startedAt: call.startedAt,
    participants: Array.from(call.participants.entries()).map(([accountId, p]) => ({
      accountId,
      muted: p.muted,
      cameraOff: p.cameraOff,
      joinedAt: p.joinedAt,
    })),
  };
}

// deps передаются из index.js — это ссылки на уже существующие в нём
// структуры данных, модуль ничего не хранит и не мутирует помимо
// activeCalls (своего собственного стейта).
function registerCallHandlers(io, socket, deps) {
  const { socketToAccount, accountSockets, accounts, chats, publicAccount } = deps;

  function myAccountId() {
    return socketToAccount.get(socket.id);
  }

  // Аккаунт может быть залогинен на нескольких устройствах одновременно
  // (см. accountSockets в index.js) — событие звонка шлём на все его
  // живые сокеты, а не на один.
  function emitToAccount(accountId, event, payload) {
    const sockets = accountSockets.get(accountId);
    if (!sockets) return;
    for (const sid of sockets) io.to(sid).emit(event, payload);
  }

  socket.on('call:start', ({ chatId, type } = {}) => {
    const accountId = myAccountId();
    const chat = chats.get(chatId);
    if (!accountId || !chat || !chat.members.has(accountId)) return;
    const callType = type === 'audio' ? 'audio' : 'video';

    // Если звонок в этом чате уже идёт — просто присоединяемся к нему
    // (типичный сценарий для группового чата: кто-то уже звонит, я
    // нажимаю "позвонить" и на самом деле вхожу в существующий звонок).
    let call = activeCalls.get(chatId);
    if (!call) {
      call = { chatId, type: callType, participants: new Map(), startedAt: Date.now() };
      activeCalls.set(chatId, call);
    }
    if (!call.participants.has(accountId)) {
      call.participants.set(accountId, { joinedAt: Date.now(), muted: false, cameraOff: call.type === 'audio' });
    }

    socket.emit('call:state', callStatePayload(call));

    const initiator = accounts.get(accountId);
    for (const memberId of chat.members) {
      if (memberId === accountId || call.participants.has(memberId)) continue;
      emitToAccount(memberId, 'call:incoming', {
        chatId,
        type: call.type,
        isGroup: !!chat.isGroup,
        chatName: chat.isGroup ? chat.name : (initiator ? initiator.name : ''),
        from: initiator ? publicAccount(initiator) : null,
      });
    }
  });

  // Ответ на входящий звонок (или добровольное присоединение к уже
  // идущему групповому звонку по кнопке "Присоединиться").
  socket.on('call:join', ({ chatId } = {}) => {
    const accountId = myAccountId();
    const chat = chats.get(chatId);
    const call = activeCalls.get(chatId);
    if (!accountId || !chat || !chat.members.has(accountId) || !call) return;
    if (call.participants.has(accountId)) {
      socket.emit('call:state', callStatePayload(call));
      return;
    }

    const newcomer = accounts.get(accountId);
    // Существующие участники сами инициируют offer к новичку (см.
    // public/calls.js) — так проще избежать "glare" (одновременных
    // встречных предложений), чем при взаимной инициации с обеих сторон.
    for (const existingId of call.participants.keys()) {
      emitToAccount(existingId, 'call:peer-joined', {
        chatId,
        accountId,
        account: newcomer ? publicAccount(newcomer) : null,
      });
    }

    call.participants.set(accountId, { joinedAt: Date.now(), muted: false, cameraOff: call.type === 'audio' });
    socket.emit('call:state', callStatePayload(call));
  });

  // Явный отказ от входящего звонка (в основном имеет смысл для 1:1 —
  // в группе просто можно проигнорировать уведомление на клиенте).
  socket.on('call:decline', ({ chatId } = {}) => {
    const accountId = myAccountId();
    const chat = chats.get(chatId);
    if (!accountId || !chat) return;
    for (const memberId of chat.members) {
      if (memberId !== accountId) emitToAccount(memberId, 'call:declined', { chatId, accountId });
    }
  });

  socket.on('call:leave', ({ chatId } = {}) => {
    const accountId = myAccountId();
    const call = activeCalls.get(chatId);
    if (!accountId || !call || !call.participants.has(accountId)) return;
    call.participants.delete(accountId);
    for (const remainingId of call.participants.keys()) {
      emitToAccount(remainingId, 'call:peer-left', { chatId, accountId });
    }
    if (call.participants.size === 0) activeCalls.delete(chatId);
  });

  // Позволяет клиенту узнать про уже идущий звонок в чате, который он
  // открыл позже (т.е. пропустил исходное call:incoming).
  socket.on('call:query', ({ chatId } = {}) => {
    const accountId = myAccountId();
    const chat = chats.get(chatId);
    const call = activeCalls.get(chatId);
    if (!accountId || !chat || !chat.members.has(accountId) || !call) return;
    socket.emit('call:active', callStatePayload(call));
  });

  // Чистый relay: сервер не понимает содержимое data (offer/answer/
  // ICE-кандидат) — просто пересылает конкретному участнику звонка.
  socket.on('call:signal', ({ chatId, to, data } = {}) => {
    const accountId = myAccountId();
    const call = activeCalls.get(chatId);
    if (!accountId || !to || !data || !call) return;
    if (!call.participants.has(accountId) || !call.participants.has(to)) return;
    emitToAccount(to, 'call:signal', { chatId, from: accountId, data });
  });

  socket.on('call:media', ({ chatId, kind, enabled } = {}) => {
    const accountId = myAccountId();
    const call = activeCalls.get(chatId);
    const p = call && call.participants.get(accountId);
    if (!p || (kind !== 'audio' && kind !== 'video')) return;
    if (kind === 'audio') p.muted = !enabled;
    else p.cameraOff = !enabled;
    for (const otherId of call.participants.keys()) {
      if (otherId !== accountId) emitToAccount(otherId, 'call:peer-media', { chatId, accountId, kind, enabled });
    }
  });

  return {
    // Вызвать из существующего socket.on('disconnect', ...) в index.js,
    // когда у аккаунта не осталось ни одного живого сокета (последнее
    // устройство отключилось) — иначе участник "зависнет" в звонке,
    // хотя реально уже не на связи.
    handleAccountFullyOffline(accountId) {
      for (const [chatId, call] of activeCalls) {
        if (!call.participants.has(accountId)) continue;
        call.participants.delete(accountId);
        for (const remainingId of call.participants.keys()) {
          emitToAccount(remainingId, 'call:peer-left', { chatId, accountId });
        }
        if (call.participants.size === 0) activeCalls.delete(chatId);
      }
    },
  };
}

module.exports = { registerCallHandlers };