# IIMP - Events Sync Documentation

## Overview
Events are per-user and are synced via `GET /api/client/sync`. Each event has an `EventId` (monotonically increasing), an `EventType` and a `Payload`.

On first sync (no cursor), events are returned from the beginning up to the server's `limit` (maximum 100). On subsequent syncs, only events since the cursor are returned. If `NextCursor` is empty, the client is caught up. If `NextCursor` is present, more events exist and the client should fetch again using `NextCursor` as the cursor.

## Sync Loop
```
cursor = stored_cursor (empty on first sync)
do:
  response = GET /api/client/sync?cursor=cursor&limit=100
  upsert(response.events)
  cursor = response.nextCursor
while cursor is not empty
store cursor locally
```

---

## Event Types

### `ConversationUpsert`
Fired when a conversation is created or updated (rename, participant added/removed).

**Payload:** Full `Conversation` model.

---

### `MessageUpsert`
Fired when a message is created or updated (new message, edit, redact, react, read receipt).

**Payload:** Full `Message` model.

---

## Client Handling

Since full models are always pushed, the client should simply **upsert** based on:
- `Conversation.ConversationId` for `ConversationUpsert`
- `Message.MessageId` for `MessageUpsert`

No merging logic needed.