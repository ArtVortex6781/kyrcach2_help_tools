# mesh_crypto

Самостоятельное криптографическое ядро проекта.

`mesh_crypto` не зависит от БД, sync-логики и transport-слоя.
Модуль предоставляет базовые криптографические возможности, которые затем
используются другими слоями проекта:

- генерация ключей
- сериализация ключей
- AEAD-шифрование бинарных данных
- подписи и проверка подписи
- derivation session key / shared-secret based key derivation
- хранение ключей через file-based keystore
- структурированная модель ошибок

---

## Status

**Phase 2 complete.**

Это означает, что в модуле завершены и покрыты тестами:


- Базовый слой
- Слой примитивов
- Слой хранилища ключей
- Курируемый публичный API
- Внутренний слой поддержки

---

## Текущие возможности


В настоящее время `mesh_crypto` предоставляет:

- `KeyId` и `KeyKind`
- Пары ключей подписи Ed25519
- Пары ключей шифрования X25519
- Сериализация/восстановление необработанных ключей
- Шифрование и дешифрование AEAD для произвольных байтов
- Контекстно-зависимая подпись и проверка
- Вывод сессионного ключа
- Версионированные криптографические конверты
- Файловое хранилище ключей
- Защита мастер-ключа на основе пароля
- Дополнительная защита мастер-ключа на основе связки ключей ОС
- Структурированная иерархия исключений

---

## Module structure

### `core/`
Базовые типы, модели ключей, key ids, key kinds, сериализация ключей,
domain separation constants.

### `primitives/`
Криптографические операции и форматы:

- AEAD
- signatures
- Diffie–Hellman
- KDF
- versioned envelopes

### `keystore/`
Хранение ключей и защита master key at rest:

- protectors
- file-based keystore

### `_internal/`
Приватный внутренний слой поддержки:

- validation helpers
- encoding helpers
- parsing helpers

`_internal` не является публичным контрактом и может меняться без сохранения
обратной совместимости.

---

## Философия публичного API

У модуля есть узкий curated public API.

- не все low-level symbols поднимаются на top-level
- `_internal` строго конфиденциально
- envelope classes, serializers и часть low-level helpers доступны только через подмодули
- package-level API предназначен для типичных интеграционных сценариев
- низкоуровневые детали остаются на уровне соответствующих модулей

---

## Example

```python
from mesh_crypto import encrypt, decrypt

key = b"\x01" * 32
aad = b"mesh_crypto:example:aad"
plaintext = b"hello"

envelope = encrypt(key, plaintext, aad)
restored = decrypt(key, envelope, aad)

assert restored == plaintext
```

## Пример с keystore
```python
from mesh_crypto import FileKeyStore, PasswordProtector

protector = PasswordProtector("strong-password")
keystore = FileKeyStore("keystore_data", protector)

keystore.create_new()
key_id = keystore.generate_key()
key_bytes, meta = keystore.get_key(key_id)

keystore.close()
```

## Не включено во второй этап.

В текущий модуль пока не входят:

- полноценный E2EE protocol
- final group encryption model
- multi-device model
- sync semantics
- DB integration
- media/file chunking policy
- transport / handshake protocol logic как часть сетевого слоя


# mesh_node_db

Типизированный storage layer для node-local состояния.

`mesh_node_db` предоставляет локальное хранение данных узла на базе SQLite за типизированным API.
Модуль включает typed records, repositories, database engine и transaction model, 
при этом raw SQL connection handling, schema bootstrap и transaction orchestration 
остаются внутри storage слоя.

## Статус

**Phase 3 завершена.**

Это означает, что в `mesh_node_db` реализованы и покрыты тестами:

- Типизированная архитектура хранения данных
- Типизированные записи классов данных
- Уровень репозитория с запросами, специфичными для сущностей
- Механизм базы данных и обработка жизненного цикла
- Политика транзакций для групповых записей
- Структурированный контракт обработки ошибок базы данных

## Текущая архитектура

### `tables.py`
Типизированные записи классов данных и типизированные записи проекции/результата.=

### `repositories.py`
Репозитории, SQL, сопоставление строк и записей, сопоставление записей и параметров,
запросы, специфичные для сущностей и минимальные JOIN-запросы.

### `database.py`
Механизм базы данных, жизненный цикл SQLite, загрузка схемы, проверка схемы,
границы транзакций, внутренний исполнитель и подключение репозитория.

### `errors.py`
Структурированная иерархия ошибок storage/database слоя.

## Философия публичного API

Repositories являются частью public typed storage API.

Прямые read-операции допустимы, например:

- `db.peers.read(...)`
- `db.messages.read(...)`
- `db.messages.list_by_chat(...)`

Single write-операции также допустимы напрямую через repositories.

Grouped multi-step writes, которые должны выполниться атомарно как одна операция,
нужно выполнять через:

- `db.run_in_transaction(...)`

Это позволяет сохранить удобный repository API и при этом централизовать transaction policy в database engine.

## Текущий scope хранения

На текущем этапе модуль покрывает типизированное хранение для:

- peers
- chats
- chat participants
- messages
- attachments

## Пример использования

```python
from mesh_node_db import (
    ChatParticipantRecord,
    ChatRecord,
    MessageRecord,
    NodeDatabase,
    PeerRecord,
)

db = NodeDatabase("node.db")

db.open()
db.initialize()

db.peers.add(
    PeerRecord(
        peer_id = "peer_a",
        display_name = b"Alice",
        public_key = b"public-key-a",
        created_at = 1,
        updated_at = 1,
        is_deleted = False,
        deleted_at = None,
    )
)

db.chats.add(
    ChatRecord(
        chat_id = "chat_main",
        chat_type = "direct",
        chat_name = b"Direct chat",
        created_at = 1,
        updated_at = 1,
    )
)

db.chat_participants.add(
    ChatParticipantRecord(
        chat_id = "chat_main",
        peer_id = "peer_a",
        joined_at = 1,
    )
)

db.messages.add(
    MessageRecord(
        message_id = "msg_1",
        chat_id = "chat_main",
        sender_id = "peer_a",
        created_at = 1,
        updated_at = 1,
        payload = b"hello",
        attachment_hash = None,
    )
)

message = db.messages.read("msg_1")
messages = db.messages.list_by_chat("chat_main", limit = 50)

def write_batch(tx: NodeDatabase) -> None:
    tx.messages.add(
        MessageRecord(
            message_id = "msg_2",
            chat_id = "chat_main",
            sender_id = "peer_a",
            created_at = 2,
            updated_at = 2,
            payload = b"second message",
            attachment_hash = None,
        )
    )

db.run_in_transaction(write_batch)

db.close()
```

## Не включено в третий этап.

В текущий модуль ещё не входят:

- интеграция с mesh_crypto
- зашифрованное хранение
- семантика синхронизации
- сквозное шифрование / шифрование на уровне сообщений
- финальная policy для media/file encryption