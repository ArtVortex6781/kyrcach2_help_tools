# mesh_node_db

Минимальный локальный уровень хранения для узла(node).

`mesh_node_db` предоставляет небольшой абстрактный интерфейс хранения локального состояния узла,
используя SQLite в качестве внутренней реализации.

В настоящее время модуль реализует  **Фазу 1 — Основу минимальных абстрактных баз данных узлов**.

SQLite намеренно скрыт за узким API, чтобы более высокие уровни не
зависели от SQL, курсоров или структуры таблиц.
---

# Example

```python
from mesh_node_db import NodeDB

db = NodeDB("node.db")

db.open()
db.initialize()

db.add_message(
    message_id="msg1",
    chat_id="chat1",
    sender_id="peerA",
    payload=b"hello"
)

msg = db.get_message("msg1")

messages = db.list_chat_messages("chat1", limit=50)

db.close()
```

---

# Public API

```
NodeDB
MessageRecord
NodeDBError
```

Основные операции:

```
open()
close()
initialize()

add_message()
get_message()
list_chat_messages()

run_in_transaction()
```

---

# Storage model (Phase 1)

Минимальная неизменяемая запись сообщения:

```
message_id
chat_id
sender_id
payload (BLOB)
created_at
```

Полезная нагрузка хранится в виде двоичного файла (blob) для обеспечения возможности последующего зашифрованного хранения.

---

# Status

Phase 1 complete.

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