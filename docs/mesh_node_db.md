# mesh_node_db

`mesh_node_db` — локальный typed SQLite storage module для node-local состояния mesh-ноды.

Модуль отвечает за структуру локальной базы данных, typed records, repository API, transaction model и encrypted-at-rest хранение выбранных полей. SQLite является внутренней реализацией storage layer и не должен протекать в внешний C++/app layer через SQL, курсоры или raw-табличные операции.

Короткое разделение ответственности:

```text
mesh_node_db = что хранить, как хранить, какие DB fields шифровать
mesh_crypto  = как шифровать bytes
C++/app layer = orchestration, network, UI, trust decisions, key rotation policy
```

## Статус

Текущий статус: **Phase 5 завершена**.

Реализовано:

- typed storage architecture;
- repositories по основным сущностям;
- database engine и schema validation;
- transaction model;
- encrypted-at-rest integration для выбранных DB fields;
- soft-delete/tombstone модель для `peers`;
- unit-тесты;
- security audit;
- проверка корректности использования `mesh_crypto.storage`.

## Область ответственности

`mesh_node_db` отвечает за:

- lifecycle SQLite-соединения;
- schema bootstrap и schema version validation;
- проверку структуры схемы, FK и критичных индексов;
- typed dataclass records;
- repositories для `peers`, `chats`, `chat_participants`, `messages`, `attachments`;
- transaction boundary через `run_in_transaction(...)`;
- selected-field encrypted-at-rest storage;
- AAD для encrypted DB fields;
- soft-delete/tombstone модель для peers;
- нормализацию DB-level и encrypted-field ошибок.

`mesh_node_db` не отвечает за:

- network transport;
- peer discovery;
- delivery / ACK / retry;
- trust UI;
- direct E2EE protocol;
- crypto primitives;
- реализацию `FileKeyStore`;
- C++/Python bridge;
- sync protocol;
- key rotation policy;
- media encryption policy.

## Структура пакета

```text
mesh_node_db/
  __init__.py
  errors.py
  tables.py
  repositories.py
  database.py
  _validation.py
  crypto_adapter.py
```

## Назначение файлов

### `__init__.py`

Curated public API пакета. Экспортирует основной класс базы, public record types, crypto adapter boundary и public errors.

Внешний код должен импортировать основные сущности через package-level API:

```python
from mesh_node_db import NodeDatabase, MessageRecord, NodeDBCryptoAdapter
```

Не следует импортировать internal helpers напрямую без необходимости.

### `errors.py`

Structured DB error hierarchy.

Основные группы ошибок:

- базовая ошибка модуля: `NodeDBError`;
- configuration errors: ошибки конфигурации БД и crypto adapter;
- database state errors: БД не открыта, executor недоступен, schema не инициализирована;
- record/schema/migration errors;
- transaction errors;
- low-level execution / constraint / operational storage errors;
- storage crypto provider errors;
- encrypted field processing errors.

Ошибки encrypted-at-rest не выходят наружу как raw `mesh_crypto` exceptions. Они нормализуются на уровне `mesh_node_db`.

`StorageCryptoProviderError` означает ошибку вызова внешнего storage crypto provider. Ошибка содержит диагностические поля вроде `operation` и `cause_type`, если они поддерживаются текущей реализацией.

`EncryptedFieldError` означает ошибку обработки конкретного encrypted DB field. Ошибка содержит `field_name`, `operation` и `cause_type`, если они поддерживаются текущей реализацией.

`cause_type` — диагностическая информация, а не основной stable branching contract для бизнес-логики.

### `tables.py`

Typed dataclass records. Файл описывает логическую модель данных, а не физическое SQLite-представление.

Правила:

- records содержат logical values;
- records не содержат SQL;
- records не выполняют encryption/decryption;
- encrypted BLOB representation обрабатывается в `repositories.py` через `crypto_adapter.py`;
- timestamps представлены как non-negative `int`;
- `updated_at >= created_at` для записей, где есть обе временные метки.

Основные records:

- `PeerRecord`;
- `ChatRecord`;
- `ChatParticipantRecord`;
- `MessageRecord`;
- `AttachmentRecord`.

Projection records используются для отдельных JOIN/list queries, например:

- `ChatMessageWithSenderRecord`;
- `ChatWithParticipantCountRecord`.

### `repositories.py`

Repository layer для сущностей.

Repositories:

- содержат SQL;
- выполняют mapping `record -> SQL params`;
- выполняют mapping `row -> typed record`;
- вызывают `NodeDBCryptoAdapter` для выбранных encrypted fields;
- не владеют lifecycle SQLite-соединения;
- не управляют commit/rollback напрямую;
- не являются pseudo-ORM и не предоставляют generic dict-driven query API.

Public access:

```python
db.peers
db.chats
db.chat_participants
db.messages
db.attachments
```

### `database.py`

Основной database engine.

`NodeDatabase` отвечает за:

- `open()` / `close()` lifecycle;
- schema bootstrap;
- schema version validation;
- schema shape / FK / index / storage type validation;
- repository wiring;
- internal executor;
- transaction model;
- encrypted DB mode configuration через `crypto_adapter`.

`NodeDatabase` требует crypto adapter. Plaintext DB mode после Phase 5 не используется.

### `_validation.py`

Internal validation helpers для typed records и DB inputs.

Файл не является crypto-validation layer. Crypto-level validation выполняется в `mesh_crypto` и provider/storage layer. `_validation.py` нужен для проверки record/input shape на уровне `mesh_node_db`.

### `crypto_adapter.py`

DB-specific encrypted-at-rest integration layer.

Основные компоненты:

- `StorageKeyId`;
- `StorageCryptoProvider`;
- `CallableStorageCryptoProvider`;
- `NodeDBCryptoAdapter`;
- `build_storage_field_aad(...)`.

`crypto_adapter.py`:

- не импортирует `mesh_crypto` напрямую;
- не знает concrete API `FileKeyStore`;
- не работает с raw key material;
- строит AAD для DB fields;
- кодирует/декодирует UTF-8 для encrypted string fields;
- вызывает переданный provider;
- оборачивает provider/decode failures в DB-level errors.

C++/app layer не должен строить AAD самостоятельно.

## Public typed model

Public records отражают логическую модель данных, а не физическую SQLite-форму.

Ключевые logical types:

```python
PeerRecord.display_name: str
ChatRecord.chat_name: str
ChatMessageWithSenderRecord.sender_display_name: str
ChatWithParticipantCountRecord.chat_name: str

MessageRecord.payload: bytes
AttachmentRecord.file_path: str
```

Пояснение:

- `display_name`, `chat_name`, `file_path` — логические текстовые поля;
- `messages.payload` — произвольная полезная нагрузка сообщения в bytes;
- encrypted BLOB — внутренняя физическая форма хранения SQLite;
- encrypted BLOB не должен выходить наружу через public typed API.

## Сущности и схема данных

### `peers`

Ключевые поля:

```text
peer_id
display_name
public_key
created_at
updated_at
is_deleted
deleted_at
```

Семантика:

- `peer_id` — стабильный логический идентификатор peer;
- `public_key` — long-term Ed25519 identity public key;
- `display_name` — logical `str`, физически encrypted `BLOB`;
- peers используют soft-delete/tombstone модель;
- `is_deleted` фиксирует tombstone-состояние;
- `deleted_at` задаётся только для soft-deleted peer.

Удаление peer не должно удалять сообщения, где `messages.sender_id == peer_id`. `sender_id` остаётся historical string reference.

### `chats`

Ключевые поля:

```text
chat_id
chat_type
chat_name
created_at
updated_at
```

Семантика:

- `chat_id` — стабильный идентификатор чата;
- `chat_type` — открытое meta-поле для query/index usage;
- `chat_name` — logical `str`, физически encrypted `BLOB`;
- `created_at` — immutable storage fact;
- `updated_at` — timestamp последней версии записи.

### `chat_participants`

Ключевые поля:

```text
chat_id
peer_id
joined_at
```

Связующая таблица между `chats` и `peers`.

При soft-delete peer memberships этого peer должны удаляться через grouped transaction.

### `messages`

Ключевые поля:

```text
message_id
chat_id
sender_id
created_at
updated_at
payload
attachment_hash
```

Семантика:

- `message_id` — стабильный идентификатор сообщения;
- `chat_id` — ссылка на чат;
- `sender_id` — historical string reference на отправителя;
- `payload` — logical `bytes`, физически encrypted `BLOB`;
- `updated_at` — timestamp последней версии записи;
- `attachment_hash` — nullable ссылка на attachment metadata.

`messages.payload` хранит logical message bytes encrypted-at-rest. Он не хранит `DirectMessageEnvelope` сетевого/E2EE-слоя.

### `attachments`

Ключевые поля:

```text
attachment_hash
file_path
```

Семантика:

- `attachment_hash` — открытый идентификатор attachment metadata;
- `file_path` — logical `str`, физически plaintext `TEXT`.

`attachments.file_path` в Phase 5 не шифруется по командному решению.

## Encrypted-at-rest fields

Шифруются только выбранные поля:

```text
messages.payload
peers.display_name
chats.chat_name
```

Не шифруются:

```text
IDs
FK fields
timestamps
chat_type
public_key
attachment_hash
attachments.file_path
chat_participants fields
soft-delete metadata
```

Это selected-field encryption-at-rest, а не full SQLite file encryption и не metadata hiding.

Иными словами:

```text
Шифруются отдельные чувствительные поля, а не весь SQLite-файл.
Служебные идентификаторы, связи, временные метки и часть метаданных остаются открытыми для работы запросов и индексов.
```

## AAD для encrypted fields

`NodeDBCryptoAdapter` строит AAD через `build_storage_field_aad(...)`.

AAD привязывает ciphertext к:

```text
table
field
record_id
```

Логические примеры:

```text
mesh_node_db:v1:messages:payload:<message_id>
mesh_node_db:v1:peers:display_name:<peer_id>
mesh_node_db:v1:chats:chat_name:<chat_id>
```

Allowed encrypted field pairs:

```text
("messages", "payload")
("peers", "display_name")
("chats", "chat_name")
```

Смысл AAD:

```text
ciphertext нельзя незаметно переложить в другое поле, другую таблицу или другую запись без ошибки authentication/integrity check.
```

C++/app layer не должен строить AAD самостоятельно.

## Crypto adapter integration

`mesh_node_db` не импортирует `mesh_crypto` напрямую в repositories/database. Integration layer передаёт callables из `mesh_crypto.storage` через provider boundary.

Ожидаемая форма storage crypto functions:

```python
encrypt_storage_field(keystore, plaintext: bytes, *, aad: bytes, key_id=None) -> bytes
decrypt_storage_field(keystore, envelope: bytes, *, aad: bytes) -> bytes
```

Схема интеграции:

```text
integration/C++ layer
  -> encrypt/decrypt callables + keystore + active_storage_key_id

CallableStorageCryptoProvider
  -> wraps callables + keystore

NodeDBCryptoAdapter
  -> builds AAD
  -> encrypts/decrypts DB-specific fields

repositories
  -> row <-> typed record mapping

SQLite
  -> stores StorageFieldEnvelope bytes
```

Пример подключения:

```python
from mesh_node_db import (
    CallableStorageCryptoProvider,
    NodeDatabase,
    NodeDBCryptoAdapter,
)
from mesh_crypto.storage import decrypt_storage_field, encrypt_storage_field

provider = CallableStorageCryptoProvider(
    encrypt_func=encrypt_storage_field,
    decrypt_func=decrypt_storage_field,
    keystore=keystore,
)

crypto_adapter = NodeDBCryptoAdapter(
    provider=provider,
    active_storage_key_id=storage_key_id,
)

db = NodeDatabase(
    path="node.db",
    crypto_adapter=crypto_adapter,
)

db.open()
db.initialize()
```

Если фактические имена параметров `CallableStorageCryptoProvider` отличаются, используйте сигнатуру текущей реализации. Контракт остаётся тем же: provider оборачивает encrypt/decrypt callables и keystore.

## Storage key rotation в Phase 5

Phase 5 не реализует master key rotation и не делает полную перешифровку БД.

Текущая модель:

```text
C++/integration layer decides when to rotate storage key.
FileKeyStore creates new symmetric storage key.
Integration layer receives new_storage_key_id.
New NodeDBCryptoAdapter is created with active_storage_key_id=new_storage_key_id.
New DB writes use new key_id.
Old records remain encrypted under old key_id.
Decrypt resolves key_id from StorageFieldEnvelope.
```

Старые storage keys нельзя удалять, пока в БД есть записи, зашифрованные под их `key_id`.

Рекомендации:

- не переключать `active_storage_key_id` во время concurrent write operations;
- предпочитать создание нового adapter / reopen DB access под app-level lock;
- не считать storage key rotation заменой master key rotation;
- не ожидать immediate full DB re-encryption после смены active key.

Псевдокод:

```python
new_storage_key_id = keystore.generate_key(...)

new_provider = CallableStorageCryptoProvider(
    encrypt_func=encrypt_storage_field,
    decrypt_func=decrypt_storage_field,
    keystore=keystore,
)

new_crypto_adapter = NodeDBCryptoAdapter(
    provider=new_provider,
    active_storage_key_id=new_storage_key_id,
)

# Recreate DB access under app-level lock.
db.close()

db = NodeDatabase(
    path="node.db",
    crypto_adapter=new_crypto_adapter,
)
db.open()
db.initialize()
```

## Transaction model

Repositories являются частью public typed storage API.

Правила:

```text
single repository read/write operations may be called directly;
multi-step logical operations must use run_in_transaction(...);
repositories do not manage commit/rollback directly;
transaction policy is centralized in database.py;
internal executor performs SQL execution.
```

Одиночная запись может выполняться напрямую:

```python
db.messages.add(record)
```

Группа связанных операций должна выполняться через `run_in_transaction(...)`:

```python
def create_chat(tx: NodeDatabase) -> None:
    tx.chats.add(chat_record)
    tx.chat_participants.add(participant_a)
    tx.chat_participants.add(participant_b)

db.run_in_transaction(create_chat)
```

### Soft-delete peer

Мягкое удаление peer должно выполняться только через `run_in_transaction(...)`.

Причина: операция состоит из нескольких SQL-запросов и должна фиксироваться или откатываться целиком.

Минимальная логика soft-delete:

```text
UPDATE peers
SET is_deleted = 1,
    deleted_at = ...,
    updated_at = ...
WHERE peer_id = ...

DELETE FROM chat_participants
WHERE peer_id = ...
```

Обязательное правило:

```text
Do not call peer soft-delete logic as separate independent repository operations.
Use db.run_in_transaction(...) for peer soft-delete and any grouped write operation.
```

Пример:

```python
def soft_delete_peer(tx: NodeDatabase) -> None:
    tx.peers.soft_delete(
        peer_id="peer-1",
        deleted_at=deleted_at,
        updated_at=deleted_at,
    )
    tx.chat_participants.delete_by_peer("peer-1")

db.run_in_transaction(soft_delete_peer)
```

Если в текущей реализации `PeerRepository.soft_delete(...)` сам удаляет memberships, вызывайте только его, но всё равно внутри `run_in_transaction(...)`.

Другие grouped operations:

- create chat + participants;
- insert message + attachment metadata;
- peer soft-delete;
- future re-encryption / migration operations.

## Repository API

### `db.peers`

Типовые операции:

- `add(...)`;
- `read(...)`;
- `update(...)`;
- `soft_delete(...)`;
- `list_active(...)`;
- `list_deleted(...)`.

`PeerRecord.display_name` в public API является `str`. Физически значение хранится как encrypted `BLOB`.

### `db.chats`

Типовые операции:

- `add(...)`;
- `read(...)`;
- `update(...)`;
- `delete(...)`;
- `list_all(...)`;
- `list_by_type(...)`;
- `list_with_participant_count(...)`.

`ChatRecord.chat_name` в public API является обязательным `str`. Физически значение хранится как encrypted `BLOB`.

### `db.chat_participants`

Типовые операции:

- `add(...)`;
- `read(...)`;
- `delete(...)`;
- `list_by_chat(...)`;
- `list_by_peer(...)`;
- `delete_by_peer(...)`, если поддерживается текущей реализацией.

### `db.messages`

Типовые операции:

- `add(...)`;
- `read(...)`;
- `update(...)`;
- `delete(...)`;
- `list_by_chat(...)`;
- `list_by_sender(...)`;
- `list_by_chat_and_time_range(...)`;
- `list_by_chat_with_sender_display_name(...)`.

`MessageRecord.payload` в public API является `bytes`. Физически значение хранится как encrypted `BLOB`.

`MessageRepository.update(...)` должен менять только допустимые mutable content fields и `updated_at`, но не должен менять identity/context поля вроде `message_id`, `chat_id`, `sender_id`, `created_at`.

### `db.attachments`

Типовые операции:

- `add(...)`;
- `read(...)`;
- `delete(...)`.

`AttachmentRecord.file_path` в public API является `str`. В Phase 5 поле хранится как plaintext `TEXT`.

## Public API examples

### Запись peer

```python
from mesh_node_db import PeerRecord

peer = PeerRecord(
    peer_id="peer-1",
    display_name="Alice",
    public_key=public_key_bytes,
    created_at=created_at,
    updated_at=created_at,
    is_deleted=False,
    deleted_at=None,
)

db.peers.add(peer)
```

`display_name` будет зашифрован repository layer автоматически.

### Чтение peer

```python
peer = db.peers.read("peer-1")

if peer is not None:
    display_name = peer.display_name
```

Repository layer автоматически расшифрует `display_name` и вернёт logical `str`.

### Запись сообщения

```python
from mesh_node_db import MessageRecord

message = MessageRecord(
    message_id="msg-1",
    chat_id="chat-1",
    sender_id="peer-1",
    created_at=created_at,
    updated_at=created_at,
    payload=b"message bytes",
    attachment_hash=None,
)

db.messages.add(message)
```

`payload` будет зашифрован repository layer автоматически.

### Чтение сообщения

```python
message = db.messages.read("msg-1")

if message is not None:
    payload = message.payload
```

Repository layer автоматически расшифрует `payload` и вернёт logical `bytes`.

### Grouped write

```python
def write_message_with_attachment(tx: NodeDatabase) -> None:
    tx.attachments.add(attachment_record)
    tx.messages.add(message_record)

db.run_in_transaction(write_message_with_attachment)
```

Если одна операция внутри callback падает, вся группа откатывается.

## Error handling

Основные группы ошибок:

```text
ConfigurationError
DatabaseConfigurationError
StorageCryptoConfigurationError
EncryptedFieldConfigurationError

DatabaseStateError
DatabaseNotOpenError
DatabaseExecutorUnavailableError
DatabaseNotInitializedError

InvalidRecordError
RecordNotFoundError
SchemaError
MigrationError
TransactionError

DatabaseExecutionError
ConstraintError
OperationalStorageError

StorageCryptoProviderError
EncryptedFieldError
```

Интеграционный слой должен обрабатывать ошибки на уровне DB-domain classes, а не raw `sqlite3` или raw `mesh_crypto` exceptions.

### Configuration errors

Используются для неправильной конфигурации:

- пустой или неправильный `path`;
- неправильный `crypto_adapter`;
- unsupported PRAGMA settings;
- неправильный active storage key id;
- unsupported encrypted field pair.

### Database state errors

Используются для неправильного lifecycle state:

- БД не открыта;
- executor не wired;
- schema не инициализирована.

### Transaction errors

`TransactionError` означает ошибку grouped transaction через `run_in_transaction(...)`.

Nested transactions запрещены и должны падать fail-fast.

### Storage crypto errors

`StorageCryptoProviderError` — ошибка вызова внешнего storage crypto provider.

`EncryptedFieldError` — ошибка обработки конкретного encrypted DB field, например:

```text
field_name = "messages.payload"
operation = "decrypt"
cause_type = "IntegrityError" / "UnicodeDecodeError" / etc.
```

`cause_type` используется для диагностики, а не как stable branching contract.

## Что нельзя делать

Не допускается:

```text
инстанцировать NodeDatabase без crypto_adapter;
использовать plaintext DB mode;
шифровать DB fields вручную в C++;
строить AAD в C++;
хранить DirectMessageEnvelope в messages.payload;
выдавать encrypted BLOB наружу как public record value;
использовать repository SQL напрямую извне;
вызывать peer soft-delete отдельными независимыми write-операциями;
удалять старые storage keys, пока в БД есть записи под их key_id;
считать storage key rotation master key rotation;
считать selected-field encryption скрытием всех метаданных.
```

## Интеграционные правила для C++/app layer

C++/app layer должен:

- создать/получить keystore;
- выбрать active storage key id;
- передать encrypt/decrypt callables из `mesh_crypto.storage`;
- создать `CallableStorageCryptoProvider`;
- создать `NodeDBCryptoAdapter`;
- создать `NodeDatabase` с `crypto_adapter`;
- использовать typed repositories;
- выполнять grouped writes через `run_in_transaction(...)`;
- не шифровать DB fields вручную;
- не строить AAD вручную;
- не удалять storage keys, пока они нужны для старых DB records.

## Краткий итог

`mesh_node_db` после Phase 5 — это typed encrypted-at-rest SQLite storage module.

Он предоставляет:

- typed records;
- repository API;
- schema validation;
- transaction model;
- selected-field encryption-at-rest;
- DB-level error contract;
- интеграционную границу к `mesh_crypto.storage` через provider/adapter.

Он не реализует crypto primitives, E2EE, sync protocol, network transport или C++ bridge.
