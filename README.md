# mesh_crypto

`mesh_crypto` — Python-модуль криптографической защиты для Mesh P2P Messenger.

После завершения Phase 4 модуль включает:

```text
crypto core + primitives + keystore + storage crypto + authenticated direct E2EE v1
```

Модуль предоставляет:

- генерацию и идентификацию ключей;
- сериализацию ключевого материала;
- AEAD-шифрование и расшифрование;
- подписи Ed25519;
- X25519 DH / key agreement;
- HKDF/KDF;
- файловое хранилище ключей `FileKeyStore`;
- API шифрования локально сохраняемых полей;
- authenticated direct E2EE v1 для личных диалогов;
- структурированную модель ошибок.

`mesh_crypto` не отвечает за:

- сетевой транспорт;
- UDP/TCP/WebSocket-логику;
- peer discovery;
- доставку, ACK, retry;
- маршрутизацию сообщений;
- UI;
- trust UI / fingerprint UI;
- схему базы данных;
- синхронизацию;
- C++ bridge implementation;
- хранение `SessionState` между перезапусками процесса.

---

## 1. Структура пакета

Актуальная структура после Phase 4:

```text
mesh_crypto/
  __init__.py
  facade.py
  errors.py

  core/
    __init__.py
    key_ids.py
    key_types.py
    keys.py
    serialization.py
    types.py
    domain_separation.py

  primitives/
    __init__.py
    aead.py
    dh.py
    envelopes.py
    kdf.py
    signatures.py

  keystore/
    __init__.py
    protectors.py
    file_keystore.py
    operations.py

  storage/
    __init__.py
    _constants.py
    storage_crypto.py
    envelopes.py

  sessions/
    __init__.py
    _constants.py
    state.py
    handshake.py
    chains.py
    ratchet.py
    messages.py
    envelopes.py

  _internal/
    __init__.py
    validation.py
    encoding.py
    parsing.py
    framing.py
    error_mapping.py
```

Назначение основных частей:

```text
core/        — базовые типы, идентификаторы ключей, сериализация, domain separation
primitives/  — низкоуровневые криптографические операции
keystore/    — файловое хранилище ключей и операции с ключами
storage/     — шифрование локальных записей / полей
sessions/    — direct E2EE v1 для личных диалогов
_internal/   — внутренние проверки, парсинг, кодирование и framing
errors.py    — доменная модель ошибок
```

---

## 2. Public API policy

`mesh_crypto` использует узкую политику верхнеуровневого публичного API.

Top-level пакет:

```python
import mesh_crypto
```

экспортирует только стабильные базовые сущности:

```text
KeyId
KeyKind
SigningKeyPair
EncryptionKeyPair

FileKeyStore
Protector
PasswordProtector
KeyringProtector

public errors
```

Storage API, direct E2EE API и operation-based signing API импортируются из документированных подпакетов:

```python
from mesh_crypto.storage import encrypt_storage_field, decrypt_storage_field
from mesh_crypto.sessions import encrypt_direct_message, decrypt_direct_message
from mesh_crypto.keystore.operations import sign_with_key
```

Такой подход выбран намеренно. `mesh_crypto/__init__.py` не является агрегатором всего пакета. Он не должен скрывать границы между storage encryption, direct E2EE, keystore operations и низкоуровневыми primitives.

Не использовать напрямую:

```python
mesh_crypto._internal
```

`_internal` — приватный слой. Его функции могут изменяться без сохранения совместимости.

Также не нужно вручную собирать криптографический протокол из низкоуровневых primitives, если уже есть high-level API:

- для локального хранения использовать `mesh_crypto.storage`;
- для direct E2EE использовать `mesh_crypto.sessions`;
- для подписи через ключ из хранилища использовать `mesh_crypto.keystore.operations`.

Не следует доставать raw private key или session key material наружу, если для операции уже есть безопасный API.

Не являются integration API:

```text
sessions/_constants.py
storage/_constants.py
_internal/*
chains.py helpers
ratchet.py helpers
raw-key storage helpers
validation/parsing/framing helpers
skipped-key helpers
```

Для app/C++ слоя direct ratchet выполняется только через:

```python
encrypt_direct_message(..., force_ratchet=True)
decrypt_direct_message(...)
```

а не через прямой вызов ratchet helpers.

---

## 3. Facade policy

`facade.py` не является вторым `__init__.py` и не используется как полный re-export aggregator.

Его задача — дать только небольшие сценарные convenience helpers там, где они реально сокращают жизненный цикл операции:

```python
from mesh_crypto.facade import (
    create_file_keystore,
    open_file_keystore,
    generate_identity_key,
    generate_storage_key,
)
```

`facade.py` может использоваться для:

- создания нового `FileKeyStore`;
- открытия существующего `FileKeyStore`;
- генерации базовых key pair;
- генерации identity/storage keys внутри keystore.

`facade.py` не должен переэкспортировать:

- весь `mesh_crypto.storage`;
- весь `mesh_crypto.sessions`;
- весь `mesh_crypto.keystore.operations`;
- primitives;
- envelopes;
- errors;
- ratchet helpers;
- chain helpers;
- raw-key storage helpers.

Для storage и sessions интеграционный код должен использовать явные подпакеты:

```python
from mesh_crypto.storage import encrypt_storage_field, decrypt_storage_field
from mesh_crypto.sessions import create_direct_handshake_init, encrypt_direct_message
from mesh_crypto.keystore.operations import sign_with_key
```

---

## 4. Core и primitives

### 4.1. `core/`

`core/` содержит базовые типы и служебные механизмы:

- `key_ids.py` — генерация и нормализация `key_id`;
- `key_types.py` — виды ключей;
- `keys.py` — структуры ключевых пар;
- `serialization.py` — сериализация и восстановление ключей;
- `types.py` — общие типы;
- `domain_separation.py` — константы domain separation для разных криптографических контекстов.

### 4.2. `primitives/`

`primitives/` содержит низкоуровневые криптографические операции:

- `aead.py` — AEAD-шифрование и расшифрование;
- `signatures.py` — Ed25519 подписи и проверка подписей;
- `dh.py` — X25519 DH / key agreement;
- `kdf.py` — HKDF/Scrypt;
- `envelopes.py` — базовые контейнеры `AeadEnvelope`, `WrappedKeyEnvelope`.

Эти функции являются строительными блоками. Интеграционный код обычно должен использовать более высокоуровневые API из `storage/`, `keystore/operations.py` и `sessions/`.

---

## 5. Keystore

`keystore/` реализует файловое хранилище ключевого материала.

Основной класс:

```python
FileKeyStore
```

Файлы:

```text
keystore/
  file_keystore.py
  protectors.py
  operations.py
```

`FileKeyStore` отвечает за:

- создание файлового хранилища;
- загрузку master key;
- хранение encrypted key records;
- генерацию ключей;
- импорт ключей;
- получение ключей по `key_id`;
- active key;
- базовую смену active key.

Типичная структура хранилища:

```text
keystore_dir/
  master.key
  keystore.json
  keys/
    <key_id>.key
```

`master.key` содержит данные, необходимые для восстановления master key через protector.  
`keys/*.key` содержат encrypted key records.  
`keystore.json` хранит metadata хранилища, включая active key.

---

## 6. Protectors

`protectors.py` содержит механизмы защиты master key.

Основные protector-ы:

```python
PasswordProtector
KeyringProtector
```

Их задача — защитить master key, который затем используется для шифрования отдельных key records.

Пример создания нового хранилища:

```python
from mesh_crypto import FileKeyStore, PasswordProtector

protector = PasswordProtector(password=b"strong password")
keystore = FileKeyStore("node_keystore", protector)

keystore.create_new()
```

Пример открытия существующего хранилища:

```python
from mesh_crypto import FileKeyStore, PasswordProtector

protector = PasswordProtector(password=b"strong password")
keystore = FileKeyStore("node_keystore", protector)

keystore.load()
```

Можно также использовать convenience helpers из `facade.py`:

```python
from mesh_crypto.facade import create_file_keystore, open_file_keystore

keystore = create_file_keystore("node_keystore", protector)
loaded_keystore = open_file_keystore("node_keystore", protector)
```

Закрытие:

```python
keystore.close()
```

`close()` удаляет ссылку на master key из памяти на best-effort уровне. Это не является строгой secure-memory wiping гарантией.

---

## 7. Key lifecycle terminology

Важно не смешивать разные операции.

### 7.1. Storage/data key rotation

Это смена active key для новых операций storage encryption.

```text
new storage key -> set active key -> новые StorageFieldEnvelope используют новый key_id
```

Старые записи продолжают хранить старый `key_id` и расшифровываются своим ключом.

Это не master key rotation.

### 7.2. Protector/password rewrap

Это смена способа защиты master key.

```text
old password/protector -> new password/protector
master key остаётся тем же
```

В Phase 4 это не реализуется как отдельный production flow.

### 7.3. Full master key rotation

Это настоящая ротация master key:

```text
generate new master key
-> decrypt all key records with old master key
-> re-encrypt all key records with new master key
-> atomically update master.key
```

В Phase 4 это не реализовано.

Если используется API вроде `rotate_key(...)`, его нужно понимать как active-key switch / migration helper, а не как full master key rotation.

---

## 8. Operation-based signing

Файл:

```text
keystore/operations.py
```

Основные функции:

```python
sign_with_key(...)
require_signing_key_matches_public_key(...)
```

### 8.1. `sign_with_key(...)`

Назначение:

```text
подписать context-bound data через Ed25519 private key,
который хранится внутри FileKeyStore
```

Raw private key не возвращается вызывающему коду.

Пример:

```python
from mesh_crypto.keystore.operations import sign_with_key

signature = sign_with_key(
    keystore,
    identity_key_id,
    context=b"some signing context",
    data=b"data to sign",
)
```

Эта функция используется, например, для подписи direct handshake transcript.

### 8.2. `require_signing_key_matches_public_key(...)`

Проверяет, что переданный Ed25519 public key соответствует ключу в `FileKeyStore` по `key_id`.

Используется перед созданием handshake, чтобы локальная ошибка вида:

```text
identity_key_id от одного ключа, а identity_public_key от другого
```

ловилась сразу на локальной стороне.

Проверка подписи выполняется public-key API / primitives verify, потому что public key не является secret material.

Generic API вида `with_private_key(callback)` не используется.

---

## 9. Storage Crypto API

`mesh_crypto.storage` реализует encrypted-at-rest API для отдельных локально сохраняемых полей.

Файлы:

```text
storage/
  _constants.py
  envelopes.py
  storage_crypto.py
```

Основные public integration сущности:

```python
StorageFieldEnvelope
encrypt_storage_field(...)
decrypt_storage_field(...)
```

Рекомендуемый путь интеграции — только через `FileKeyStore`.

Raw-key storage helpers, если они присутствуют внутри `mesh_crypto.storage`, не являются integration API. Их нельзя использовать в C++/app layer как обычный путь шифрования локальных данных.

### 9.1. Назначение

Storage crypto используется для шифрования bytes перед сохранением в локальную БД.

Пример логики записи:

```text
plaintext field bytes
-> encrypt_storage_field(...)
-> serialized StorageFieldEnvelope bytes
-> SQLite BLOB
```

Пример логики чтения:

```text
serialized StorageFieldEnvelope bytes
-> decrypt_storage_field(...)
-> plaintext field bytes
```

`StorageFieldEnvelope` — это контейнер локального хранения.  
Это не сетевой E2EE-контейнер и не `DirectMessageEnvelope`.

---

## 10. StorageFieldEnvelope

`StorageFieldEnvelope` содержит:

```text
version
type
algorithm
key_id
aead
```

Где:

```text
version   — версия формата контейнера
type      — тип контейнера
algorithm — идентификатор storage crypto формата
key_id    — идентификатор ключа, которым зашифровано поле
aead      — вложенный AeadEnvelope
```

`key_id` записывается в envelope. Это важно: при расшифровании используется именно ключ из envelope, а не текущий active key.

Это позволяет делать active storage key rotation:

```text
старые записи -> старый key_id
новые записи -> новый active key_id
decrypt -> key_id из конкретного envelope
```

---

## 11. Storage encryption API

### 11.1. Шифрование через FileKeyStore

```python
from mesh_crypto.storage import encrypt_storage_field

encrypted = encrypt_storage_field(
    keystore,
    plaintext=b"message text",
    aad=b"messages:payload:<message_id>",
)
```

Если `key_id` не передан, используется текущий active key:

```python
encrypted = encrypt_storage_field(
    keystore,
    plaintext=b"message text",
    aad=b"messages:payload:<message_id>",
    key_id=None,
)
```

Можно указать ключ явно:

```python
encrypted = encrypt_storage_field(
    keystore,
    plaintext=b"message text",
    aad=b"messages:payload:<message_id>",
    key_id=storage_key_id,
)
```

### 11.2. Расшифрование через FileKeyStore

```python
from mesh_crypto.storage import decrypt_storage_field

plaintext = decrypt_storage_field(
    keystore,
    envelope=encrypted,
    aad=b"messages:payload:<message_id>",
)
```

`decrypt_storage_field(...)` читает `key_id` из `StorageFieldEnvelope` и загружает нужный ключ из `FileKeyStore`.

### 11.3. Raw-key storage helpers

Raw-key storage helpers не являются integration API.

C++/app layer не должен передавать raw storage key в storage crypto API. Правильный путь интеграции:

```python
encrypt_storage_field(keystore, plaintext, aad=..., key_id=...)
decrypt_storage_field(keystore, envelope, aad=...)
```

Если raw-key helper-ы существуют внутри `mesh_crypto.storage`, они предназначены для низкоуровневого foundation/test usage и не должны использоваться как обычный production path.

---

## 12. Storage AAD

AAD для storage encryption обязателен.

`aad` должен быть одинаковым при encrypt и decrypt. Если AAD отличается, расшифрование должно завершиться authentication failure.

`mesh_crypto` не знает схему `mesh_node_db`. Поэтому AAD формирует вызывающий storage/database layer.

Рекомендуемый смысл AAD:

```text
module/table/field/record_id/schema_version
```

Примеры:

```python
aad = b"messages:payload:<message_id>"
aad = b"peers:display_name:<peer_id>"
aad = b"attachments:metadata:<attachment_id>"
```

Требования к AAD:

- должен быть стабильным;
- должен быть детерминированным;
- должен быть одинаковым при записи и чтении;
- должен связывать ciphertext с конкретным storage context;
- не должен зависеть от случайных runtime-данных.

AAD должен препятствовать незаметному переносу ciphertext между разными таблицами, полями или записями.

---

## 13. Direct E2EE v1 overview

`mesh_crypto.sessions` реализует authenticated direct one-to-one E2EE v1.

Реализовано:

- Ed25519 identity transcript signatures;
- X25519 handshake;
- HKDF key schedule;
- `SessionState`;
- `root_key`;
- send/recv chains;
- per-message keys;
- DH ratchet;
- bounded out-of-order;
- skipped message key cache;
- replay detection;
- `DirectMessageEnvelope`.

Не реализовано в Phase 4:

- group E2EE;
- X3DH/prekeys;
- PQXDH;
- multi-device;
- persistent protected `SessionState`;
- rollback protection;
- Signal compatibility;
- network ACK/retry;
- sync-aware replay model;
- trust UI;
- peer discovery.

---

## 14. Identity and trust model

### 14.1. Ed25519 identity key

Ed25519 identity key — долгосрочный identity key пользователя.

`peers.public_key` в app/db layer должен хранить Ed25519 identity public key peer-а.

Это не X25519 key.

### 14.2. X25519 ratchet key

X25519 используется для key agreement и DH ratchet.

X25519 ratchet public key передаётся внутри handshake/direct message протокола и не должен смешиваться с `peers.public_key`.

### 14.3. Trust boundary

`mesh_crypto` не решает, доверять ли peer key.

App/C++ layer должен передать:

```text
expected_peer_identity_public_key
```

`mesh_crypto` проверяет, что handshake действительно подписан ключом, соответствующим ожидаемому Ed25519 identity public key.

Если identity public key peer-а изменился, его нельзя молча принимать как обычную ротацию. Это trust-level событие, которое должно обрабатываться внешним приложением:

- TOFU reset;
- fingerprint verification;
- QR/manual confirmation;
- trusted recovery flow.

В Phase 4 автоматическая identity key rotation не реализована.

---

## 15. Direct handshake flow

Файл:

```text
sessions/handshake.py
```

Основные классы:

```python
PendingDirectHandshake
DirectHandshakeInit
DirectHandshakeResponse
```

Основные функции:

```python
create_direct_handshake_init(...)
accept_direct_handshake_init(...)
complete_direct_handshake(...)
```

Общий flow:

```text
Initiator creates init
-> Responder verifies init and returns response + responder SessionState
-> Initiator verifies response and creates initiator SessionState
```

### 15.1. Initiator создаёт init

```python
from mesh_crypto.sessions import create_direct_handshake_init

pending, init = create_direct_handshake_init(
    keystore=alice_keystore,
    identity_key_id=alice_identity_key_id,
    identity_public_key=alice_identity_public_key,
    expected_peer_identity_public_key=bob_identity_public_key,
)
```

Результат:

```text
pending — временное локальное состояние initiator-а
init    — сообщение для responder-а
```

App/C++ layer должен:

```text
1. сохранить pending в RAM;
2. отправить init responder-у через сеть.
```

### 15.2. Responder принимает init

```python
from mesh_crypto.sessions import accept_direct_handshake_init

bob_state, response = accept_direct_handshake_init(
    keystore=bob_keystore,
    identity_key_id=bob_identity_key_id,
    identity_public_key=bob_identity_public_key,
    expected_peer_identity_public_key=alice_identity_public_key,
    init=init,
)
```

Результат:

```text
bob_state — готовое SessionState responder-а
response  — ответ initiator-у
```

App/C++ layer должен:

```text
1. сохранить bob_state в RAM;
2. отправить response initiator-у.
```

### 15.3. Initiator завершает handshake

```python
from mesh_crypto.sessions import complete_direct_handshake

alice_state = complete_direct_handshake(
    pending=pending,
    init=init,
    response=response,
    expected_peer_identity_public_key=bob_identity_public_key,
)
```

После этого у обеих сторон есть совместимые `SessionState`.

---

## 16. Handshake transcript

Handshake использует canonical transcript.

Init transcript включает:

```text
protocol version
algorithm id
session_id
initiator identity key id
initiator identity public key
initiator X25519 ratchet public key
```

Response transcript включает:

```text
protocol version
algorithm id
session_id
init transcript hash
initiator identity key id
initiator identity public key
initiator X25519 ratchet public key
responder identity key id
responder identity public key
responder X25519 ratchet public key
```

Transcript подписывается Ed25519.

X25519 не используется «сам по себе»: handshake key agreement связан с identity через подписанные transcript-ы.

---

## 17. Session ID

В Phase 4 `session_id` создаётся initiator-ом через:

```python
uuid.uuid4()
```

`session_id`:

- не является секретом;
- не является key material;
- не является security authority;
- используется как stable random session handle;
- включается в signed init transcript;
- включается в signed response transcript;
- включается в `DirectMessageEnvelope`;
- включается в Direct Message AAD.

Security binding обеспечивается не самим `session_id`, а:

- Ed25519 transcript signatures;
- expected peer identity public key;
- raw identity public keys в transcript;
- raw X25519 public keys в transcript;
- X25519 shared secret;
- handshake hash;
- HKDF key schedule;
- Direct Message AAD binding.

Deterministic session id от transcript hash в Phase 4 не используется.

---

## 18. SessionState integration contract

`SessionState` — состояние direct E2EE-сессии.

Оно содержит live secret material:

```text
root_key
send_chain_key
recv_chain_key
local_ratchet_key_pair
skipped_message_keys
```

App/C++ layer может хранить `SessionState` в RAM, но не должен:

- логировать `SessionState`;
- сериализовать `SessionState` в открытом виде;
- сохранять `SessionState` в БД;
- вручную менять root key;
- вручную менять chain keys;
- вручную менять counters;
- вручную менять ratchet key material;
- вручную менять skipped message keys.

Все переходы состояния должны выполняться через `mesh_crypto.sessions` API.

### 18.1. State transition model

Отправка:

```python
new_state, envelope = encrypt_direct_message(
    old_state,
    plaintext,
    aad=optional_aad,
)
```

Приём:

```python
new_state, plaintext = decrypt_direct_message(
    old_state,
    envelope,
    aad=optional_aad,
)
```

После успешной операции вызывающий код обязан заменить старое состояние новым:

```text
old_state -> new_state
```

Старое состояние нельзя использовать повторно после успешного transition.

Если операция завершилась ошибкой:

```text
old_state remains valid
state must not be replaced
```

### 18.2. Atomic commit rule

После успешного `decrypt_direct_message(...)` вызывающий код должен атомарно принять plaintext и сохранить `new_state`.

Если plaintext принят, но `new_state` отброшен, replay protection и consumption of skipped keys не гарантируются.

### 18.3. Concurrency

Операции над одной direct session должны быть сериализованы внешним приложением.

Не делать параллельно:

```text
encrypt/decrypt на одном и том же old SessionState
```

App/C++ layer должен использовать per-session lock или другой механизм сериализации.

### 18.4. Restart

В Phase 4 `SessionState` является RAM-only.

После перезапуска процесса direct session нужно установить заново через handshake.

Persistent protected `SessionState` storage не входит в Phase 4.

---

## 19. Direct message encryption/decryption

Файл:

```text
sessions/messages.py
```

Основные функции:

```python
encrypt_direct_message(...)
decrypt_direct_message(...)
```

### 19.1. Отправка сообщения

```python
from mesh_crypto.sessions import encrypt_direct_message

new_alice_state, envelope = encrypt_direct_message(
    alice_state,
    plaintext=b"hello",
    aad=b"chat:<chat_id>",
)

alice_state = new_alice_state
```

`envelope` передаётся по сети через app/C++ layer.

`mesh_crypto` не отправляет сообщение самостоятельно.

### 19.2. Приём сообщения

```python
from mesh_crypto.sessions import decrypt_direct_message

new_bob_state, plaintext = decrypt_direct_message(
    bob_state,
    envelope,
    aad=b"chat:<chat_id>",
)

bob_state = new_bob_state
```

Если при отправке был использован user AAD, те же bytes должны быть переданы при decrypt.

### 19.3. User AAD

Direct Message protocol AAD всегда строится внутри `mesh_crypto` и включает protocol metadata.

Пользовательский `aad` опционален.

```python
aad=None
```

и

```python
aad=b""
```

являются разными криптографическими контекстами.

Если app layer имеет стабильный контекст сообщения, например `chat_id` или conversation id, его следует передавать как `aad` при encrypt и decrypt.

---

## 20. DirectMessageEnvelope

`DirectMessageEnvelope` — сетевой/session artifact для direct E2EE.

Поля:

```text
version
type
session_id
counter
previous_chain_length
algorithm
ratchet_pub
aead
```

Где:

```text
version               — версия формата direct message envelope
type                  — тип контейнера
session_id            — идентификатор direct session
counter               — номер сообщения в текущей sending chain
previous_chain_length — длина предыдущей sending chain до ratchet transition
algorithm             — идентификатор direct E2EE формата
ratchet_pub           — текущий X25519 ratchet public key отправителя
aead                  — вложенный AeadEnvelope
```

В `DirectMessageEnvelope` нет:

- timestamp;
- application message id;
- DB id;
- sync fields;
- delivery status;
- group metadata;
- media metadata.

Эти данные относятся к application/storage/sync layer, а не к crypto-required metadata.

---

## 21. Direct Message AAD

Для direct messages protocol AAD строится внутри `mesh_crypto`.

В него входят:

```text
purpose
version
type
algorithm
session_id
counter
previous_chain_length
ratchet_pub
external_aad_present
external_aad
```

Это нужно, чтобы ciphertext нельзя было незаметно перенести:

- в другую session;
- на другой counter;
- в другой ratchet context;
- в envelope с другим `ratchet_pub`;
- в другой application context.

---

## 22. Chain keys и per-message keys

`chains.py` реализует symmetric chain evolution.

Схема:

```text
chain_key_n
-> message_key_n
-> chain_key_n+1
```

`message_key_n` используется для AEAD-шифрования конкретного сообщения.

`chain_key` напрямую не используется для шифрования payload.

Для каждого сообщения выводится отдельный message key.

---

## 23. DH ratchet

`ratchet.py` реализует DH ratchet/root refresh.

Handshake X25519 key pair становится initial ratchet key pair.

Root key не обновляется на каждое сообщение. Он обновляется через DH ratchet.

### 23.1. Outgoing ratchet

Outgoing ratchet может быть инициирован так:

```python
new_state, envelope = encrypt_direct_message(
    state,
    plaintext,
    aad=aad,
    force_ratchet=True,
)
```

При `force_ratchet=True` выполняется:

```text
generate new local X25519 ratchet key pair
X25519(new local private, current remote public)
refresh root_key
derive new send_chain_key
reset send_counter
set previous_chain_length
```

### 23.2. Receive ratchet

Receive ratchet выполняется автоматически при decrypt, если:

```text
envelope.ratchet_pub != state.remote_ratchet_public_key
```

В этом случае `mesh_crypto` строит candidate state, выполняет receive ratchet и возвращает новый state только после успешной AEAD-аутентификации сообщения.

Если decrypt завершается ошибкой, старый state остаётся валидным и не должен заменяться.

---

## 24. Out-of-order и replay detection

Direct E2EE v1 поддерживает bounded out-of-order delivery.

Для этого используется skipped message key cache.

Лимит:

```text
DEFAULT_MAX_SKIP = 600
```

Модель:

- если сообщение пришло с future counter, промежуточные message keys сохраняются как skipped keys;
- если старое сообщение позже приходит out-of-order, оно может быть расшифровано через skipped key;
- после успешного использования skipped key удаляется;
- повтор такого сообщения считается replay;
- слишком большой counter gap приводит к `SkippedKeyLimitError`.

Replay cases:

```text
old counter without skipped key -> replay
consumed skipped key replay -> replay
gap > DEFAULT_MAX_SKIP -> skipped key limit error
```

---

## 25. Direct E2EE и Storage Crypto — разные уровни

Важно не смешивать контейнеры.

```text
DirectMessageEnvelope = network/session artifact
StorageFieldEnvelope  = local encrypted-at-rest artifact
```

Для исходящего сообщения:

```text
plaintext
  -> sessions.encrypt_direct_message(...)
  -> DirectMessageEnvelope
  -> network

plaintext
  -> storage.encrypt_storage_field(...)
  -> StorageFieldEnvelope
  -> SQLite BLOB
```

Для входящего сообщения:

```text
DirectMessageEnvelope
  -> sessions.decrypt_direct_message(...)
  -> plaintext
  -> storage.encrypt_storage_field(...)
  -> StorageFieldEnvelope
  -> SQLite BLOB
```

`messages.payload` в локальной БД должен хранить logical message bytes, защищённые storage encryption.

Не сохранять `DirectMessageEnvelope` как локальный payload истории сообщений.

---

## 26. Типовой integration flow

Перед примерами важно зафиксировать импортную политику:

```python
from mesh_crypto import FileKeyStore, PasswordProtector, KeyKind
from mesh_crypto.storage import encrypt_storage_field, decrypt_storage_field
from mesh_crypto.sessions import (
    create_direct_handshake_init,
    accept_direct_handshake_init,
    complete_direct_handshake,
    encrypt_direct_message,
    decrypt_direct_message,
)
from mesh_crypto.keystore.operations import sign_with_key
```

Top-level `mesh_crypto` используется только для базовых типов, keystore classes и errors. Storage/session/operation APIs импортируются из своих подпакетов.

### 26.1. Создать или открыть keystore

```python
from mesh_crypto import FileKeyStore, PasswordProtector

protector = PasswordProtector(password=b"strong password")
keystore = FileKeyStore("node_keystore", protector)

if not keystore.exists():
    keystore.create_new()
else:
    keystore.load()
```

### 26.2. Создать identity key

```python
from mesh_crypto import KeyKind

identity_key_id = keystore.generate_key(KeyKind.ED25519)
```

Публичный Ed25519 key должен быть получен из metadata key record и передан/сохранён на уровне app/db layer как peer identity public key.

### 26.3. Создать storage key

```python
from mesh_crypto import KeyKind

storage_key_id = keystore.generate_key(KeyKind.SYMMETRIC)
keystore.set_active_key(storage_key_id)
```

### 26.4. Зашифровать поле БД

```python
from mesh_crypto.storage import encrypt_storage_field

encrypted_payload = encrypt_storage_field(
    keystore,
    plaintext=b"hello",
    aad=b"messages:payload:<message_id>",
)
```

### 26.5. Расшифровать поле БД

```python
from mesh_crypto.storage import decrypt_storage_field

payload = decrypt_storage_field(
    keystore,
    envelope=encrypted_payload,
    aad=b"messages:payload:<message_id>",
)
```

### 26.6. Initiator handshake

```python
from mesh_crypto.sessions import create_direct_handshake_init

pending, init = create_direct_handshake_init(
    keystore=alice_keystore,
    identity_key_id=alice_identity_key_id,
    identity_public_key=alice_identity_public_key,
    expected_peer_identity_public_key=bob_identity_public_key,
)
```

Отправить `init` responder-у.

### 26.7. Responder handshake

```python
from mesh_crypto.sessions import accept_direct_handshake_init

bob_state, response = accept_direct_handshake_init(
    keystore=bob_keystore,
    identity_key_id=bob_identity_key_id,
    identity_public_key=bob_identity_public_key,
    expected_peer_identity_public_key=alice_identity_public_key,
    init=init,
)
```

Сохранить `bob_state` в RAM. Отправить `response` initiator-у.

### 26.8. Complete handshake

```python
from mesh_crypto.sessions import complete_direct_handshake

alice_state = complete_direct_handshake(
    pending=pending,
    init=init,
    response=response,
    expected_peer_identity_public_key=bob_identity_public_key,
)
```

После этого обе стороны могут обмениваться direct E2EE-сообщениями.

### 26.9. Отправить direct message

```python
from mesh_crypto.sessions import encrypt_direct_message

alice_state, envelope = encrypt_direct_message(
    alice_state,
    plaintext=b"hello Bob",
    aad=b"chat:<chat_id>",
)
```

Отправить `envelope` по сети.

### 26.10. Принять direct message

```python
from mesh_crypto.sessions import decrypt_direct_message

bob_state, plaintext = decrypt_direct_message(
    bob_state,
    envelope,
    aad=b"chat:<chat_id>",
)
```

После успешного decrypt обязательно заменить старый state новым.

---

## 27. Ошибки

`mesh_crypto` использует структурированную модель ошибок из `errors.py`.

Основные группы:

```text
MeshCryptoError                  — базовый класс
InvalidInputError                — некорректный input public API
MalformedDataError               — повреждённая или некорректная serialized структура
UnsupportedFormatError           — неподдерживаемая версия/тип/алгоритм
AuthenticationError / IntegrityError — ошибка аутентификации/целостности
SignatureVerificationError       — ошибка проверки подписи
KeystoreNotLoadedError           — keystore не загружен/не готов
KeyNotFoundError                 — ключ не найден
WrongKeyTypeError                — ключ неправильного типа
InvalidKeyError                  — некорректный key material
SessionError                     — базовая session ошибка
HandshakeError                   — ошибка handshake
InvalidSessionStateError         — некорректное состояние сессии
SessionCounterError              — ошибка счётчика
ReplayDetectedError              — replay
OutOfOrderMessageError           — некорректный порядок сообщения
SkippedKeyLimitError             — превышен лимит skipped keys
RatchetError                     — ошибка DH ratchet
```

Интеграционный код должен ловить ошибки на уровне нужного слоя.

Пример:

```python
from mesh_crypto.errors import MeshCryptoError

try:
    new_state, plaintext = decrypt_direct_message(state, envelope, aad=aad)
except MeshCryptoError:
    # reject message, keep old state
    raise
else:
    state = new_state
```

При ошибке decrypt старый `SessionState` остаётся валидным и не должен заменяться.

---

## 28. Security notes

Не логировать:

- raw private keys;
- master key;
- storage keys;
- root key;
- chain keys;
- message keys;
- `SessionState` целиком;
- skipped message keys.

Не делать:

- не принимать изменённый peer identity public key молча;
- не использовать `DirectMessageEnvelope` как storage payload;
- не использовать `StorageFieldEnvelope` как network E2EE envelope;
- не считать `session_id` секретом;
- не запускать параллельные encrypt/decrypt на одном old `SessionState`;
- не переиспользовать old state после successful transition;
- не передавать нестабильный AAD;
- не менять вручную поля `SessionState`;
- не импортировать storage/session/operation APIs из top-level `mesh_crypto`, если они не экспортируются явно;
- не использовать `facade.py` как агрегатор всех функций пакета;
- не использовать raw-key storage helpers в C++/app integration path.

Нужно делать:

- хранить peer Ed25519 identity public key на уровне app/db layer;
- передавать expected peer identity key в handshake;
- использовать stable deterministic AAD;
- атомарно заменять `SessionState` после успешной операции;
- сериализовать операции на одну direct session;
- создавать новую session после restart, если persistent protected session storage ещё не реализован.

---

## 29. Ограничения Phase 4

Phase 4 даёт рабочую основу:

```text
key storage + storage encryption + authenticated direct E2EE v1
```

Но Phase 4 не включает:

- group E2EE;
- prekey server;
- X3DH;
- PQXDH;
- multi-device;
- persistent protected `SessionState`;
- rollback protection;
- sync-aware replay model;
- media/file encryption;
- full master key rotation;
- identity key recovery/rotation protocol;
- network delivery semantics.

Эти темы должны рассматриваться как отдельные будущие фазы.

---

## 30. Термины, которые нельзя смешивать

```text
DirectMessageEnvelope != StorageFieldEnvelope
Ed25519 identity key != X25519 ratchet key
storage/data key rotation != master key rotation
SessionState holder != SessionState owner
mesh_crypto checks signatures != mesh_crypto decides trust
top-level mesh_crypto API != полный API всех подпакетов
facade.py != re-export aggregator
raw-key storage helper != integration storage API
```

Разделение ответственности:

```text
mesh_crypto:
  cryptographic operations
  key storage primitives
  storage encryption
  direct E2EE session transitions
  envelope parsing/validation
  structured crypto errors

app/C++ layer:
  networking
  peer discovery
  identity trust decisions
  UI
  database schema
  delivery/retry/ACK
  SessionState lifecycle in RAM
  per-session locking
  storage AAD construction
```

---

## 31. Минимальный checklist для интеграции

Перед использованием direct E2EE:

```text
[ ] keystore created or loaded
[ ] local Ed25519 identity key exists
[ ] local identity public key exported to app/db layer
[ ] remote peer Ed25519 identity public key known and trusted by app layer
[ ] expected_peer_identity_public_key passed into handshake
[ ] pending handshake state stored in RAM until completion
[ ] SessionState stored only in RAM
[ ] per-session operations serialized
```

Перед использованием storage encryption:

```text
[ ] symmetric storage key exists
[ ] active storage key selected
[ ] AAD format defined by storage/db layer
[ ] same AAD used for encrypt/decrypt
[ ] envelope bytes stored as BLOB
[ ] decrypt uses key_id from envelope
```

Перед отправкой сообщения:

```text
[ ] SessionState exists
[ ] plaintext is bytes
[ ] optional user aad is stable
[ ] returned new_state replaces old state after success
[ ] DirectMessageEnvelope is sent over network
```

Перед приёмом сообщения:

```text
[ ] envelope parsed/received from network
[ ] correct SessionState selected by session_id
[ ] same user aad supplied if used
[ ] on success: commit new_state + accept plaintext
[ ] on failure: keep old state and reject plaintext
```


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
