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

Интеграционный код должен использовать только публичные API из:

```python
mesh_crypto
mesh_crypto.keystore
mesh_crypto.storage
mesh_crypto.sessions
```

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

---

## 3. Core и primitives

### 3.1. `core/`

`core/` содержит базовые типы и служебные механизмы:

- `key_ids.py` — генерация и нормализация `key_id`;
- `key_types.py` — виды ключей;
- `keys.py` — структуры ключевых пар;
- `serialization.py` — сериализация и восстановление ключей;
- `types.py` — общие типы;
- `domain_separation.py` — константы domain separation для разных криптографических контекстов.

### 3.2. `primitives/`

`primitives/` содержит низкоуровневые криптографические операции:

- `aead.py` — AEAD-шифрование и расшифрование;
- `signatures.py` — Ed25519 подписи и проверка подписей;
- `dh.py` — X25519 DH / key agreement;
- `kdf.py` — HKDF/Scrypt;
- `envelopes.py` — базовые контейнеры `AeadEnvelope`, `WrappedKeyEnvelope`.

Эти функции являются строительными блоками. Интеграционный код обычно должен использовать более высокоуровневые API из `storage/`, `keystore/operations.py` и `sessions/`.

---

## 4. Keystore

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

## 5. Protectors

`protectors.py` содержит механизмы защиты master key.

Основные protector-ы:

```python
PasswordProtector
KeyringProtector
```

Их задача — защитить master key, который затем используется для шифрования отдельных key records.

Пример создания нового хранилища:

```python
from mesh_crypto.keystore import FileKeyStore, PasswordProtector

protector = PasswordProtector(password=b"strong password")
keystore = FileKeyStore("node_keystore", protector)

keystore.create_new()
```

Пример открытия существующего хранилища:

```python
from mesh_crypto.keystore import FileKeyStore, PasswordProtector

protector = PasswordProtector(password=b"strong password")
keystore = FileKeyStore("node_keystore", protector)

keystore.load()
```

Закрытие:

```python
keystore.close()
```

`close()` удаляет ссылку на master key из памяти на best-effort уровне. Это не является строгой secure-memory wiping гарантией.

---

## 6. Key lifecycle terminology

Важно не смешивать разные операции.

### 6.1. Storage/data key rotation

Это смена active key для новых операций storage encryption.

```text
new storage key -> set active key -> новые StorageFieldEnvelope используют новый key_id
```

Старые записи продолжают хранить старый `key_id` и расшифровываются своим ключом.

Это не master key rotation.

### 6.2. Protector/password rewrap

Это смена способа защиты master key.

```text
old password/protector -> new password/protector
master key остаётся тем же
```

В Phase 4 это не реализуется как отдельный production flow.

### 6.3. Full master key rotation

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

## 7. Operation-based signing

Файл:

```text
keystore/operations.py
```

Основные функции:

```python
sign_with_key(...)
require_signing_key_matches_public_key(...)
```

### 7.1. `sign_with_key(...)`

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

### 7.2. `require_signing_key_matches_public_key(...)`

Проверяет, что переданный Ed25519 public key соответствует ключу в `FileKeyStore` по `key_id`.

Используется перед созданием handshake, чтобы локальная ошибка вида:

```text
identity_key_id от одного ключа, а identity_public_key от другого
```

ловилась сразу на локальной стороне.

Проверка подписи выполняется public-key API / primitives verify, потому что public key не является secret material.

Generic API вида `with_private_key(callback)` не используется.

---

## 8. Storage Crypto API

`mesh_crypto.storage` реализует encrypted-at-rest API для отдельных локально сохраняемых полей.

Файлы:

```text
storage/
  _constants.py
  envelopes.py
  storage_crypto.py
```

Основные сущности:

```python
StorageFieldEnvelope
encrypt_storage_field(...)
decrypt_storage_field(...)
encrypt_storage_field_with_raw_key(...)
decrypt_storage_field_with_raw_key(...)
```

### 8.1. Назначение

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

## 9. StorageFieldEnvelope

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

## 10. Storage encryption API

### 10.1. Шифрование через FileKeyStore

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

### 10.2. Расшифрование через FileKeyStore

```python
from mesh_crypto.storage import decrypt_storage_field

plaintext = decrypt_storage_field(
    keystore,
    envelope=encrypted,
    aad=b"messages:payload:<message_id>",
)
```

`decrypt_storage_field(...)` читает `key_id` из `StorageFieldEnvelope` и загружает нужный ключ из `FileKeyStore`.

### 10.3. Raw-key API

Низкоуровневые функции:

```python
encrypt_storage_field_with_raw_key(...)
decrypt_storage_field_with_raw_key(...)
```

Они нужны для foundation/test scenarios. Для интеграции с приложением основной путь — API через `FileKeyStore`.

---

## 11. Storage AAD

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

## 12. Direct E2EE v1 overview

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

## 13. Identity and trust model

### 13.1. Ed25519 identity key

Ed25519 identity key — долгосрочный identity key пользователя.

`peers.public_key` в app/db layer должен хранить Ed25519 identity public key peer-а.

Это не X25519 key.

### 13.2. X25519 ratchet key

X25519 используется для key agreement и DH ratchet.

X25519 ratchet public key передаётся внутри handshake/direct message протокола и не должен смешиваться с `peers.public_key`.

### 13.3. Trust boundary

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

## 14. Direct handshake flow

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

### 14.1. Initiator создаёт init

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

### 14.2. Responder принимает init

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

### 14.3. Initiator завершает handshake

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

## 15. Handshake transcript

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

## 16. Session ID

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

## 17. SessionState integration contract

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

### 17.1. State transition model

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

### 17.2. Atomic commit rule

После успешного `decrypt_direct_message(...)` вызывающий код должен атомарно принять plaintext и сохранить `new_state`.

Если plaintext принят, но `new_state` отброшен, replay protection и consumption of skipped keys не гарантируются.

### 17.3. Concurrency

Операции над одной direct session должны быть сериализованы внешним приложением.

Не делать параллельно:

```text
encrypt/decrypt на одном и том же old SessionState
```

App/C++ layer должен использовать per-session lock или другой механизм сериализации.

### 17.4. Restart

В Phase 4 `SessionState` является RAM-only.

После перезапуска процесса direct session нужно установить заново через handshake.

Persistent protected `SessionState` storage не входит в Phase 4.

---

## 18. Direct message encryption/decryption

Файл:

```text
sessions/messages.py
```

Основные функции:

```python
encrypt_direct_message(...)
decrypt_direct_message(...)
```

### 18.1. Отправка сообщения

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

### 18.2. Приём сообщения

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

### 18.3. User AAD

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

## 19. DirectMessageEnvelope

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

## 20. Direct Message AAD

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

## 21. Chain keys и per-message keys

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

## 22. DH ratchet

`ratchet.py` реализует DH ratchet/root refresh.

Handshake X25519 key pair становится initial ratchet key pair.

Root key не обновляется на каждое сообщение. Он обновляется через DH ratchet.

### 22.1. Outgoing ratchet

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

### 22.2. Receive ratchet

Receive ratchet выполняется автоматически при decrypt, если:

```text
envelope.ratchet_pub != state.remote_ratchet_public_key
```

В этом случае `mesh_crypto` строит candidate state, выполняет receive ratchet и возвращает новый state только после успешной AEAD-аутентификации сообщения.

Если decrypt завершается ошибкой, старый state остаётся валидным и не должен заменяться.

---

## 23. Out-of-order и replay detection

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

## 24. Direct E2EE и Storage Crypto — разные уровни

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

## 25. Типовой integration flow

### 25.1. Создать или открыть keystore

```python
from mesh_crypto.keystore import FileKeyStore, PasswordProtector

protector = PasswordProtector(password=b"strong password")
keystore = FileKeyStore("node_keystore", protector)

if not keystore.exists():
    keystore.create_new()
else:
    keystore.load()
```

### 25.2. Создать identity key

```python
from mesh_crypto.core.key_types import KeyKind

identity_key_id = keystore.generate_key(KeyKind.ED25519)
```

Публичный Ed25519 key должен быть получен из metadata key record и передан/сохранён на уровне app/db layer как peer identity public key.

### 25.3. Создать storage key

```python
storage_key_id = keystore.generate_key(KeyKind.SYMMETRIC)
keystore.set_active_key(storage_key_id)
```

### 25.4. Зашифровать поле БД

```python
from mesh_crypto.storage import encrypt_storage_field

encrypted_payload = encrypt_storage_field(
    keystore,
    plaintext=b"hello",
    aad=b"messages:payload:<message_id>",
)
```

### 25.5. Расшифровать поле БД

```python
from mesh_crypto.storage import decrypt_storage_field

payload = decrypt_storage_field(
    keystore,
    envelope=encrypted_payload,
    aad=b"messages:payload:<message_id>",
)
```

### 25.6. Initiator handshake

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

### 25.7. Responder handshake

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

### 25.8. Complete handshake

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

### 25.9. Отправить direct message

```python
from mesh_crypto.sessions import encrypt_direct_message

alice_state, envelope = encrypt_direct_message(
    alice_state,
    plaintext=b"hello Bob",
    aad=b"chat:<chat_id>",
)
```

Отправить `envelope` по сети.

### 25.10. Принять direct message

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

## 26. Ошибки

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
except MeshCryptoError as exc:
    # reject message, keep old state
    raise
else:
    state = new_state
```

При ошибке decrypt старый `SessionState` остаётся валидным и не должен заменяться.

---

## 27. Security notes

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
- не менять вручную поля `SessionState`.

Нужно делать:

- хранить peer Ed25519 identity public key на уровне app/db layer;
- передавать expected peer identity key в handshake;
- использовать stable deterministic AAD;
- атомарно заменять `SessionState` после успешной операции;
- сериализовать операции на одну direct session;
- создавать новую session после restart, если persistent protected session storage ещё не реализован.

---

## 28. Ограничения Phase 4

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

## 29. Термины, которые нельзя смешивать

```text
DirectMessageEnvelope != StorageFieldEnvelope
Ed25519 identity key != X25519 ratchet key
storage/data key rotation != master key rotation
SessionState holder != SessionState owner
mesh_crypto checks signatures != mesh_crypto decides trust
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

## 30. Минимальный checklist для интеграции

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