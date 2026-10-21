# Mesh P2P Messenger — Python Components

**Python-подсистемы криптографии и локального хранения данных для командного P2P-мессенджера.**

Репозиторий содержит две самостоятельные библиотеки: `mesh_crypto` и `mesh_node_db`. Они предназначены для использования C++/application layer через встроенный CPython и обеспечивают защищённые личные сессии, управление ключами и типизированное SQLite-хранилище с выборочным шифрованием данных.

Это **репозиторий Python-компонентов**, а не самостоятельная реализация всего мессенджера: сетевой транспорт, маршрутизация, UI и C++-интеграция разрабатываются другими участниками команды.

## Мой вклад

В рамках согласованных командных требований и межмодульных контрактов я проектировал, реализовывал, тестировал и документировал обе Python-подсистемы:

- **`mesh_crypto`** — криптографические операции, файловый keystore, authenticated direct E2EE, управление состоянием защищённых сессий и шифрование локальных данных.
- **`mesh_node_db`** — типизированная модель SQLite, репозитории, транзакции, проверка схемы и интеграция шифрования на уровне отдельных полей.
- **Интеграционные контракты** — разделение ответственности между пакетами, обработка ошибок и подключение crypto provider/adapter без прямой зависимости DB-пакета от `mesh_crypto`.
- **Поставка Python runtime** — подготовка Windows- и Debian-артефактов с CPython и runtime-зависимостями для использования C++-приложением.

C++ bridge, CMake, networking, routing и orchestration не относятся к моей самостоятельной реализации.

## Архитектура

```text
                 C++ / application layer (команда)
                 ├─ network, routing, UI, orchestration
                 ├─ управление identity trust и SessionState
                 └─ связывание Python-компонентов
                             │
              ┌──────────────┴────────────────────┐
              ▼                                   ▼
         mesh_crypto                         mesh_node_db
         ├─ keystore                         ├─ NodeDatabase
         ├─ primitives                       ├─ typed repositories
         ├─ sessions (Direct E2EE)           ├─ transactions / schema validation
         └─ storage encrypt/decrypt          └─ NodeDBCryptoAdapter
              ▲                                   │
              └──── CallableStorageCryptoProvider ┘
                                                  │
                                                  ▼
                                                SQLite
```

**Ключевая граница:** `mesh_node_db` не импортирует `mesh_crypto` напрямую. Внешний integration layer передаёт функции шифрования/расшифровки и keystore в `CallableStorageCryptoProvider`. `NodeDBCryptoAdapter` выбирает защищаемые поля и формирует AAD с привязкой к таблице, полю и идентификатору записи. `NodeDatabase` предоставляет typed repository API и управляет транзакциями.

Транспортный `DirectMessageEnvelope` и локальный `StorageFieldEnvelope` — разные форматы с разными задачами. Локальная БД хранит логические данные сообщения, защищённые storage encryption, а не сетевой E2EE-контейнер.

## Реализованные возможности

### `mesh_crypto`

- **Криптографические primitives:** AES-GCM, Ed25519, X25519, HKDF, сериализация и проверка криптографических данных.
- **Keystore:** `FileKeyStore` с зашифрованными key records; защита master key через `PasswordProtector` или `KeyringProtector`; operation-based подпись через `sign_with_key(...)`.
- **Authenticated Direct E2EE v1:** X25519 handshake с Ed25519-подписями transcript и проверкой ожидаемого identity public key собеседника.
- **Состояние сессии:** `SessionState`, send/receive chains, per-message keys, DH ratchet, ограниченная обработка out-of-order сообщений и обнаружение replay.
- **Storage encryption:** AES-GCM, AAD и versioned envelopes с `key_id` для выбора ключа при расшифровке.

### `mesh_node_db`

- **Typed storage:** dataclass records и репозитории для peers, chats, chat participants, messages и attachments.
- **Централизованные транзакции:** `run_in_transaction(...)` для атомарных составных операций, включая peer soft-delete/tombstone и связанные изменения.
- **Schema validation:** проверка версии и структуры схемы, ключевых ограничений и типов хранения зашифрованных полей.
- **Encrypted-at-rest integration:** автоматическое шифрование `messages.payload`, `peers.display_name` и `chats.chat_name` при работе через репозитории.
- **Разделение ошибок:** структурированные DB-level exceptions, включая ошибки crypto provider и конкретных encrypted fields.

Шифруются **выбранные поля**, а не весь SQLite-файл. Служебные идентификаторы, часть метаданных и `attachments.file_path` не скрываются этой схемой.

## Статус разработки

| Этап | Результат | Статус |
|---|---|---|
| Phase 1 | Основа `mesh_node_db`: SQLite lifecycle и схема | Завершён |
| Phase 2 | `mesh_crypto`: primitives и keystore | Завершён |
| Phase 3 | Типизированные записи, репозитории и транзакции | Завершён |
| Phase 4 | Storage crypto и authenticated Direct E2EE v1 | Завершён |
| Phase 5 | Интеграция encrypted-at-rest в `mesh_node_db` | Завершён |

**Известные ограничения:** `SessionState` пока хранится в памяти процесса и не восстанавливается после перезапуска; trust decisions принимает приложение. Полная ротация master key, group E2EE, persistent sessions, sync-протокол и шифрование медиафайлов не входят в завершённые этапы.

Реализованный Direct E2EE — собственный протокол v1; он не заявляется как Signal-compatible, независимо аудированный или production-ready.

## Разработка и тестирование

- **Python:** 3.12.
- **Зависимости для разработки и тестов:** `requirements-dev.txt`.
- **Тесты:** `pytest`, конфигурация в `pytest.ini`, тестовые модули в `tests/`.
- **Работа с исходниками:** оба пакета находятся в корне репозитория; для разработки используется отдельное Python-окружение и запуск тестов из корня проекта.

После активации окружения Python 3.12:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

Unit- и интеграционные проверки охватывают криптографические операции, E2EE-состояния, репозитории, транзакции и шифрование полей. Численные показатели покрытия или производительности здесь не заявляются.

## Runtime artifacts — v0.5.0

[**GitHub Release v0.5.0 — Mesh Python Runtime Artifacts**](https://github.com/ArtVortex6781/kyrcach2_help_tools/releases/tag/v0.5.0)

Релиз содержит два bundled CPython runtime для включения Python-компонентов в поставку C++-приложения:

| Платформа | Артефакт |
|---|---|
| Windows 11 x64 (Intel/AMD) | `mesh_python_runtime_win_amd64_py312.zip` |
| Debian 13 amd64 | `mesh_python_runtime_debian13_amd64_py312.tar.gz` |

В артефакты включены CPython 3.12.4, оба Python-пакета и необходимые runtime-зависимости. Они рассчитаны на работу без отдельно установленного Python и без установки пакетов через `pip` на целевой машине; для Linux остаются требования к совместимым системным библиотекам.

**Runtime artifacts не заменяют окружение разработки:** `pytest`, инструменты анализа кода и другие dev-зависимости не входят в поставку. Артефакты сопровождаются smoke-тестами и SHA256-контрольными суммами; релиз не включает ARM64/Android.

## Документация

Подробные API, форматы данных, инварианты и правила интеграции вынесены из корневого README:

- [`docs/mesh_crypto.md`](docs/mesh_crypto.md) — keystore, crypto primitives, Direct E2EE, SessionState, storage crypto и границы ответственности.
- [`docs/mesh_node_db.md`](docs/mesh_node_db.md) — typed repositories, SQLite schema, transactions, provider/adapter и encrypted-at-rest.

## Лицензия

См. [`LICENSE`](LICENSE).
