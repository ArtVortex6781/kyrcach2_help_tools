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
