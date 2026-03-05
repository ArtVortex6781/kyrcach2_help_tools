# kyrcach2_help_tools

# mesh_node_db

Минимальный слой хранения SQLite для состояния узла mesh.

## Пример

from mesh_node_db import NodeDB

db = NodeDB("node.db")

db.create("peer:123", {"ip": "10.0.0.2"})
peer = db.read("peer:123")

## Статус

Фаза 1 завершена: хранение + миграции.