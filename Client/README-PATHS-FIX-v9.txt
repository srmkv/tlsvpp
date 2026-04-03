Перепроверка путей клиента:
- найден оставшийся старый путь /api/v1/clients в UI/helpers
- добавлена миграция старых путей из config.json:
  - /api/v1/clients -> /api/client/heartbeat
  - /api/v1/commands -> /api/client/command
  - /api/v1/apps/report -> /api/client/apps
- теперь даже со старым сохраненным config.json клиент перейдет на новые пути agent
