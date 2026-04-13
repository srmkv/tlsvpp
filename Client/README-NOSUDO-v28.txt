TLS Client v28 — работа без sudo

Что изменено:
1. Linux runtime больше не зависит от shell-вызовов `ip link/ip route` для TUN и маршрутов.
   Настройка интерфейса и маршрутов переведена на netlink внутри процесса.
2. Это позволяет запускать GUI обычным пользователем, если на бинарник один раз выданы capability:
   cap_net_admin,cap_net_raw+ep
3. Tray теперь не валит приложение, если вы запустили его как root или в окружении без DBus.

Рекомендуемый запуск:
  ./tlsclient

Один раз после сборки:
  sudo setcap cap_net_admin,cap_net_raw+ep ./bin/tlsclient

Проверить:
  getcap ./bin/tlsclient

Ожидаемо:
  ./bin/tlsclient cap_net_admin,cap_net_raw=ep

Если capability не выданы, TUN/route операции будут падать по правам.
