v28.fixed2

Исправлено:
- удалён неиспользуемый import strconv из internal/client/runtime_linux.go

Важно:
- зависимость github.com/vishvananda/netlink всё ещё подтягивается через go mod tidy / go get на вашей машине
