v28 fixed12

Что исправлено:
- при ручном disconnect dataplane переводится в shutdown до очистки activeBase/activeSession
- TUN закрывается и runtime откатывается до финальной очистки activeBase
- postFrame/pollFrame молча завершаются при shutdown или пустом base URL
- ошибки вида unsupported protocol scheme "" после штатного disconnect больше не должны появляться

Сборка:
go mod tidy
go build -o bin/tlsclient ./cmd/tlsclient
